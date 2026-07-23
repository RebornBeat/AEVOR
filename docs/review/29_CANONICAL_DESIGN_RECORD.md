# 29 — Canonical Design Record

**The code is the canonical design.** This document states, authoritatively, what
the finalized implementation establishes — and, explicitly, which earlier design
statements it **supersedes**. It is the single source to reconcile `README.md`
(1,370 lines, March) and `WHITEPAPER.md` (~1 MB, March) against, since both predate
this work and describe decisions since revised by measurement.

Each entry gives the canonical statement, the evidence, and what it replaces.
Anything not listed here is unchanged from the whitepaper.

---

## 1. Consensus and state

### 1.1 Corruption detection is attestation verification — NOT re-execution
**Canonical.** A verifier establishes correctness by verifying the producer's TEE
attestation and checking its enclave **code measurement** against a network-agreed
registry. This is O(1) per block and requires no re-execution.

**Evidence.** Re-execution runs at the produce rate (~11.5k tx/s) versus ~1.05M tx/s
for attestation verification — ~90×. Using re-execution as the mechanism would
reintroduce the O(N) execution cost Proof-of-Uncorruption exists to remove.

**Supersedes.** Any text implying validators re-execute to detect corruption. A
re-execution primitive was built, measured, found anti-scaling, and reverted. An
*optional, sampled* re-execution quorum remains available as defence-in-depth
against a compromised TEE — a tunable dial, not the mechanism.

### 1.2 Balances settle off-Merkle, bound by commitment
**Canonical.** Balance changes ship as explicit per-account deltas in `StateDelta`,
committed by `balance_commitment` inside the attestation body. Verifiers apply them
as hash-map writes and check the commitment.

**Evidence.** Committing balances into the Merkle state root measured **+112–136%**
on the verify path. The delta+commitment design gives identical consistency and
enforcement at ~zero throughput cost.

**Supersedes.** Any description of account balances as Merkle-tree state. Light
client balance *proofs* remain an opt-in capability at that cost.

### 1.3 The attestation body binds the producer
**Canonical.** The signed body is
`producer ‖ prior_root ‖ new_root ‖ tx_commitment ‖ balance_commitment ‖ rules_version`.
A lane's claimed producer must equal the attested one, and slashing attributes only
to the attested producer.

**Evidence.** Without this binding, `LaneBlock.producer` was attacker-mutable
metadata used as the slashing offender: an attacker could submit a deliberately
invalid lane labelled with a **victim's** id and have the victim slashed. Fixed and
regression-tested (`lane_cannot_be_attributed_to_a_victim_validator`).

**Supersedes.** Any description of lane attribution as metadata alongside the
attestation.

### 1.4 Multi-lane settlement is sender-sharded
**Canonical.** Each account's transactions route to one lane per round, and each
lane credits only its own validator, so concurrent lanes touch disjoint accounts and
per-lane absolute balance deltas apply without contention.

**Defended structurally.** The apply path rejects same-object and same-account
writes across lanes, so a routing violation becomes a rejected round rather than a
double-spend. Transfers (payer + payee in different shards) will need a cross-shard
protocol; out of scope for the fee-only economy.

---

## 2. Scaling

### 2.1 The governing equation
```
network throughput ≈ N_lanes × per-lane production rate
```
**Production is the bottleneck** (~11.5k tx/s per core), not verification (~1.05M,
~90× headroom) and not finality (O(1) BLS aggregation).

**Measured basis.** Per-lane production cost is **flat** with lane count
(first-half vs second-half of 32 isolated lanes: ratio 1.01 / 1.00 / 0.99 across
three runs), so N validators on N cores give N × per-lane linearly. Sharded
verification keeps each validator's slice bounded (2–5 lanes measured as N grows
8 → 128). The ~1M tx/s ≈ 90 lanes and ~100M ≈ 9,000 lanes figures are projections
from measured independence and measured slice-bounding, not arithmetic assertion.

### 2.2 What sharding does — and does not — do
**Canonical.** State sharding does **not** multiply production. It removes the
**state ceiling**: without it every validator holds all state, so sustained high
throughput eventually exceeds any single node. Sharding makes the projection
*sustainable* rather than a burst.

**Measured** (8 lanes / 16,000 objects, same round applied at increasing shard
counts): per-validator objects stored fall 100% → 6.2% and apply time 23.00 ms →
4.58 ms at 16 shards; per-node verify rises ~0.7M → ~3.5M tx/s.

### 2.3 Which per-round costs shard
| cost | scales with | shards? |
|---|---|---|
| storage + Merkle root | objects | **yes** — by shard ownership |
| cross-lane conflict checks | objects | **yes** — perfectly, by object space |
| attestation verification | lanes | yes — via quorum slice assignment |
| deterministic ordering | lanes | **no**, and must not (determinism); 1 µs |

**Conflict checks partition perfectly** because a conflict is defined on a *single
object*: object X's conflicts are detectable only by whoever owns X, so each shard
checking its own slice catches every conflict **exactly once**. Measured 1.660 ms →
0.106 ms at 16 shards (**15.7×**).

**Coverage is structural, never implicit.** A validator checking only its slice
knows only *its* slice is clean. `certify_shard_conflicts` emits a
`ShardConflictCertificate` bound to a commitment over the exact lane set, and
`apply_lane_round_certified` **rejects** any round whose certificates do not cover
every shard for that lane set. Applying on a partial check would silently downgrade
the double-spend guarantee.

**Residual model.** Each shard needs an honest quorum (a fully byzantine shard could
falsely certify its slice) — the same assumption as sharded verification, so a
tradeoff rather than a new class of risk.

### 2.4 The monolithic ceiling is the Merkle tree
**Canonical.** For a monolithic validator, apply is dominated by state insertion +
Merkle root: **89.4%** (18.912 ms of 21.148 ms), versus conflict checks 7.8% and
attestation verification 2.8%.

**Consequence.** A Merkle root depends on all leaves and does not partition the way
conflicts do. **Sharding is the architectural answer to monolithic's dominant cost** —
each shard owns its own subtree. This is the measured justification for sharding
existing at all.

**Core-parallel conflict checking (built, gated).** Conflict checking is a live
production cost: **every validator checks conflicts on every round it applies**, so
speeding it up helps every node, monolithic included. It parallelises across cores
for exactly the reason it shards across validators — bucketing by object hash keeps
both writes to the same object in one bucket, so per-bucket duplicate detection is
exactly as complete as one global pass.

`detect_object_conflicts` implements this, gated two ways:

- **available parallelism** — measured on a single core, the bucketed path cost
  **~57% more** than a straight pass (2.604 ms vs 1.660 ms): extra allocation and
  partitioning with no parallelism to recover it. It therefore runs sequentially
  unless `rayon::current_num_threads() >= 2`. After gating, single-core cost
  returned to 1.736 ms — baseline within variance.
- **round size** — below 4,096 owned objects the hand-off costs more than it saves.

The multi-core speedup is **not measurable in this environment** (`nproc` = 1); the
partition argument and correctness are verified by
`parallel_conflict_detection_matches_sequential_above_threshold` (5,200 objects:
clean round certifies, planted cross-lane double-spend caught).

The 7.8% figure bounds the *ceiling* of this gain on a monolithic node, since Merkle
dominates at 89.4%. It is **not** a reason to exclude conflict sharding, and conflict
sharding is **not** excluded from monolithic.

### 2.4.1 Conflict certification is universal, not sharded-only

`certify_shard_conflicts` is one code path used by both modes:

- **Monolithic** owns everything, so `owns_object` / `owns_account` are always true
  and the function checks the **whole round** — identical safety to the inline check,
  no behavioural change.
- Monolithic is shard 0 of 1, therefore **complete coverage by itself**:
  `apply_lane_round_certified(lanes, &[])` succeeds with no peer certificates.
- It produces the **same state root** as the default `apply_lane_round`, which is
  unchanged and remains the default path.
- It still rejects double-spends in monolithic mode.

Verified by `conflict_certification_degenerates_correctly_for_monolithic`. Nothing
about sharding degrades or bypasses the monolithic guarantee.

### 2.5 Cross-round pipelining applies to both modes
**Canonical.** Pipelining is a round-*lifecycle* property, independent of state
partitioning: a round's authenticated root is known at apply, before its finality
certificate aggregates, so the next round produces while earlier finality settles.
Applied state advances at production rate; finality trails by the pipeline depth.

---

## 3. TEE model

### 3.1 One validator, one TEE, five supported platforms
**Canonical.** AWS Nitro, Intel SGX, AMD SEV-SNP, ARM TrustZone, RISC-V Keystone are
**options**, not a fused multi-attestation. Each is implemented with its real
format: Nitro `COSE_Sign1`/ES384 to the pinned AWS root; SGX DCAP v3 (P-256 over
header‖body, QE key binding, PCK chain); SEV-SNP (P-384 over the signed region with
the VCEK); TrustZone PSA token (ES256 `COSE_Sign1` + PSA claims); Keystone
(device→SM→enclave Ed25519 chain, `verify_strict`).

### 3.2 Producing requires hardware; verifying requires only public keys
**Canonical.** This asymmetry is deliberate and is what lets any validator — even
one with no TEE — verify any platform's evidence in O(1). Forgery is prevented
because each format chains to a vendor root the network **pins as configuration**
(`TeeTrustRoots`), never carried inside the evidence. Platforms whose root is
configuration (TrustZone, Keystone) **fail closed** when it is absent.

### 3.3 Replay is prevented by binding
**Canonical.** Evidence binds the attestation body as its `user_data`, and every
block has a different body; `prior_root` must equal the round base. Old evidence
cannot validate a new block.

### 3.4 Mixed-platform networks are a genesis policy choice
**Canonical.** `CodeRegistry` is platform-scoped, so a network chooses its exposure
by which identities it registers — a network is only as strong as the weakest
platform it accepts. This should be an explicit genesis decision, not a default.

### 3.5 Code identity subsumes the protocol rules version
**Canonical.** The enclave measurement uniquely pins the exact binary including its
economic rules, so under real TEE it subsumes `PROTOCOL_RULES_VERSION` (retained as
a coarse interim pin and a human-readable tag).

---

## 4. Engine modes (production-first defaults)

| axis | default | alternative |
|---|---|---|
| state | **Monolithic** (full state — proven) | `Sharded { shard_id, assignment }` |
| transport | **`ValidatorNetwork::bind`** (real TCP) | `LocalNetwork` (tests only) |
| attestation | **real hardware evidence** when a TEE is present | simulation signature off-hardware |

In every case production is the default and the test/simulation path is the
explicit exception.

---

## 5. Verification baseline

| gate | count |
|---|---|
| library tests (9 crates) | 940 |
| end-to-end consensus | 40 |
| TEE attestation | 144 |
| named security invariants | 7/7 |
| clippy (node, aevor-tee) | 0 warnings |

Throughput baseline (single-core sandbox; economics are deterministic and must not
move between runs): PRODUCE ~11.4–11.9k tx/s, VERIFY ~1.0–1.1M tx/s, base fee 990,
fee/tx 485,000 nano, validator reward = sender debit (conservation).

`test_aevor.sh` is the canonical pre-release gate and exits non-zero on any failure.

---

## 6. Reconciliation checklist for the narrative documents

For `WHITEPAPER.md` and `README.md`, in order:

1. **Corruption detection** — replace any re-execution framing with §1.1.
2. **State/balances** — replace Merkle-balance framing with §1.2.
3. **Attestation contents** — add the producer binding, §1.3.
4. **Multi-lane** — state sender-sharding and the structural conflict rejections, §1.4.
5. **Scaling** — replace throughput claims with the measured basis in §2.1–2.4;
   state plainly that sharding removes the state ceiling rather than multiplying
   production.
6. **TEE** — five platforms as options with real formats, the produce/verify
   asymmetry, pinned roots as configuration, fail-closed behaviour, and mixed-network
   policy (§3).
7. **Modes and defaults** — §4, emphasising production-first.
8. **Performance specifications** — replace unmeasured figures with §5, labelling
   projections as projections.
9. **Getting started / CLI** — verify every command against the actual binary before
   publishing; the March text describes flags that may not exist.

Items 1–8 are content corrections traceable to measurements in docs 21–28. Item 9
requires an audit pass against the CLI surface.

### Progress on this checklist

**Done:**
- `README.md` **Performance Specifications** rewritten against §2: the governing
  equation, measured production/verification/finality, per-lane independence,
  sharding measurements, and projections **labelled as projections** rather than
  presented as measured results.
- `README.md` gained an **About the figures** section pointing here as the
  authoritative record.

**Also done since:**
- **CLI reconciled.** The README's Getting Started described commands that **do not
  exist** (`aevor init`, `aevor deploy`, `aevor test`, `aevor create-subnet`,
  `aevor benchmark`). Replaced with the real surface — `node`, `validator`,
  `network`, `governance`, `tee`, `keys`, `config`, `status` — plus build steps, the
  verification gate, and the engine-mode defaults. Remaining aspirational developer
  tooling is explicitly labelled as roadmap rather than presented as available.
- **False "measured" claims removed.** All ten README passages carrying *"measured on
  reference hardware"* for unvalidated figures now read as design targets pending
  re-validation. Four equivalent whitepaper claims ("Reference hardware has
  demonstrated 1.2–1.4M tx/s …") given the same treatment.
- **Node Operations Guide** written (doc 30): node roles with measured work profiles,
  validator lifecycle, per-platform TEE bring-up and failure modes, configuration
  reference, operating expectations and alerting, and known operational gaps.

**Outstanding — flagged, not silently left:**
- Ten further passages in `README.md` carry *"measured on reference hardware"* for
  figures that have **not** been re-validated (bridge performance, TEE overhead
  ratios, per-platform characteristics, security-level timings, frontier metrics).
  The provenance note now scopes them as design targets pending audit; each needs
  either a measurement or removal.
- `WHITEPAPER.md` — **first pass done.** A *Canonical Implementation Notes* section
  now sits immediately before the Table of Contents, stating what the implementation
  confirms, the five decisions measurement refined (§1.1–1.4, §2.2), the measured
  performance baseline, and an explicit scope note that later performance figures are
  design targets pending audit rather than verified results. The executive summary's
  "measured 200,000 tx/s sustained / 1,000,000 burst" claim is replaced with the
  governing equation plus the actual measured per-lane and verification numbers.
  A useful finding from this pass: the whitepaper's **pre-execution conflict
  rejection** framing (no speculative execution, no state unwinding) is *correct* and
  matches the implementation — it needed no change. Remaining: per-section figure
  audit in the deeper performance chapters (e.g. the 1.2–1.4M burst claims), which is
  staged rather than attempted in one pass, since a partial rewrite of a document
  that size risks internal inconsistency.
- CLI/`Getting Started` commands need verification against the actual binary surface.
