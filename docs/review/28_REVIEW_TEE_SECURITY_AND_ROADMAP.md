# 28 — Wiring Review, TEE Security Model, and the Road to Devnet → Beta-Mainnet

This is the consolidated review: what is wired, what the TEE trust model actually
is (including a real vulnerability found and fixed while answering that question),
what sharding measurably buys, and the ordered plan from here to dApps.

---

## 1. Verification suite — `test_aevor.sh` replaced, not deleted

The old script dated from March and predated everything: it asserted a stale crate
count, ran `cargo test --workspace` (slow, and it hides which crate broke), and
referenced a test baseline that no longer exists. But its *purpose* — a single
canonical pre-release gate — is exactly what a devnet/testnet needs, so it was
**rewritten** rather than removed.

The new runner gates on: environment → build → per-crate library tests →
end-to-end consensus contract → **named security invariants** → TEE attestation
(all platforms) → clippy → optional throughput. It exits non-zero on any failure
and prints whether the build may be promoted.

Current result — **all gates pass**:

| gate | result |
|---|---|
| library tests (9 crates) | **940** |
| end-to-end consensus | **38** |
| security invariants | 7/7 |
| TEE attestation | 144 |
| clippy (node, aevor-tee) | 0 warnings |

The security invariants are listed by name in the script deliberately: a
regression in double-spend rejection or attestation binding must be unmissable in
a CI log, not buried in a count.

---

## 2. The TEE question — and a real vulnerability it surfaced

> *"All TEEs can verify all others even if not running that TEE — how? Doesn't that
> let someone just provide an attestation without having attested anything?"*

### 2.1 Why cross-platform verification is sound

**Producing and verifying are asymmetric.** Producing evidence requires hardware:
a signature from a key fused into the chip or provisioned by the vendor
(NSM/Nitro, the SGX quoting enclave, the SEV-SNP VCEK, the ARM IAK, the Keystone
device key). Verifying requires only *public* keys. So a validator with **no TEE at
all** can verify a Nitro or SGX attestation — and that is deliberate: it is what
makes verification O(1) and lets the network scale to validators on mixed hardware.

**Fabrication is not possible** because each format's signature chains to a vendor
root the network pins. Critically, those roots are **network configuration
(`TeeTrustRoots`), never carried inside the evidence** — an attacker who could
supply their own root could forge anything. This is why TrustZone and Keystone
**fail closed** when no root is configured rather than accepting blindly.

### 2.2 Replay — the attack the question is really pointing at

If evidence were merely "a signed blob," anyone who obtained one valid attestation
could resubmit it forever. Two bindings prevent that:

- **Payload binding.** The evidence's `user_data` *is* the attestation body —
  `producer ‖ prior_root ‖ new_root ‖ tx_commitment ‖ balance_commitment ‖
  rules_version`. Every block has a different body, so evidence from one block
  cannot validate another.
- **Fork-point binding.** `prior_root` must equal the round base, so a lane cannot
  be spliced in from another history.

### 2.3 The vulnerability this review found — and the fix

Asking the question properly exposed a genuine flaw. The attestation body bound the
state transition but **not the producer identity**, while `LaneBlock.producer` was
plain, attacker-mutable metadata — *and* `detect_lane_corruption` used it as the
slashing `offender`.

**The attack:** craft a lane with a deliberately invalid attestation, set
`producer` to a **victim** validator's id, and submit it. The victim gets slashed
for a block they never produced. Slashing destroys stake, so this is severe.

**The fix (now in place and tested):**
1. `producer` is a field of `ExecutionAttestation` and is **bound into the signed
   body** — altering it invalidates the signature.
2. Both round-apply paths reject any lane whose claimed producer differs from the
   attested one.
3. Slashing attributes to `attestation.producer`, never the claimed field.
4. `run_round` derives the lane's producer from the attestation instead of carrying
   it alongside — the same unbound-metadata pattern, removed at the source.

Regression test: `lane_cannot_be_attributed_to_a_victim_validator` (re-labelled lane
rejected, slashing never names the victim, tampering with the producer invalidates
the attestation). Now a named gate in the verification suite.

**Cost: none.** Benchmarks after the fix: PRODUCE 11,359 / 11,506; VERIFY
1,076,877 / 1,090,079; economics byte-identical.

### 2.4 Mixed-platform networks are a policy choice

A network accepting all five platforms is only as strong as the weakest one it
registers. `CodeRegistry` is **platform-scoped**, so a network chooses its exposure
simply by which identities it registers — register only SGX identities and Nitro
evidence is rejected regardless of validity. This should be an explicit genesis
decision, not a default.

---

## 3. Does sharding actually scale? (measured)

`bench_state_sharding_scaling` — the same 8-lane / 16,000-object round applied by
validators at increasing shard counts:

| shards | objects stored | per-validator share | apply | apply tx/s |
|---:|---:|---:|---:|---:|
| 1 (monolithic) | 16,000 | 100% | 23.00 ms | 695,528 |
| 2 | 8,000 | 50% | 11.55 ms | 1,385,549 |
| 4 | 4,000 | 25% | 7.17 ms | 2,232,276 |
| 8 | 2,000 | 12.5% | 5.13 ms | 3,117,956 |
| 16 | 1,000 | 6.2% | 4.58 ms | 3,490,092 |

**Honest reading.** Per-validator state and apply work divide by shard count
exactly as designed, and per-node verify throughput rises from ~0.7M to ~3.5M tx/s.
The initial speedup was ~5× at 16 shards, not 16×, because three costs were paid per
round regardless of partitioning. Measuring them
(`bench_round_constant_breakdown`, 8 lanes / 16,000 objects) settled which of those
could be fixed:

| cost | time | scales with | shardable? |
|---|---:|---|---|
| cross-lane conflict checks | **2.035 ms** (77% of the floor) | objects | **yes — perfectly** |
| attestation verification | 0.606 ms | lanes | already does (quorum slice) |
| deterministic ordering | 0.001 ms | lanes | no — and needn't (1 µs) |

### 3.1 Sharding the conflict check (built)

Conflicts **partition perfectly**: a conflict is defined on a *single object*, so
object X's conflicts are detectable only by whoever owns X. If every shard checks
its own slice, every possible conflict is caught **exactly once** — complete,
non-redundant coverage at 1/N the cost. Measured
(`bench_sharded_conflict_checking`, 16,000 objects):

| shards | conflict check | speedup |
|---:|---:|---:|
| 1 | 1.660 ms | 1.0× |
| 4 | 0.380 ms | 4.4× |
| 8 | 0.189 ms | 8.8× |
| 16 | 0.106 ms | **15.7×** |
| 32 | 0.080 ms | 20.7× |

Near-linear to 16 shards, saturating at 32 because the per-lane transaction-set
check stays global (one entry per lane, run by every shard so duplicate lanes are
caught everywhere).

**Is it a security concern? Only if coverage is left implicit — so it isn't left
implicit.** A validator that checks just its slice knows only that *its* slice is
clean; committing requires knowing the round is **globally** clean. Applying on a
partial check would silently downgrade the double-spend guarantee. So coverage is
**structural**: `certify_shard_conflicts` produces a `ShardConflictCertificate`
bound to a commitment over the exact lane set, and `apply_lane_round_certified`
**rejects** any round whose certificates do not cover every shard for that same lane
set. Tests prove it: incomplete coverage rejects, certificates from another round do
not satisfy coverage (replay), and exactly one shard — the object's owner — catches
a planted double-spend while monolithic always catches it.

**Residual security model:** identical in kind to sharded *verification*, which the
design already accepts — each shard needs an honest quorum, since a fully byzantine
shard could falsely certify its slice. Per-shard quorum size is therefore the
security floor. A tradeoff, not a new class of risk.

**Ordering is deliberately not sharded.** Every validator must compute the *same*
total order or state diverges; it is O(N log N) on lane count and measured at 1 µs.
Sharding it would trade determinism for nothing.

**What sharding does and does not do for the 100M tx/s figure.** It does *not*
multiply production — aggregate throughput is still `N_lanes × per-lane production`
(doc 23). What it does is remove the **state ceiling**: without it, every validator
must hold all state, so sustained high throughput eventually exceeds any single
node. Sharding is what makes the projection *sustainable* rather than a burst, and
it raises the per-node verification ceiling ~5× so the full-verification crossover
moves out correspondingly.

**Status: the apply and execution sides are finalized** (shard-aware execution,
exactly-once coordination, per-shard storage, cross-shard delta shipping).
Monolithic remains the default and is unaffected.

---

## 4. Wiring audit — what is connected, end to end

| layer | status |
|---|---|
| Economics (fee market, congestion, tokenomics) | ✅ settled inline in both production paths |
| Balance settlement + per-account deltas + commitment | ✅ in attestation body; verify unchanged |
| Micro-DAG conflict rejection (pre-execution) | ✅ |
| Macro-DAG multi-lane round + deterministic ordering | ✅ |
| Cross-lane double-spend defenses (object, account, tx-set) | ✅ 5 named tests |
| Attestation producer binding (anti-framing) | ✅ **new this round** |
| Sharded verification (bounded slice) | ✅ measured bounded 2–5 lanes to N=128 |
| State sharding (opt-in mode, shard-aware execution) | ✅ monolithic default |
| Cross-round pipelining (both modes) | ✅ |
| Live network round over real transport | ✅ `ValidatorNetwork::bind` production-first |
| Real TEE attestation, 5 platforms | ✅ + platform-agnostic registry/evidence |
| Multi-core execution | ✅ rayon across the independent set |
| Accelerator backends (GPU/TPU/NPU) | framework ✅, concrete backends per-hardware |

### Known gaps (deliberate, not oversights)

1. **Sampled re-execution backstop** — defense-in-depth against a *compromised* TEE
   (design captured doc 22 §5; the balance-delta sync it needs is in place).
2. **Registry governance distribution** — `CodeRegistry` exists; distributing and
   updating it through on-chain governance is not wired.
3. **Multi-machine orchestration** — devnet/testnet topology, peer discovery
   configuration, genesis distribution.
4. **Cross-shard live driver** — classification and per-shard application are done;
   routing transactions to their coordinating shard across the network is part of
   the mempool/routing layer.
5. **Accelerator backends** — per-hardware, when that hardware is in hand.

---

## 5. Forward plan — review, docs, devnet, testnet, beta-mainnet, dApps

Ordered so each stage's prerequisites are genuinely met before the next.

### Stage A — Canonicalization (immediate)
The code as it stands **is** the canonical design, so the narrative artifacts must
be reconciled to it, not the reverse.
- **Whitepaper**: update to reflect (a) settlement + balance-delta sync with
  commitment rather than root inclusion, (b) corruption detection as
  attestation-measurement verification rather than re-execution, (c) sender-sharded
  multi-lane settlement, (d) producer binding in the attestation body, (e) state
  sharding as an opt-in mode and pipelining as a round-lifecycle property,
  (f) the five-platform TEE model with a platform-agnostic registry.
- **README**: rebuild around the finalized layout, the verification suite, and how
  to run a node in each mode.
- **Doc-set review**: audit the existing ~200-doc list against the finalized code;
  mark stale, add missing. Docs 21–28 are the new findings to fold in.

### Stage B — Node operations documentation
What an operator needs that does not exist yet:
- Node roles and expected behavior (producer / verifier / light client) —
  responsibilities, resource profile, failure modes.
- **TEE operations guide per platform**: building the enclave image, obtaining
  measurements, registering them, configuring trust roots, device prerequisites,
  and what each failure mode looks like in logs.
- Validator lifecycle: join, stake, produce, slashing conditions, exit.
- Configuration reference: subnet policy, sharding mode, pipeline depth, transport.

### Stage C — Devnet (single-operator, multi-process)
- Genesis tooling (accounts, validator set, registry, trust roots).
- Multi-process launch on one machine over real `TcpTransport`.
- Observability: metrics, structured logs, health endpoints.
- **Exit criterion**: N processes produce, gossip, converge, and settle for a
  sustained run with the full verification suite green.

### Stage D — Testnet (multi-machine, real TEE)
- Deploy to real TEE hardware (AWS Nitro first).
- Register real measurements; distribute trust roots.
- Validate the properties only multi-machine can show: aggregate throughput across
  parallel producers, sharded verification under load, live equivocation/slashing.
- **Exit criterion**: sustained multi-machine operation, corruption detection
  demonstrated against a deliberately-modified validator binary.

### Stage E — Beta-mainnet readiness
- External security review (the attack surface catalogue in doc 22 §10 plus §2.3
  here is the starting brief).
- Sampled re-execution backstop, if the threat model calls for it.
- Registry governance on-chain.
- Economic parameter finalization at real load.

### Stage F — dApp platform
- Contract/VM developer documentation and SDK.
- Testnet faucet + explorer.
- Reference dApps exercising each privacy level and both sharding modes.

**Recommended immediate next step:** Stage A. The whitepaper and README currently
describe design decisions that this work has since superseded — reconciling them is
both quick and the prerequisite for every doc after it, because everything in
Stages B–F cites them.

---

## 6. Verification state at this checkpoint

- **940 library tests** across 9 crates; **38 end-to-end**; **144 TEE**; clippy 0.
- All 7 named security invariants green.
- No throughput degradation: PRODUCE ~11.4–11.5k, VERIFY ~1.08M, economics
  byte-identical across runs.
- Sharding measured: per-validator apply work divides by shard count (~5× faster
  per-node verify at 16 shards).
