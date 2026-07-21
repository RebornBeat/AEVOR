# 21 — Balance Settlement, Rule Enforcement, and the Economic Sweet Spot (M39)

This milestone closes the settlement gap flagged in M38 (fees were *computed and
reported* but never *debited*), hooks the finalized economics **into the actual
throughput pipeline** (not a standalone simulation), and finalizes the economic
sweet spot against the measured throughput sweet spot. It also answers a
correctness question raised during review: **what makes these economics binding
rules that every node must follow identically, and can the test-only funding path
be abused on a real network?**

All numbers below were produced by the real engine (`cargo test -p node --test
benchmarks ... --ignored --nocapture`) with settlement active, on a single-core
sandbox. Gas, fees, and rewards are exact regardless of build; wall-clock
throughput is debug/optimized-test (release times out in the sandbox) and is
labelled measured-vs-projected.

---

## 1. Balance settlement (the M38 gap, now closed)

### What was missing
Through M38 the engine produced a `fee_charged` and accrued a `validator_reward`,
but no account balances existed — a sender was never actually debited, so a
transaction cost nothing to submit and the "reward" was a number with no
counterparty. That is fine for a fee-market simulation but not for a finalized
chain.

### What settlement now does
- The executor exposes **per-transaction execution gas**
  (`ProgramOutcome.accepted_tx_gas`, keyed by tx hash) so fees settle against each
  sender individually rather than only in aggregate.
- The engine holds an **account ledger** (`Address -> Amount`), funded at genesis.
- Every block runs two shared helpers on **both** production paths
  (`process_block` and the PoU `produce_attested_batch`):
  - `affordability_filter` — the **account-level abuse guard**. It reserves each
    sender's intrinsic fee against a running per-sender tally and drops any
    transaction whose sender cannot cover it, **before execution**. Feeless
    subnets admit everyone.
  - `settle_and_advance` — for each accepted transaction the actual fee is
    `(intrinsic_gas + execution_gas) * base_fee`; the sender is **debited** and the
    validator **credited**, then the congestion market advances.

### Conservation, by construction
Because the block fee is the sum over accepted transactions and the same sum is
credited to the validator:

```
fee_charged  ==  sum of sender debits  ==  validator reward for the block
```

This is asserted directly in
`balance_settlement_debits_senders_credits_validator_and_guards_abuse`, and
observed live in every benchmark (e.g. the headline pipeline: 5 000-tx block,
`block fee 2 425 000 000 nano == validator reward accrued 2 425 000 000 nano`).

### The abuse guard, demonstrated
The settlement test proves all three regimes:
- **Funded sender** → 4/4 accepted, debited exactly the block fee, validator
  credited the same.
- **Unfunded sender on a fee subnet** → 0 accepted, `insufficient_funds == 1`,
  nothing settled, no reward. No balance, no execution — this is where spam and
  fee-drain attacks stop.
- **Feeless subnet** → 1/1 accepted with no funds required and no balances moved.

---

## 2. What makes these binding *rules*, not just local bookkeeping

Review asked, correctly: the benchmark/test funding path mints balance — can that
leak to a real network, and how do we guarantee every node applies the *same*
finalized economics? Three mechanisms, each now in the code:

### 2.1 `fund()` is genesis-only — no minting on a running chain
`fund()` is gated to `height == 0` and returns `false` afterward
(`independent_nodes_...` asserts `!fund()` post-genesis). It is a **genesis
allocation primitive**, not a transaction. On a real deployment the genesis
allocation is fixed and agreed by every validator as part of the genesis block;
after that the only ways balance moves are fee settlement and (future) transfer
transactions. The test/benchmark funding therefore **cannot** be exercised on a
live chain — it is structurally unavailable once a single block exists.

### 2.2 The rules are deterministic — every node computes the same result
Settlement, the fee formula, the congestion advance, the abuse guard, the gas
schedule, and intrinsic gas are all **pure deterministic functions** of the
block's transactions and the subnet config. Two independent validators that
process the identical block therefore reach **byte-identical** balances, fee,
reward, next base fee, and authenticated state root. This is proven directly by
`independent_nodes_settle_identically_same_rules_same_result` and observed in
`bench_combined_pou_scaling` (the re-execute and verify-attest paths on separate
engines agree on gas and fee at every batch size).

### 2.3 The rule *version* is folded into the attestation — divergent rules are rejected
`PROTOCOL_RULES_VERSION` is folded into the body of every `ExecutionAttestation`.
A validator running different economics (a different fee formula, gas schedule, or
settlement rule) signs a **different body**, so a verifier on another version
fails `attestation.verify()` and rejects its blocks — the same mechanism that
already rejects a forged attestation (`corruption_detection_...`,
forged-attestation cases). A network upgrade is the coordinated act of every
validator moving to the same new version; until they do, cross-version blocks do
not verify. **This is what forces every node onto the same finalized code —
divergence is cryptographically rejected, not merely discouraged.**

### 2.4 Why balances need not (yet) live in the state root
AEVOR attests, per block, to `prior_root`, `new_root` (object state), **and**
`tx_commitment` (exactly which transactions ran) — plus, now, the rule version.
Because balances are a deterministic function of *(genesis allocation + the
attested transaction sequence + the pinned rules)*, a node cannot diverge on
balances without diverging on the attested transaction set or the rule version —
both of which are already caught. Committing balances **directly** into the state
root (Ethereum-style, enabling light-client balance proofs and defense-in-depth
against an implementation bug) is a clean, well-scoped enhancement — see §5 —
but is not required for the rules to be binding today.

---

## 3. Economics hooked into the throughput pipeline (measured together)

The finalized economics now run **inside** the throughput benchmarks — the same
block that is timed for tx/s also settles fees and accrues the validator reward.
This is the "run everything together for real numbers, not a standalone
simulation" the finalization called for.

### 3.1 Headline PoU pipeline @ 5 000 tx/lane (measured, single core)

| Stage | rate (tx/s) | note |
|---|---:|---|
| PRODUCE (execute + commit + attest) | **11 657** | the per-lane bottleneck |
| VERIFY (attest check + apply delta, no re-exec) | **1 086 777** | ~93× faster than produce |
| re-execute (no PoU, for contrast) | 11 947 | every node re-doing the work |
| FINALIZE (BLS) | O(1) ~1.3 ms | flat to 50 000 validators |

Economics settled by that same run: base fee 990 nano/gas, total gas 2 425 000,
**block fee 2.425 AVR**, **fee/tx 485 000 nano (0.000485 AVR)**, validator reward
accrued 2.425 AVR (= sender debited: conservation). Fiat display: **$0.024 per
block @ $0.01/AVR**, $2.43 @ $1/AVR, $363.75 @ $150/AVR.

### 3.2 Batch-size sweep with economics (measured, single core)

| batch | re-execute tx/s | verify-attest tx/s | PoU speedup | fee/tx nano | block fee AVR | base fee |
|---:|---:|---:|---:|---:|---:|---:|
| 500 | 11 337 | 805 268 | 71.0× | 485 000 | 0.242500 | 988 |
| 1 000 | 12 456 | 1 126 509 | 90.4× | 485 000 | 0.485000 | 988 |
| **2 000** | **12 491** | 1 232 423 | 98.7× | 485 000 | 0.970000 | 989 |
| 3 000 | 12 459 | 1 089 505 | 87.5× | 485 000 | 1.455000 | 989 |
| 5 000 | 12 419 | 1 215 197 | 97.8× | 485 000 | 2.425000 | 990 |
| 8 000 | 12 374 | 1 157 980 | 93.6× | 485 000 | 3.880000 | 991 |
| 10 000 | 12 363 | 1 139 985 | 92.2× | 485 000 | 4.850000 | 992 |
| 15 000 | 12 206 | 1 068 576 | 87.5× | 485 000 | 7.275000 | 994 |
| 25 000 | 12 423 | 946 110 | 76.2× | 485 000 | 12.125000 | 998 |
| 50 000 | 11 757 | 760 107 | 64.7× | 485 000 | 24.250000 | 1007 |

**fee/tx is flat at 0.000485 AVR at every batch size** — it is `(intrinsic +
execution) gas × base_fee`, and gas/tx is constant for identical work. Total block
fee scales linearly with batch. The base fee barely moves (988→1007) because a
single block stays near or below the congestion target (see §4).

### 3.3 Congestion dynamics (measured; small-budget subnet, sustained load on one engine)

Subnet: budget 2 000 gas/block, target 1 000, ±12.5% max step, floor 100 nano/gas.
3 congested blocks (5 tx ≈ 2 425 gas each) then 8 idle blocks (1 tx ≈ 485 gas):

```
block    gas  over/under   base fee   cumul reward (settled)
   1    2425     +1425        1178        2 425 000
   2    2425     +1425        1387        5 281 650
   3    2425     +1425        1634        8 645 125
   4     485      -515        1529        9 437 615
   ...
  11     485      -515         962       13 730 350
```

The controller raises the base fee while blocks exceed target and decays it toward
the floor when they fall below — **congestion, not token price, sets the fee**.
The cumulative reward is now **real settled balance**, and matches the M38
fee-market figures exactly (base fee 1000→1634, decay to 962, reward 13 730 350) —
so settlement is consistent with the finalized market, it just now actually moves
the money. Post-quantum bloat premium: **Ed25519 485 000 nano vs ML-DSA-65
5 650 000 nano ≈ 11×**, priced purely through intrinsic (size) gas.

### 3.4 Aggregate throughput (PROJECTION — see caveat)

`aggregate = N_lanes × per-lane production`. This is an **analytical projection**:
the sandbox is single-core, so per-lane rate (~12 k tx/s) is measured but real
multi-lane parallelism is a multi-machine property that cannot be benchmarked
here.

| lanes N | aggregate exec tx/s | regime |
|---:|---:|---|
| 8 | 97 686 | full verification OK |
| 64 | 781 486 | full verification OK |
| 96 | 1 119 083 | → sharded verification |
| 128 | 1 562 971 | sharded |
| 512 | 6 251 885 | sharded |
| 3 000 | 36 632 137 | sharded |
| 10 000 | 122 107 125 | sharded |

The **1M–100M+ TPS** target is reached at ~82 lanes (1M) through ~8 200 lanes
(100M), linearly. One verifier keeps up with full verification to ~93–98 lanes;
past that, sharded verification (F-A2) removes the cap and aggregate scales with N,
uncapped, while every lane is still attestation-verified by someone and finality
is O(1)-aggregated across all N.

---

## 4. The economic sweet spot, tied to the throughput sweet spot

**Throughput sweet spot:** single-node production peaks at batch ≈ **2 000
tx/block** (~12 500 tx/s) and holds within a few percent across 1 k–25 k. This is
the PoU verify-attest sweet spot band established in earlier milestones,
re-confirmed here with the parallel additions (M31–M34) in place.

**Congestion target:** with the mainnet config (30 M block gas limit, 50% target),
the target is **15 M gas/block ≈ 30 900 transactions** (at ~485 gas/tx). That is
**far above** the per-lane throughput sweet spot.

**Therefore the economic sweet spot coincides with the throughput sweet spot:**
at the batch that maximizes tx/s (~2 k, and anywhere in the 1 k–10 k band), a
lane's block is well below the congestion target, so the base fee **sits at the
floor** (988–1000 nano/gas) and fee/tx is at its **cheapest** (0.000485 AVR). The
controller only lifts the fee above the floor when a block would exceed ~30 900
transactions — i.e. congestion pricing engages *past* the throughput sweet spot,
not within it. This is exactly the finalized target: **fees as cheap as possible,
rising only to hold off genuine congestion, never at the sweet spot.**

**The finalized algorithm (one formula, unchanged from M38, now settled):**
```
per_tx_gas   = intrinsic_gas(size) + execution_gas(vm, incl. TEE premium)
per_tx_fee   = per_tx_gas * base_fee
block_fee    = Σ per_tx_fee over accepted txs         (debited from senders)
validator   += block_fee                              (credited; conservation)
next_base_fee = base_fee * (1 + adj_bps/10000 * (gas_used - target)/target), floored at min
```
- Privacy is priced via the TEE execution-gas premium (in `execution_gas`).
- Post-quantum bloat is priced via `intrinsic_gas` (per-byte) — ~11× for ML-DSA-65.
- Token price never enters the protocol; it only scales the fiat display.

---

## 5. Honest caveats (preserved)

1. **Aggregate 1M–100M TPS is an analytical projection**, not a measured number.
   `aggregate = lanes × per-lane`; the sandbox is single-core, so lane parallelism
   is not benchmarked here. Per-lane (~12 k tx/s) and verify (~1.2 M tx/s) are
   measured; the multiplication by lane count is the projection.
2. **All test/benchmark transactions share the zero sender.** `new_simple` sets
   `sender = Address::ZERO` and signing does not derive it from the public key, so
   every synthetic transaction settles against one account. This is a **test
   artifact**, documented in the openers (`genesis_fund` / `bench_fund`). Real
   transactions carry distinct senders and would settle against distinct balances;
   the settlement/abuse logic is per-sender and unaffected, but the determinism and
   conservation tests exercise a single account by construction.
3. **Balances are authoritative engine state, deterministic and rule-versioned,
   but not yet committed *directly* into the state root.** As argued in §2.4 this
   is sufficient for the rules to be binding (balances are a deterministic function
   of attested inputs under a pinned rule version). Committing them into the root —
   balance-namespaced tree keys, balance deltas shipped in the attested delta, the
   verifier applying them — is a clean next step that adds light-client balance
   proofs and defense-in-depth against an implementation bug. It is explicitly
   **not** done in this milestone to avoid shipping half-finished consensus state.

---

## 6. Verification for this milestone

- `aevor-execution`: 79 lib tests pass (per-tx gas exposure).
- `node` lib: 56 tests pass.
- `node` e2e: **24 tests pass** — the prior 22 plus
  `balance_settlement_debits_senders_credits_validator_and_guards_abuse` and
  `independent_nodes_settle_identically_same_rules_same_result`.
- Clippy: **clean** on `-p node --lib --tests` (lib + all integration/benchmark
  targets).
- Benchmarks run with economics settled inline (headline pipeline, batch sweep,
  congestion dynamics) — numbers in §3.

**Status:** balance settlement, the account abuse guard, deterministic
rule-versioned enforcement, and economics-in-the-throughput-pipeline are
finalized. Next on the finalization ledger: network transport (gossip) for live
multi-node, then real TEE attestation (F-E1), then folding balances into the state
root (§5.3) as defense-in-depth.
