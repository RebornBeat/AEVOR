# 22 — Where Corruption Detection Belongs, and What Scaling Needs at Real TEE

**Status: design capture, not a milestone.** This records a decision reached by
review before committing code: a re-execution-based corruption primitive was
prototyped, measured against the real-TEE model, found to be the wrong layer for
production, and **reverted**. This document captures the correct design so it is
built with F-E1 (real TEE), not before it. The codebase is at the balance-delta
state (settlement + `StateDelta` + `balance_commitment`); nothing here is wired
yet.

---

## 1. The question

Fast-path verifiers apply an attested batch **without re-executing** — instant,
~1.2M tx/s. That catches *tampering* (a delta that doesn't reproduce the attested
root, a balance delta that doesn't match its commitment, a bad signature, a
foreign rule version). It does **not**, on its own, catch a producer that ran the
VM but attested to a **self-consistent yet incorrect** transition. So: how do we
catch that rogue actor, and how fast — without breaking scaling, and taking real
TEE into account?

## 2. What real TEE changes (the decisive point)

Proof-of-Uncorruption exists so validators verify **without re-executing**. With
real hardware TEE attestation (Intel SGX / AMD SEV-SNP / ARM TrustZone / RISC-V
Keystone / AWS Nitro), the attestation is a **hardware proof** that:

1. a specific, **measured code binary** ran,
2. inside a **genuine enclave** on genuine hardware,
3. producing the **attested output** (the state transition).

A verifier that checks the attestation therefore confirms the *right code ran
correctly in a genuine TEE* — so **corruption is caught instantly, at verify
time, with zero re-execution**. A rogue cannot produce a valid attestation for
wrong execution without either running unmeasured code (the code measurement in
the attestation won't match the network-agreed one → rejected) or breaking the
TEE hardware boundary (the TEE threat model). This is O(1) per block and is the
real scaling path.

## 3. Why re-execution is the wrong layer for the mechanism

The prototyped primitive (`reexecute_and_detect_corruption`) re-executed the
producer's transactions and compared the result to its attestation. It works, but:

- It calls the produce path, so it runs at the **produce rate (~12k tx/s)** — by
  our own measured numbers, **~100× slower than fast-path verify (~1.2M tx/s)**.
  Using re-execution as *the* corruption mechanism reintroduces exactly the O(N)
  execution cost PoU exists to remove. It is anti-scaling.
- With real TEE it is **redundant**: the attestation already proves correct
  execution. Re-executing would re-derive what the hardware already guarantees.

So re-execution is not the production mechanism. It has at most an *optional*
role (§5). It was reverted from the finalized engine.

## 4. What is actually native-to-AEVOR for real-TEE corruption detection

The TEE proves *"this measured code ran correctly."* AEVOR must supply the part
that says *"...and that measured code is the one the whole network agreed to run."*
That is native-to-AEVOR and is O(1) per block:

1. **Accepted-code-measurement registry.** The canonical protocol binary's enclave
   measurement (per TEE platform) is part of the network's agreed configuration —
   the genesis/governance-pinned set of acceptable measurements.
2. **Attestation verification checks the measurement.** A verifier accepts a
   producer's attestation only if its code measurement is in the registry, the
   enclave is genuine (platform attestation valid), and the signature verifies over
   the attested body. Wrong code → wrong measurement → rejected instantly.
3. **Governance-coordinated upgrades.** Updating the protocol binary is a
   coordinated registry update — the real-TEE analogue of, and a superset of, the
   `PROTOCOL_RULES_VERSION` pin shipped today. With real TEE the **measurement
   subsumes the rule version**: it uniquely identifies the exact code, including
   its economic rules, so a validator on different economics has a different
   measurement and is rejected. `PROTOCOL_RULES_VERSION` remains a useful coarse
   pin in the interim and a human-readable version tag.

This is the corruption-detection design to build **with** F-E1. It is instant,
O(1)/block, and needs no re-execution.

## 5. The only legitimate role for re-execution: optional defense-in-depth

TEEs are not infallible — SGX alone has seen Foreshadow, Plundervolt, SGAxe, ÆPIC,
and others. A production deployment may therefore want a **small, tunable
re-execution quorum** that samples a fraction of blocks and re-executes them as a
backstop against a *compromised* TEE (one producing valid attestations for wrong
output because its key was extracted). Key properties, to be designed with the TEE
threat model:

- **Sampled, not universal.** A random/assigned small quorum re-executes a fraction
  of blocks; the rest ride the instant attestation path. The re-execution load is a
  tunable security/throughput dial, not an every-block cost.
- **Bounded latency.** Sampling rate sets the expected time to catch a compromised
  TEE; higher sampling = faster detection, lower throughput.
- **Prerequisite already in place.** Sound re-execution needs the checker to hold
  the producer's *prior* state — objects (via `prior_root`) **and** balances.
  Balances are consistent because they sync atomically with objects in the same
  `StateDelta` (this is exactly why balance deltas are shipped, not derived). So the
  balance-delta work already done is the enabler if/when this backstop is built.

Because its right form (sampling rate, quorum assignment, sla­shing weight) depends
on the concrete TEE integration and threat model, it is captured here and built
with F-E1 — not bolted on beforehand.

## 6. What is already correct for real TEE (kept)

- **Balance settlement + per-account balance deltas + `balance_commitment`.** With
  real TEE the enclave attests the full transition, including the balance changes
  bound by `balance_commitment` in the attested body. Verifiers apply the shipped
  balance deltas (cheap HashMap writes) and check them against the commitment — no
  re-execution, and TEE-proven correct. Measured verify throughput is unchanged
  (~1.0–1.15M tx/s) vs +112–136% for Merkle-root commitment (doc 21 §2.4). This is
  the scaling-correct design and stays.
- **`PROTOCOL_RULES_VERSION`** in the attestation body — useful now, subsumed by the
  code measurement under real TEE.

## 7. Multi-lane balance settlement: DECIDED — sender-sharded routing (validated)

`apply_lane_round` applies each lane's **absolute** balance deltas. The question
was whether that is correct when lanes run concurrently. The decision, for the
current **fee-only** economy, is **sender-sharded routing**, and it is now
validated by test (`multi_lane_settlement_correct_under_sender_sharding`).

**Why it is correct for fees.** The only balance movements today are: a sender is
debited its fee, and the lane's **own** validator is credited. Under sender-
sharding, every account is touched by exactly one lane in a round:

- A sender's transactions are nonce-ordered and route together into one lane, so
  no sender is debited by two lanes.
- Each lane credits only its own producer/validator, and a producer produces one
  lane, so no validator account is credited by two lanes.

So concurrent lanes touch **disjoint accounts**; per-lane absolute deltas apply
without contention and without cross-lane double-spend. The test produces two
lanes from two distinct senders on disjoint objects and confirms a verifier
applying the round reflects **both** debits exactly. (Absolute deltas are also
self-correcting: a verifier that missed a block heals to the current balance on
the next apply, given the same global genesis.)

**When transfers arrive.** A user-to-user transfer touches two accounts (payer +
payee) that may fall in different shards, reintroducing cross-lane contention on
the payee. That is the classic cross-shard problem and is **out of scope for the
fee-only model**; it will be handled with the transfer feature via one of:
(a) a cross-shard receipt/2-phase protocol keeping balances off-Merkle, or
(b) modelling accounts as first-class objects so the existing cross-lane object
conflict rejection also shards accounts (correct, but that puts balances back in
the Merkle root with the measured +112–136% verify cost — so only if light-client
balance proofs are also wanted). Captured; decided with transfers, not now.

**Routing layer.** The sender→lane assignment that enforces sharding lives in the
mempool/routing layer, which is part of the network / multi-node rollout (it
cannot be exercised single-node). The apply side is correct today under the
sharding invariant, which the tests establish by construction.

## 8. Decision

- **Reverted** the re-execution corruption primitive from the finalized engine — it
  is not the production mechanism and its cost is anti-scaling.
- **Corruption detection is TEE attestation verification** (code-measurement registry
  + genuine-enclave + signature), instant and O(1)/block — built **with F-E1**.
- **Optional sampled re-execution** is a defense-in-depth backstop against TEE
  compromise — a tunable dial, designed **with F-E1**, enabled by the balance-delta
  sync already in place.
- **Multi-lane balance settlement: sender-sharded routing**, validated by test for
  the fee-only economy; transfers get a cross-shard protocol when they land.
- **Kept**: balance settlement, balance deltas, `balance_commitment`,
  `PROTOCOL_RULES_VERSION` — all correct and scaling-neutral for real TEE.

## 9. Scaling-stack status (honest, single-core sandbox)

What each scaling axis actually is today, with the new economics/balance work
folded in:

- **Multi-core (per-node parallelism): ✅ finalized.** `node/src/compute` selects a
  backend sized to the host; execution runs the micro-DAG independent set across all
  cores (rayon `par_iter`). Settlement is a cheap sequential pass *after* parallel
  execution (HashMap writes), so it does not serialize the parallel section. Balance
  deltas are gathered from the accepted set — no effect on execution parallelism.
- **Multi-lane (macro-DAG): ✅ apply side finalized; live concurrent production needs
  multi-node.** `apply_lane_round` (full) and `apply_lane_round_sharded` (bounded
  per-validator slice) apply N lanes' object writes *and* balance deltas, checking
  each lane's `balance_commitment`. Correct under sender-sharding (§7). The routing
  that assigns txs to lanes and the actual concurrent producers on separate machines
  are the network / multi-node rollout.
- **Sharded verification: ✅ finalized (apply).** `apply_lane_round_sharded` +
  `LaneAssignment` bound each validator's verify load to its assigned slice, so
  aggregate scales with validator count past the ~93–98-lane full-verification
  crossover. Balance deltas ride the same per-lane path.
- **GPU / TPU / NPU accelerators: framework ✅, concrete backend ⛔ (per-hardware,
  future).** The `ComputeBackend` trait is the pluggable seam for offloading batchable
  primitives; a concrete accelerator backend is added per target when that hardware is
  in hand. Settlement is intentionally CPU (branchy HashMap work, not accelerator-
  shaped), so it is unaffected.
- **Multi-node (live network): 🟡 logic validated in-process; real wire pending.**
  A **`Transport` seam** now sits between the node and its peers (`node/src/transport`):
  a `NetworkMessage` set + an **in-memory backend** that connects N `NodeEngine`s in
  one process. The full macro-DAG round runs over it end-to-end —
  `multi_node_round_over_transport_converges_with_settlement`: several validators each
  produce a lane on disjoint accounts/objects, broadcast it, and every validator
  applies the collected round and **converges to one state root with consistent
  settled balances** (object roots + balance deltas both). This validates the network
  *logic* single-core. What remains: the **real gossip/TCP backend** — `aevor-network`
  already has the primitives (gossip, propagation, discovery, erasure-coded
  availability, bandwidth shaping, 61 tests); it plugs in behind the same `Transport`
  trait, so the consensus flow is unchanged whether a message crosses a process or the
  globe. Also carried by the real backend: the sender-sharding tx routing (§7) and
  peer/latency/loss handling. The wire needs multi-machine to prove.
- **Real TEE (F-E1): ⛔ last.** Simulated today; §2–§5 capture the corruption-detection
  design that lands with it.

Node types under all of the above: **producers** execute + settle + ship
`StateDelta` (objects + balance deltas) under an attestation; **verifiers** apply
without re-executing (object root + `balance_commitment` checks, HashMap balance
writes) at ~1.0–1.2M tx/s; **light clients** check the object root + balance
commitment cheaply. All three are consistent with the balance-delta design.

## 10. Attack surface — what is rejected, and where it is tested

Every item below is covered by a passing test (32 e2e + 57 lib). "No double-spend"
is a *tested rejection*, not an assertion.

**Double-spend (the core property):**
- **Cross-lane object double-spend** — two lanes writing the *same object* (distinct
  txs). `apply_lane_round` step 2b rejects the round; last-write-wins can never
  silently drop a conflicting spend. Test: `cross_lane_object_double_spend_is_rejected`.
  *(This gap was found and fixed during this review — the prior check only rejected
  duplicate tx-commitments.)*
- **Within-lane conflict** — two txs writing the same object in one batch: one is
  rejected pre-execution (micro-DAG). Test: `conflicting_transactions_are_rejected`.
- **Cross-lane balance conflict** — two lanes settling the *same account*
  (violating sender-sharding). `apply_lane_round` step 2c rejects it, so a fee
  cannot be lost or an account over-debited across lanes. Test:
  `cross_lane_same_account_settlement_is_rejected`.
- **Balance overdraft** — spending more than an account holds: the affordability
  guard drops it before execution. Test:
  `balance_settlement_debits_senders_credits_validator_and_guards_abuse`.

**Forgery / tampering (caught at verify, no re-execution):**
- **Tampered object delta** (doesn't reproduce `new_root`) — rejected. Test:
  `corruption_detection_produces_slashing_evidence`.
- **Tampered balance delta** (single batch and per-lane) — rejected by the
  `balance_commitment` check. Tests: the settlement/corruption tests +
  `tampered_lane_balance_delta_is_rejected`.
- **Forged / invalid attestation** (bad signature, or a foreign
  `PROTOCOL_RULES_VERSION`) — rejected; `detect_lane_corruption` emits slashing
  evidence. Test: `corruption_detection_produces_slashing_evidence`.
- **Bad transaction signature** — rejected. Covered by the signed-tx path
  (`tamper` helper).

**Malformed rounds / replay / mint:**
- **Lane not forking from the round base** (spliced from another history) —
  rejected. Test: `lane_not_forking_from_round_base_is_rejected`.
- **Duplicate tx set across lanes** (same `tx_commitment`) — rejected. Test:
  `duplicate_transaction_set_across_lanes_is_rejected`.
- **Post-genesis mint** (`fund()` after height 0) — rejected. Test:
  `independent_nodes_settle_identically_same_rules_same_result`.

**Not degrading throughput:** the two new cross-lane checks are O(objects +
accounts) HashSet passes per round — cheap next to the apply, and only on the
multi-lane path. Benchmarks re-run after adding them: single-lane economics
byte-identical (base fee 990, fee/tx 485,000, reward = debit), single-lane
throughput within session variance, multi-lane apply ~402k–810k tx/s across
1–32 lanes. No regression.

**Still relying on the routing invariant (not a rejection):** sender-sharding —
that a given account's txs are routed to one lane — is enforced by the mempool /
routing layer (network rollout). `apply_lane_round` now *defends* against
violations of it (steps 2b/2c reject same-object and same-account across lanes),
so a bug or malicious producer cannot turn a routing violation into a
double-spend; it becomes a rejected round instead.
