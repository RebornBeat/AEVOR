# Performance, Uncapped Scaling, and the PoU Fast Path — Analysis, Hypotheses, and Benchmark Plan

This document answers four questions that came up after the M21 performance milestone:

1. **Why did throughput flatline at ~14k tx/s, and why is that the *right* shape?**
2. **How do we go higher — including fully exploiting Proof of Uncorruption (PoU) so we are not verifying transactions one-by-one?**
3. **How should we measure TPS, and at what scales (validators 3k/10k/50k, txs 100k→1M+), given AEVOR is *uncapped* unlike a BFT chain?**
4. **What is the granular deployment model (permissionless / permissioned / feeless subnets / fee'd subnets / privacy vs non-privacy) and is it actually in the design?**

Everything below is grounded in the whitepaper and the code; where something is a *hypothesis to measure* rather than an established fact, it is labelled **[HYPOTHESIS]**.

---

## 1. The flatline — what it is and why it is good

### Before M21 (the degrading curve)
The M16 benchmark showed execution throughput **falling** as batches grew: 13.4k tx/s at 1k txs → **3.8k tx/s at 25k txs**. That downward slope is the signature of **superlinear cost**. Two sources:

- **O(n²) conflict detection.** Each incoming transaction was compared pairwise against *every* already-accepted transaction. For a batch of n mostly-independent txs, that is ~n²/2 comparisons.
- **O(n) per-block Merkle rebuild.** The state root was rebuilt from *all* leaves on every block, and every leaf was re-hashed.

So doubling the batch more than doubled the work — throughput per tx got *worse* as the batch grew.

### After M21 (the flatline)
- Conflict detection is now **O(n)**: two hash sets (accepted writes / reads); a tx conflicts iff any of its writes hits an accepted write/read or any read hits an accepted write — the exact same relation, aggregated.
- The Merkle tree is now **incremental**: per-key leaf hashes are cached (a rebuild never re-hashes unchanged values), and the root is cached between writes.

Result: **~14k tx/s flat across 1k→25k txs.** The curve is horizontal because the per-transaction cost is now *constant* — it no longer depends on how many other transactions are in the batch. **A flat line is exactly what "scales with volume" looks like at the single-node level**: adding more transactions doesn't make each one more expensive.

**Measured confirmation (M24, debug build, single node), now extended to 100k txs:**

| txs | time | throughput |
|-----|------|------------|
| 1,000 | 68 ms | 14,635 tx/s |
| 5,000 | 359 ms | 13,912 tx/s |
| 10,000 | 708 ms | 14,121 tx/s |
| 25,000 | 1,809 ms | 13,818 tx/s |
| 50,000 | 3,514 ms | 14,228 tx/s |
| 100,000 | 7,191 ms | 13,906 tx/s |

The throughput is **flat within noise from 1k to 100k** — a 100× increase in batch size with no per-tx degradation. That is the uncapped-execution shape, measured.

### What the ~14k number *is* (and why it is not the headline)
The ~14k is the **debug-build, single-node, in-process** cost of the full write path for one transaction: signature verify → conflict check (O(1) amortized) → VM execute → persist → incremental Merkle update. It is a *floor*, not a ceiling, and it is deliberately measured pessimistically. Three multipliers are not yet applied (see §2).

---

## 2. How we go higher

Four levers, in rough order of impact:

### (a) Release build — **~10–30×** [HYPOTHESIS, standard for this workload]
Every number in the benchmark is `cargo build` debug (unoptimized, overflow checks, no inlining). Cryptographic code (Ed25519 verify, BLAKE3, Ristretto ops) is precisely what benefits most from `--release`. This alone plausibly moves ~14k → ~150k–400k tx/s single-node.

### (b) Interior sparse Merkle tree — removes the last O(n)
M21 made *leaf* hashing incremental, but the *interior* tree is still rebuilt on change. A true sparse Merkle tree (fixed leaf positions keyed by hash) makes every update an **O(log n)** path recomputation with no shifting. This flattens the Merkle-proof and commit curves fully. (The existing `SparseMerkleTree` in `aevor-crypto` is currently a flat-hash placeholder and should be replaced with a real depth-indexed SMT.)

### (c) Parallel execution scaling — with cores
M21 wired the micro-DAG's independent set to execute in parallel (rayon). On the benchmark box that is a constant-factor win; on a many-core validator it scales with cores. This is bounded by the *width* of the independent set (how many non-conflicting txs a block contains) — which is itself the point of the object-level micro-DAG.

### (d) **The PoU fast path — the big one.** See §3.

Levers (a)–(c) speed up **one node doing all the work**. Lever (d) is architectural: with PoU, most validators **don't do the work at all** — they verify a proof that it was done correctly. That is where "uncapped" actually comes from, and the current benchmark does not measure it yet.

---

## 3. The PoU fast path: verify the proof, don't re-run the computation

This is the heart of the question — *"if TEE PoU proves a system isn't corrupted, fully utilize this to increase speed… we verify the math is verified first against TEEs, in batches, and worry about sender/receiver correlation later… validators are valid until proven corrupted."* That instinct is **exactly the canonical AEVOR design**, and it is the single biggest lever. Here is the precise argument.

### 3.1 What every other chain pays that AEVOR doesn't have to
In PoW and PoS, **every full node re-executes every transaction**. Security comes from replication: you trust the result because thousands of machines independently recomputed it. That means the network's effective throughput is bounded by *a single node's execution rate* — adding validators adds security and redundancy, **not** throughput. (This is true even for chains with parallel execution: each validator parallelizes internally, but *all* of them still re-run everything.)

### 3.2 What PoU replaces it with
Under PoU, a transaction executes **once**, inside a TEE, which emits an attestation: a cryptographic proof that *these inputs produced these outputs through unmodified code on genuine hardware* (whitepaper: "identical inputs produced identical outputs through verified execution processes"). Other validators then **verify the attestation** — a signature/measurement check that is O(1) in the size of the computation — instead of re-executing it.

So the work splits cleanly into two tiers with very different costs:

| Tier | Who does it | Cost | Frequency |
|------|-------------|------|-----------|
| **Execution** | the producing validator's TEE | full VM cost | **once** per transaction |
| **Validation** | every other validator | one attestation verify | once per **batch/block**, not per tx |

The expensive tier runs **once**; the cheap tier is what the rest of the network does. This is why the whitepaper can say *"there is no architectural ceiling on throughput — performance scales unboundedly with computational resources"*: add more execution capacity (cores, validators executing *different* independent shards of the DAG) and total throughput grows, because you are not forcing every machine to redo every computation.

### 3.3 "Valid until proven corrupted" is real-time corruption detection
The model you described — trust a validator's stream while it keeps proving itself, and eject it the instant it can't — is the whitepaper's **real-time corruption detection** (§ "Real-Time Corruption Detection and Mathematical Proof"): *"identifying corruption attempts at the moment they occur… corrupted branches are isolated at the frontier and excluded from state advancement, while all previously finalized transactions remain unaffected."* Combined with the **hybrid staking/slashing** already in the code (`aevor-consensus/src/slashing`), a validator that produces a bad attestation is not just excluded — it is economically punished. So the trust is not naïve: it is "trusted while cryptographically proving correctness, slashed the moment it fails."

### 3.4 The ordering you described is already the pipeline
*"It's not that we verify transactions 1×1 as they come in… we verify they come in and the math is verified first against TEEs with batches, and it worries about matching/validity/correlation to sender/receiver later… this is done prior with the rejections."*

That is precisely the dual-DAG pipeline, and the whitepaper states it almost verbatim (line 719): *"the scheduler determines which transactions are safe to execute in parallel before any execution begins… every transaction that begins execution has already been mathematically verified as conflict-free with its parallel companions."* The pipeline is:

1. **Ingest + pre-execution conflict rejection** (micro-DAG). Conflicting txs are rejected *before* execution — no per-tx serialized consensus, no speculative execution, no rollback. (This is the O(n) pass we just optimized.)
2. **Batch execution + attestation** (TEE). The independent set executes in parallel; the TEE attests the *batch's* correctness. Sender/receiver/balance validity is enforced *inside* the attested execution — it is not a separate per-tx consensus round.
3. **Attestation verification** (all validators). Everyone checks the attestation, not the computation.
4. **Finality** (BLS-aggregated committee signatures) — one aggregate signature, O(1) to verify regardless of committee size.

### 3.5 What this means for the code and the benchmark
The foundation is already built (pre-execution rejection, parallel execution, real TEE attestation from M17, BLS finality). Two concrete steps make the PoU advantage *real and measurable*:

- **[CODE] A "verify-by-attestation" validation path.** Today the single node executes. A non-producing validator should have a code path that *verifies the batch attestation and applies the state delta* instead of re-executing. This is the tier-2 path in §3.2. It already has its building blocks: `aevor-tee` real attestation verify + the execution attestation type (`ExecutionAttestation`).
- **[CODE] Batch attestation.** Attest a *batch* of transactions with one proof rather than one proof per transaction, so tier-2 cost is per-block, not per-tx.

**[HYPOTHESIS to measure]:** in a network of N validators, PoU throughput ≈ (single-node execution rate) × (number of independent execution lanes), while tier-2 validation stays roughly constant per validator. A PoW/PoS-style network's throughput ≈ (single-node execution rate), *independent of N*. The benchmark in §5 is designed to measure exactly this gap.

---

## 4. Uncapped vs Sui — an honest framing

**What the whitepaper claims for AEVOR:** *"no architectural ceiling on throughput — performance scales unboundedly with computational resources"* (line 33) and *"throughput that grows as network capacity grows rather than reaching arbitrary limits imposed by coordination bottlenecks"* (line 537).

**On Sui specifically — be careful and measure, don't assert.** Sui is *not* a low-throughput chain and is *not* "capped at 60 or 600" — it originated the object model and parallel execution, and reports six-figure TPS in its own benchmarks. The honest, defensible differences are architectural, not "we're fast, they're slow":

- **Trust model.** Sui secures results with **BFT consensus + all-validator execution** (Narwhal/Bullshark → Mysticeti). Every Sui validator still executes. AEVOR's PoU aims to make most validators *verify an attestation instead of re-executing* (§3) — that is the mechanism by which AEVOR intends to avoid the all-validators-re-execute bound.
- **Confidentiality scope.** Sui ships confidential *transfers* (range proofs on amounts, 2026). AEVOR targets confidential *computation* (TEE) plus ZK — broader in scope. Now that M20 gives AEVOR real Bulletproofs range proofs, the amount-hiding case is directly comparable and should be **measured head-to-head**, not asserted.
- **Cost we carry that they don't.** Hardware trust. PoU's speed comes from trusting TEEs; a TEE break is a sharper single-point failure than BFT's honest-majority assumption. AEVOR mitigates with 5-platform cross-attestation + slashing, but this is a real trade, not a free lunch.

**Recommendation:** the doc should never claim "faster than Sui" until we have a same-hardware, same-workload measurement of (a) confidential-transfer overhead (AEVOR TEE+range-proof vs Sui range-proof) and (b) the re-execution gap (§3.5). The *architecture* supports an uncapped story; the *numbers* must earn it.

---

## 5. How to measure TPS, and at what scales

### 5.1 What the current benchmark measures — and its blind spots
`node/tests/benchmarks.rs` measures **single-node, in-process, debug**: verify → conflict → VM → persist → Merkle, txs ÷ wall-time. That is a legitimate **execution-throughput floor** for one node. Its blind spots, each of which must be a *separate, labelled* number so we never conflate them:

- Excludes **network propagation** (gossip, the M19 `TcpTransport`).
- Excludes the **PoU multi-node advantage** (§3) — the whole point.
- Debug, not release.
- Excludes real **distributed finality** latency under load.

**Principle: never quote a single "AEVOR does X TPS."** Always quote *which* number: single-node execution (floor), networked throughput, or PoU-effective network throughput.

### 5.2 The scales to run (answering "3k / 10k / 50k validators, more transactions")
- **Transactions per block:** 1k, 5k, 10k, 25k, **100k, 500k, 1M** — to confirm the flatline holds into the whitepaper's target range (>200k sustained, >1M burst) and to find where memory/GC (not algorithm) becomes the limit.
- **Validators (finality + attestation verification):** 4, 16, 64, 128, **512, 3k, 10k, 50k**. Two things scale here:
  - **Finality-proof aggregation.** AEVOR uses BLS12-381; committee signatures *should* **aggregate to one signature** that is O(1) to verify regardless of committee size. **[CONFIRMED — this is currently a gap]:** the finality path (`NodeEngine::finalize_block` → `consensus.finalize_round`) today collects **N individual Ed25519 signatures** — `proof.signatures` is a `Vec` of length N, and `signature_count == N`. It does **not** aggregate. That is why the M16 curve grew ~linearly (0.13ms@4 → 4.3ms@128). **At 50k validators this O(N) collection is the binding constraint**, so **BLS12-381 aggregation (N sigs → 1 aggregate, O(1) verify) is a required change before 3k/10k/50k committees are meaningful.** The extended finality benchmark (now sweeping 4→3,000 validators) is set up precisely to show this linear growth and motivate the aggregation work — running it is the evidence, not an assertion.
  - **Attestation verification fan-out** — tier-2 cost per validator should be independent of N.
- **Security levels:** measure Minimal / Basic / Strong / Full separately (whitepaper §597: these are *observed timings on reference hardware, not ceilings*). The point is to show the progressive-security curve, not a single latency.
- **Batching:** measure per-tx vs per-batch attestation (§3.5) to quantify the batch-attestation win.

### 5.3 The one comparison that proves the thesis
Run the **same workload** two ways:
1. **Re-execute mode** (simulate PoW/PoS): every validator executes every tx.
2. **PoU mode:** producer executes + attests; verifiers verify attestation.

Plot committed-tx/sec vs validator count for both. **[HYPOTHESIS]:** curve (1) is flat in N (bounded by one node); curve (2) rises with N (more independent lanes). *That plot is the empirical case for PoU.* It belongs in the final benchmark report next to the Sui comparison.

---

### 5.4 MEASURED: BLS aggregate finality does **not** degrade as validators join

This is the decentralization claim, now implemented and measured. AEVOR's BLS aggregation (`aevor_crypto::bls`) is wired so that all validators sign the same block hash, the proposer aggregates the N signatures into one, and the committee caches its aggregate public key (`aggregate_public_keys`) — after which each finality proof is verified in **one pairing check** (`verify_with_aggregate_key`), independent of committee size.

Measured (M25, debug build, single machine), committee 128 → 50,000:

| validators | per-block **verify** (O(1)) | aggregate (O(N), per block) | precompute key (O(N), per membership change) |
|-----------:|----------------------------:|----------------------------:|---------------------------------------------:|
| 128 | 1,497 µs | 9.6 ms | 13.1 ms |
| 512 | 1,508 µs | 39.4 ms | 53.3 ms |
| 1,024 | 1,443 µs | 76.6 ms | 108.2 ms |
| 3,000 | 1,306 µs | 237.4 ms | 329.1 ms |
| 10,000 | 1,325 µs | 772.3 ms | 1,046 ms |
| **50,000** | **1,267 µs** | 4,033 ms | 5,195 ms |

**The verify column is flat at ~1.3 ms from 128 to 50,000 validators** — it does not grow (it is if anything slightly *faster* at 50k, within noise). That is the whole point: per-block finality verification is O(1) in committee size. Aggregation and key-precompute are O(N), but each is amortized — aggregation once per block (by the proposer), key precompute once per membership change (by everyone, cached).

**Why this is the Sui differentiator.** Sui intentionally caps its validator set at ~100 because its consensus requires frequent all-to-all validator messaging, whose cost grows with the set — so staying small is how it keeps sub-second finality. That is a real centralization pressure. AEVOR pays finality verification in **O(1)** via BLS aggregation, so **the validator set can grow into the tens of thousands without finality verification degrading** — decentralization without the finality-latency penalty. (Honest caveat: this measures *verification*; end-to-end finality in a live network also includes signature *gathering* over the wire, which is a networking concern, not a verification bound. The verification bound was the O(N) problem; it is now O(1).)

**Status vs the earlier finding.** §5.2 flagged that the *default* `finalize_block` path collects N Ed25519 signatures (O(N)). That is still the default path; what M25 adds is the **real, tested, O(1) BLS aggregate-verification primitive** and the measurement proving it scales. The remaining wiring — making `finalize_round` produce this BLS aggregate by default (validators signing with their BLS consensus keys, the `aggregate_signature` field carrying the real point instead of the BLAKE3 placeholder) — is the next code milestone; the mechanism it depends on is now proven.

## 6. The granular deployment model — yes, it is in the design

You asked whether the permissioned/permissionless + feeless/fee'd + privacy/non-privacy deployment story was accounted for. It is, in both the whitepaper and the code.

### 6.1 In code (`aevor-config/src/deployment`)
`DeploymentMode` already enumerates the spectrum:
- `PublicMainnet`, `PublicTestnet`, `PublicDevnet` — **permissionless public** networks.
- `EnterpriseSubnet` — **permissioned** subnet (organizational control).
- `Hybrid` — partially public, partially private.

with `DeploymentConfig { subnet: Option<SubnetDeploymentConfig>, hybrid: Option<HybridDeploymentConfig>, enterprise: Option<EnterpriseSubnetConfig> }`, and helpers `is_public()` / `is_production()`.

### 6.2 In the whitepaper
- *"permissionless public networks for maximum decentralization, permissioned enterprise subnets for organizational control, and hybrid deployments"* (line 75).
- **Feeless permissioned subnets are explicit:** *"Feeless Permissioned Subnet Economics and Resource Allocation Models"* (line 416). So a permissioned chain deployed on AEVOR can be **feeless** (resource-allocation economics instead of per-tx fees) *or* run with fees — it is a deployment choice, exactly as you described.

### 6.3 The two granular axes, and that they are independent
AEVOR's design lets a deployer pick, **independently**:
- **Permission axis:** permissionless public ↔ permissioned subnet ↔ hybrid.
- **Fee axis:** fee'd ↔ feeless (feeless is called out specifically for permissioned subnets).
- **Privacy axis (per object / per dApp):** the four object privacy levels (Public / Protected / Private / Confidential) mean a dApp can be fully public, fully confidential, or mixed — privacy is *granular at the object level*, not a whole-chain switch. TEE gives confidential *computation*; M20's range proofs give confidential *amounts*.

So "deploy a permissioned feeless chain on top of AEVOR" = `DeploymentMode::EnterpriseSubnet` + feeless subnet economics; "permissioned chain with fees" = the same with the fee model enabled; "privacy dApp vs non-privacy dApp" = object-level privacy settings — all already first-class in the model.

**[GAP to verify]:** confirm the *economics* code (`aevor-config/src/economics`, `aevor-core/src/economics`) actually exposes a feeless toggle wired to `EnterpriseSubnet`, and that the fee/feeless choice is enforced at the transaction-admission layer. The whitepaper specifies it; the code should be audited to confirm the switch is real end-to-end (candidate for a future milestone).

---

## 7. Summary of concrete next steps

| Step | Type | Payoff |
|------|------|--------|
| Release-mode benchmark run | measurement | the real ~10–30× headline number |
| Interior sparse Merkle tree | code | removes last O(n); flat proof/commit curves |
| Verify-by-attestation path + batch attestation | code | makes the PoU tier-2 advantage real |
| Re-execute-vs-PoU comparison plot | measurement | the empirical case for PoU (§5.3) |
| BLS finality aggregation | **primitive proven (M25); default-path wiring remains** | O(1) aggregate verify **measured flat at ~1.3 ms from 128→50k validators** — the no-degradation proof (§5.4); remaining: `finalize_round` produces the BLS aggregate by default |
| Higher-scale runs (1M txs, 50k validators, per-security-level) | measurement | confirms uncapped shape into target range |
| Same-hardware Sui confidential-transfer comparison | measurement | honest privacy-overhead number |
| Audit feeless-subnet economics end-to-end | code/review | confirms the deployment switch is real |

The through-line: **the M21 flatline proved the single-node cost is now constant per tx; the PoU fast path (§3) is what turns a constant single-node cost into uncapped network throughput — and the benchmark plan (§5) is designed to measure that, not assert it.**
