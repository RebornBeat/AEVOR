# AEVOR — Benchmark Review & Throughput Maximization (consolidated)

One place that dwells on everything measured, sets single-node against multi-lane, and names what is still missing to *fully* maximize. All numbers are debug/single-core unless noted; release multiplies absolutes, the shapes and ratios are the point.

---

## 1. The whole benchmark picture, in one table

| dimension | measurement | what it means |
|-----------|-------------|---------------|
| Re-execute (per node) | ~11.5–14k tx/s, flat 1k→100k | a node's raw execution rate; flat = O(1)/tx |
| **Produce (execute+commit+attest)** | **~10.3k tx/s @5k** | **the real per-lane production rate (the bottleneck)** |
| Verify-by-attestation | ~0.97–1.14M tx/s @1–10k | a verifier reproduces state without re-executing; ~95× a producer |
| PoU speedup | 48–96× | verify-attest vs re-execute |
| Verify-attest sweet spot | ~1k–10k batch | past ~15k the O(n) apply + cache erode it (472k @50k) |
| BLS finality | O(1), ~1.3 ms flat 128→50k validators | decentralization without a finality penalty |
| Signature scheme (produce) | Ed25519 13k / ML-DSA 2k / mixed 3.2k tx/s | PQ is 6.2× on the producer only |
| Signature wire size | 380 B / 5,545 B / 5,641 B | PQ is 14.6× bandwidth on the producer only |
| Sparse Merkle | prove/verify flat ~30/37 µs 1k→100k | O(depth); for proofs, not batch apply |
| Sorted vs sparse (in engine) | sorted 100–300× on batch apply; sparse 3–15× on proofs | per-role backend choice |
| Multi-lane apply (per verifier) | 625k–1.1M tx/s (N lanes) | same curve as single-lane by *total* tx |
| Sharded verification | validator slice ~constant as N 8→128 | bounded per-validator load → uncapped aggregate |
| **Network aggregate** | **N × ~10.3k** | ~1M @96 lanes, ~5.3M @512, ~103M @10,000 |

---

## 2. Single node vs multi-lane — the honest distinction

**A single node has a hard per-node ceiling.** It executes at ~10–14k tx/s and verifies at ~1M tx/s. No wiring changes that — it is one machine's pipeline. The verify-attest sweet spot (~5–10k batch) is where a single node is most efficient, and bigger batches only make it worse.

**Multi-lane does NOT raise the single-node number.** This was the crucial thing the side-by-side showed: a verifier applying 64k tx across 32 lanes (~625k tx/s) sits on the *same* degradation curve as a 50k single batch (~578k tx/s). F-A1 did not make a node faster.

**What multi-lane changes is the *network*.** The macro-DAG lets N validators each produce a lane concurrently, on their own hardware, and everyone orders them deterministically (leaderless) and applies the disjoint results. So aggregate = N × per-lane. The validator set stops being N copies re-doing one node's work (PoW/PoS) and becomes N lanes of *additional* throughput. That is the entire point of the design, and it is now wired (F-A1) with bounded per-validator load (F-A2).

So: **single-node = fixed ceiling; multi-lane = linear scaling in validators.** They answer different questions — one is "how fast is a node," the other is "how fast is the network," and only the second is uncapped.

---

## 3. The key learning: the bottleneck is PRODUCTION, not verification or finality

The final pipeline benchmark makes this unambiguous. At the sweet-spot batch, one lane's lifecycle is:

- **PRODUCE (execute + commit + attest): ~10.3k tx/s** — the bottleneck.
- **VERIFY (attest + apply): ~973k tx/s — ~95× faster.** Wildly over-provisioned.
- **FINALIZE (BLS): O(1), ~1.3 ms** — flat regardless of validator count.

This reframes everything. The network's throughput is bounded by how fast lanes *produce*, not by verification or finality — those have ~95× and effectively unbounded headroom. A single verifier only saturates at ~95 lanes (then sharded verification, F-A2, removes even that). **So to maximize throughput you attack production, and you add lanes. Nothing else is close to the critical path.**

A secondary finding: producing is slightly *slower* than plain re-execute (10.3k vs 12.4k) — the attestation seal + delta materialization add ~15–20% to a lane. That is the price of the PoU fast path, and it is cheap relative to the ~95× it buys every verifier.

---

## 4. How to fully maximize throughput (the recipe, evidence-based)

1. **Raise per-lane production with multi-core execution.** Production is the bottleneck and it parallelizes (independent transactions execute concurrently). On real hardware, per-lane production scales roughly with cores, so aggregate = N lanes × (per-lane × cores). The compute abstraction (M32) auto-sizes the pool to the host's cores; this is the single biggest per-lane lever.
2. **Add lanes.** Aggregate is linear in lane count. This is a validator-set property, not a batch-size one.
3. **Batch each lane at the ~5–10k sweet spot** — not bigger (the O(n) apply + cache erode past ~15k for no gain).
4. **Use sharded verification past ~95 lanes** (F-A2) to keep per-validator load bounded → uncapped aggregate.
5. **Keep the sorted Merkle backend on executing validators** (100–300× the batch-apply rate of sparse); sparse only on proof-serving nodes.
6. **Let PQ be opt-in per lane** — its 6.2× compute + 14.6× bandwidth stay on the opting-in producer; verifiers pay nothing.
7. **Pick security level by latency, not throughput** — finality is O(1) in validator count.

Net maximized picture: **N lanes × (per-lane production × cores)**, verification and finality never gating, uncapped under sharded verification. ~1M at ~96 lanes → ~5.3M at 512 → ~103M at 10,000 (debug per-lane; multiply by release + cores).

---

## 5. What is still missing to *fully* maximize (honest gaps)

1. **Multi-core production scaling is unmeasured** — the single biggest per-lane lever. This box is one core (`nproc`=1), so we can only *wire* the scaling (compute abstraction, done) and reason about it; the actual per-lane-vs-cores curve needs multi-core hardware. This is the top unmeasured item because production is the bottleneck.
2. **~~The compute backend is not wired into the producer's signature-verification path.~~ DONE — producer signature verification is now parallelized across cores.** `verify_execute_commit` (the shared producer/re-execute core) verifies signatures on the global work-stealing pool (sized to the host by `compute`), order-preserving so conflict-rejection winners are unchanged (17 e2e still green). On one core this is equivalent; on many cores it scales the *bottleneck* (production) with the hardware — the highest-value throughput change, now wired. Its benefit is only *measurable* on multi-core hardware.
3. **The network aggregate is projected, not observed.** Per-lane and per-verifier rates are measured; N × per-lane is a projection because parallel *production* is a multi-machine property. A live multi-node run is the measurement still owed (and genuinely needs multiple machines).
4. **The sweet spot was found single-core.** With multi-core production the optimal per-lane batch may shift; worth re-measuring on real hardware.

None of these are correctness gaps — the pipeline is wired, correct, and tested end-to-end (multi-lane ordering, sharded coverage, PoU tamper rejection, O(1) finality). They are *measurement* and *one concrete optimization* (item 2) that a single-core sandbox cannot fully exercise.

---

## 6. Bottom line

The architecture is doing exactly what it claims: a fixed, well-understood single-node pipeline (production-bound at ~10k tx/s, verification ~95× over-provisioned, finality O(1)), multiplied by an uncapped number of concurrent lanes with bounded per-validator verification. The throughput levers are now identified and **wired**: **more lanes** (F-A1/F-A2) and **faster per-lane production via multi-core** (compute abstraction sizes the pool to the host; producer signature verification now runs on that pool, order-preserving). The 1M / 6M+ / 100M+ targets are reproduced by the projection from measured per-lane production. What remains for a truly maximized, *measured* result is real multi-core/multi-node hardware to exercise the now-wired parallelism — not missing code.
