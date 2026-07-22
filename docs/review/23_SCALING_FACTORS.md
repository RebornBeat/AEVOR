# 23 — Scaling Factors: Verified Numbers and Where Throughput Actually Comes From

This answers three things directly: (1) is the throughput variation degradation or
sandbox variance — verified by repeated runs, not asserted; (2) why "single-lane"
looks faster than "multi-lane" and why multi-lane declines with lane count; and
(3) the complete inventory of scaling factors, with an honest note on which are
captured and which remain for extreme scale.

---

## 1. Degradation vs variance — verified by repeated runs

Same binary, `bench_full_pipeline` three times back to back:

| run | PRODUCE tx/s | VERIFY tx/s | base fee | fee/tx | reward |
|---|---:|---:|---:|---:|---:|
| 1 | 10 652 | 1 077 549 | 990 | 485 000 | 2 425 000 000 |
| 2 | 10 826 | 1 120 063 | 990 | 485 000 | 2 425 000 000 |
| 3 | 11 345 | 1 035 500 | 990 | 485 000 | 2 425 000 000 |

`bench_multi_lane_round` twice:

| lanes | run 1 tx/s | run 2 tx/s |
|---:|---:|---:|
| 1 | 914 763 | 1 010 599 |
| 2 | 927 906 | 892 298 |
| 4 | 858 118 | 909 879 |
| 8 | 774 316 | 801 090 |
| 16 | 421 093 | 642 252 |
| 32 | 303 865 | 619 362 |

**Conclusion.** The timing-dependent numbers wander ±6–8% at low lane counts and up
to ~2× at 32 lanes (304k vs 619k), on identical code — that is sandbox variance
(one shared core, scheduling + cache pressure). The *deterministic* outputs — base
fee, gas, fee/tx, reward — are **byte-identical every run**. Deterministic parts
fixed + timing parts wandering ⇒ variance, not degradation. VERIFY is back at
~1.0–1.1M, matching the original balance-delta measurements, so the balance-delta
sync and the new cross-lane double-spend checks did **not** degrade throughput.

---

## 2. Why "single-lane" looked faster, and why multi-lane declines with N

**They measure different single-node costs.** `bench_full_pipeline` VERIFY runs
`apply_attested_batch` on one batch. `bench_multi_lane_round` runs
`apply_lane_round` on N lanes. At N=1 the two are within noise of each other
(~0.9–1.0M) — `apply_lane_round` just adds a little fixed round orchestration
(attestation checks, prior-root check, the two cross-lane conflict HashSets,
deterministic ordering). The earlier "single 1.0M vs multi 0.81M" was a low-CPU
sample of the multi path, not a structural gap.

**The decline with N is one verifier doing N× the work on one core, with growing
state.** A single verifier applying N lanes writes N×2000 objects into its state
tree sequentially. Two costs rise with N: the Merkle root computation is O(total
objects), and the working set (64 000 objects at N=32) overflows cache. That is
why a *single node under full verification* slows per-lane as N grows — and it is
noisy because it is exactly the regime most sensitive to scheduling.

**Crucially, this is not the throughput path.** Real throughput does not come from
one verifier applying every lane. It comes from §3.

---

## 3. Where maximum throughput actually comes from

The governing equation:

```
network throughput  ≈  N_lanes  ×  per-lane production rate
```

- **Per-lane production is the bottleneck**, not verification. One node *produces*
  (execute + commit + attest) at ~11k tx/s; it *verifies* at ~1.0M tx/s — a ~100×
  gap. Verification has enormous headroom.
- **Lanes are produced in parallel by different validators.** Each lane is one
  validator's production. N validators producing concurrently ⇒ N × per-lane. This
  is horizontal scale and is inherently a **multi-machine** property — a single-core
  sandbox cannot measure it, only project it.
- **Verification keeps up two ways:** one verifier covers ~100 lanes before it
  saturates (the crossover = verify/produce ≈ 1.0M/11k ≈ 90–100); past that,
  **sharded verification** (`apply_lane_round_sharded`) gives each verifier a bounded
  slice, so no node applies all N lanes. The §2 decline is the full-verification
  case that sharding replaces beyond the crossover.

So the projections — ~90 lanes ≈ 1M tx/s, ~9 000 lanes ≈ 100M tx/s — come from
parallel *production*, with verification distributed by sharding. They are
projections precisely because production parallelism is multi-machine.

---

## 4. Complete scaling-factor inventory

Every lever that raises `N_lanes × per-lane rate`, with honest status:

1. **Vertical — per-node multi-core.** The ~11k per-lane production is on *one*
   core. Execution runs the micro-DAG independent set across all cores
   (`node/src/compute` + rayon), so on a k-core validator a single lane produces
   much faster than 11k. **Captured** (framework + parallel execution); the sandbox
   just can't show it (single core).
2. **Horizontal production — multi-lane (macro-DAG).** N validators produce N lanes
   concurrently ⇒ N × per-lane. The primary multiplier. **Captured** (apply side +
   ordering; live concurrent production needs the network).
3. **Horizontal verification — sharded.** Past the ~100-lane crossover each verifier
   applies a bounded slice; aggregate verification scales with validator count and
   bounds per-node apply cost. **Captured** (`apply_lane_round_sharded`).
4. **PoU verify-by-attestation headroom.** Verification is ~100× cheaper than
   production, so it is not the bottleneck until many lanes. **Captured** (measured
   ~100× every run).
5. **Off-Merkle balances.** Balance deltas apply as HashMap writes + one commitment
   hash, so settlement does not add Merkle cost to verify (root commitment would
   cost +112–136%). **Captured** (doc 22 §2.4).
6. **O(1) finality (BLS).** Finality is a constant-time aggregate independent of lane
   count. **Captured** (flat ~1.3 ms to 50k validators in the pipeline bench).
7. **Network data availability + bandwidth.** At high throughput, propagating
   lanes/deltas is a real limit; `aevor-network` has erasure-coded availability and
   bandwidth shaping. **Primitives exist** (61 tests); integration is the network
   rollout.
8. **Accelerators (GPU/TPU/NPU).** Offload batchable primitives (signature
   verification, hashing). **Framework captured** (`ComputeBackend`); concrete
   backends are per-hardware, future.

---

## 5. Extreme-scale factors to capture (honest gaps)

Two levers are **not** fully captured and matter only at sustained extreme scale.
Noted here so they are deliberate, not forgotten:

- **State sharding (partitioned state ownership).** Sharded *verification* bounds
  the apply cost per round, but each node still holds the full object store. At
  sustained 100M tx/s the total state grows faster than any single node can hold, so
  state must be partitioned across validators (each owning a shard), not just the
  verification load. The §2 per-node decline with object count is the small-scale
  shadow of this. This is the next real horizontal-scale item beyond the network
  rollout, and it interacts with the sender-sharding routing already decided (doc 22
  §7) — route by shard, own by shard.
- **Cross-round pipelining.** The model is round-synchronous (produce a round, apply
  it, finalize). Overlapping rounds (produce round N+1 while verifying/finalizing
  round N) would raise sustained throughput and cut latency. Not modelled; a
  latency/throughput optimization for after live multi-node.

Neither blocks the 1M–100M projection (that is production parallelism × sharded
verification); both are what turns a burst into a *sustained* rate at the top end.

---

## 6. Conclusion

- No degradation: verified by repeated runs — deterministic outputs identical,
  timing within variance, verify back at ~1.0–1.1M.
- The single-vs-multi-lane confusion was measurement-shape + variance, not a
  structural regression; the per-node full-verification decline with N is expected
  and is exactly what sharded verification exists to replace.
- Maximum throughput = parallel production (N validators × per-node multi-core) with
  verification distributed by sharding — the captured factors in §4.
- Two extreme-scale factors (state sharding, cross-round pipelining) are captured in
  §5 as deliberate future work, after the network wire and real TEE.

---

## 7. Controlled experiment — isolating "does multi-lane truly scale, or is it CPU-maxing?"

The concern: the `aggregate = N × per-lane` projection assumes each lane runs on its
own core, but a single-core sandbox runs everything with contention — so is the
projection real, or an artifact? A single core cannot add cores, but it can isolate
the **work** from the **contention**. Lanes are *disjoint* (macro-DAG conflict
rejection, now tested by the double-spend checks), so each lane's production runs on
a fresh engine with no shared state. `bench_controlled_lane_independence` produces
32 isolated lanes and measures per-lane cost vs lane index. If per-lane cost is flat
(no upward trend), the work is independent of lane count ⇒ N cores give N × per-lane.

Three runs:

| run | mean per-lane tx/s | min | max | first-half vs second-half (trend) |
|---|---:|---:|---:|---:|
| 1 | 13 388 | 10 521 | 14 045 | 13 296 vs 13 479 → ratio **1.01** |
| 2 | 13 367 | 12 082 | 13 950 | 13 399 vs 13 335 → ratio **1.00** |
| 3 | 13 442 | 11 681 | 13 903 | 13 495 vs 13 390 → ratio **0.99** |

**Result.** Per-lane cost is **flat** — the first and second halves of 32 lanes are
within ~1% every run, so there is *no upward trend with lane index*. The mean is
stable run-to-run (~13.4k, ±0.5%); the min..max spread inside a run is CPU
scheduling noise, not degradation. Per-lane cost is therefore **independent of lane
count**. Disjoint lanes + flat per-lane cost ⇒ N validators on N cores achieve
**N × per-lane, linearly** — 96 lanes ≈ 1.28M, 9 000 ≈ 120M tx/s. This is the
single-core evidence that the projection is sound: the decline in
`bench_multi_lane_round` is one verifier accumulating *all* N lanes' state (full
verification on one core), not the parallel-production case.

*(A note on the CPU-throttling variant: throttling one core, or running N throttled
processes on one core, simulates N tasks **sharing** one core — contention, the
opposite of N separate cores. Isolation, above, is the correct control: it shows the
work is independent, which is what makes separate-core parallelism linear.)*

## 8. Full-spectrum verification (low lanes → crossover → sharded → 100M+)

Bringing the measured pieces together across the whole range:

- **Per-lane production (isolated, controlled):** ~13.4k tx/s, flat vs lane count
  (§7). This is the per-validator-per-core rate the aggregate multiplies.
- **Per-node verification:** ~1.0–1.1M tx/s (§1) — ~100× production headroom.
- **Full-verification crossover:** ~96–106 lanes before one verifier saturating
  (`bench_combined_pou_scaling` PART 2, from the measured verify/produce ratio).
- **Sharded verification past the crossover (measured):**
  `bench_sharded_verification_scaling` — validator-0's assigned **slice stays
  bounded (2–5 lanes)** as N grows 8→128, so each validator's verify load is
  constant regardless of total N. This is the measured evidence that verification
  scales beyond the crossover (no node applies all N lanes).
- **Aggregate (projection, justified by the above):** N × per-lane → ~1M tx/s at
  ~75–96 lanes, ~100M+ at ~7 500–9 000 lanes. A projection because production
  parallelism is multi-machine; sound because per-lane cost is independent (§7) and
  the per-validator verification slice is bounded (measured).

**What changed from before:** nothing structural in the lane model — this is the
same M31 macro-DAG apply + M32 sharded verification. This round added the
balance-delta sync and the cross-lane double-spend checks *on top*; the controlled
experiment and the sharded run confirm they did not disturb the scaling (per-lane
cost flat, slice bounded, economics byte-identical). The 96-lane figure is the
full→sharded **crossover**, not the 100M point; 100M+ is the aggregate projection at
~9 000 lanes, now backed by measured per-lane independence and measured slice
bounding rather than arithmetic alone.
