# AEVOR Benchmarks — Proof-of-Uncorruption Execution + Finality Path

Harness: `node/tests/benchmarks.rs` (run with
`cargo test -p node --test benchmarks --release -- --ignored --nocapture`).

## What is measured — and what is NOT

The harness measures the **single-node, in-process pipeline**: signature
verification → DAG conflict rejection → VM bytecode execution → durable
log-structured persistence → authenticated Merkle commitment → finality-proof
aggregation over a committee.

It does **not** measure:
- Network propagation across a live, geographically distributed validator set.
- Parallel execution across cores (the current `ComposedExecutor` processes the
  batch sequentially; the micro-DAG parallelism described in the whitepaper is a
  design target not yet exercised by this harness).
- Real TEE attestation round-trips (hardware-gated; B3).

So these numbers are **one node's local pipeline throughput** — a useful floor
and regression tracker, not deployed end-to-end latency, and not directly
comparable to a live network's wall-clock TPS.

## Captured baseline (UNOPTIMIZED / dev build)

> ⚠️ These were captured in a **debug build** (release build was not run in this
> pass). Debug is typically **10–30× slower** than release for crypto/tree-heavy
> code. Treat these as a functional floor, not representative performance.
> Re-run with `--release` to capture real numbers.

Execution throughput (verify → conflict check → execute → persist → commit):

| Batch (disjoint txs) | Time (debug) | Throughput (debug) |
|---------------------:|-------------:|-------------------:|
| 1,000                | 74 ms        | ~13,400 tx/s       |
| 5,000                | 488 ms       | ~10,200 tx/s       |
| 10,000               | 1,407 ms     | ~7,100 tx/s        |
| 25,000               | 6,581 ms     | ~3,800 tx/s        |

Finality-proof aggregation (attestation collection + proof, one block):

| Committee | Time (debug) |
|----------:|-------------:|
| 4         | 0.12 ms      |
| 16        | 0.46 ms      |
| 64        | 1.89 ms      |
| 128       | 3.82 ms      |

Authenticated-state Merkle proof generation:

| State size | Time / proof (debug) |
|-----------:|---------------------:|
| 1,000      | 0.64 ms              |
| 10,000     | 7.07 ms              |
| 25,000     | 20.4 ms              |

## Reading the results (honest gap analysis)

Two things stand out, and both point at real, expected work rather than
surprises:

1. **Throughput falls as the batch grows** (13.4k → 3.8k tx/s from 1k → 25k).
   Cause: execution is **sequential**, and each commit re-roots a Merkle tree
   that grows with state. This is precisely the workload the whitepaper's
   **micro-DAG parallel execution** is designed to absorb — it is not yet wired
   into the `ComposedExecutor`, so the benchmark is measuring the pre-parallel
   path.
2. **Proof time grows with state size.** Expected for a tree that is rebuilt
   per block in this implementation; an incremental/persistent tree would flatten
   this. Tracked as a storage optimization.

The whitepaper's target is **>200,000 tx/s sustained** on reference server
hardware with parallel execution. The gap between that and the debug single-node
numbers above is attributable to: (a) debug vs release, (b) sequential vs
parallel execution, (c) per-block Merkle rebuild. The benchmark's value is
making that gap **explicit and measurable** so the optimization work (parallel
executor, incremental tree, release tuning) can be tracked against it.

## Cross-chain comparison framework (fill from `--release` runs)

⚠️ Cross-chain TPS comparisons are **inherently apples-to-oranges**: chains
differ in what a "transaction" is, whether numbers are lab-peak or live-network,
single-node vs whole-network, and with/without full consensus + finality. Use
this table only with those caveats stated inline. Published third-party figures
below are approximate and should be re-verified before external use.

| Chain    | Published *peak* (lab)     | Typical *live* network | Finality model |
|----------|----------------------------|------------------------|----------------|
| AEVOR    | >200k sustained (target)   | *(capture on testnet)* | Deterministic / PoU attestation; ~20 ms–1 s by security level |
| Sui      | ~297k (historically cited) | ~hundreds–low thousands | BFT (Mysticeti); confidential *transfers* via range proofs (2026) |
| Aptos    | ~160k (Block-STM claim)    | ~hundreds–low thousands | BFT |
| Solana   | ~65k (theoretical)         | ~1k–3k typical          | PoH + Tower BFT (probabilistic) |
| Ethereum | ~15–30 (L1)                | ~15–30                  | Finality in ~2 epochs |

Method note for a fair AEVOR entry: capture (1) release-mode single-node
throughput from this harness, and (2) a **testnet** number that includes network
propagation and real committee finality. Only (2) is comparable to other chains'
"live network" column; (1) is comparable to other chains' single-node execution
benchmarks (e.g. Block-STM microbenchmarks), not to their live TPS.

## Next steps
- Run the harness under `--release` and replace the debug tables above.
- Add a throughput benchmark once parallel execution lands, to measure scaling
  across cores.
- Add an incremental-Merkle variant to flatten proof/commit cost, then re-measure.
- Capture a testnet end-to-end number (network + finality) for the only
  cross-chain-comparable figure.

---

## Milestone 21 — Performance milestone: before / after (debug, single-node, in-process)

The performance milestone wired the micro-DAG's independent set into parallel execution, replaced the O(n²) conflict scan with O(n) set-based detection, and made the Merkle tree incremental (cached leaf hashes + cached root). Debug build; release adds the usual 10–30×.

### Execution throughput (verify → DAG conflict check → VM execute → persist → Merkle commit)

| Batch | Before (M16) | After (M21) | Change |
|------:|-------------:|------------:|:------:|
|  1,000 txs | 13,400 tx/s | 14,070 tx/s | ~flat |
|  5,000 txs | — | 11,461 tx/s | — |
| 10,000 txs | — | 14,260 tx/s | — |
| 25,000 txs | **3,800 tx/s** | **14,436 tx/s** | **~3.8×** |

The headline is the **shape**: before, throughput collapsed as the batch grew (13.4k → 3.8k) because conflict detection was O(n²) and the Merkle tree rebuilt every block. After, throughput is **flat with batch size** — the algorithmic fixes removed the superlinear term.

### Merkle inclusion-proof generation

| State size | Before (M16) | After (M21) |
|-----------:|-------------:|------------:|
|  1,000 objects | 0.64 ms | 0.16 ms |
| 10,000 objects | — | 1.58 ms |
| 25,000 objects | ~20 ms | 5.14 ms (~4×) |

### Finality-proof aggregation (unchanged, already fast)

| Validators | Latency |
|-----------:|--------:|
|   4 | 0.13 ms |
|  16 | 0.49 ms |
|  64 | 1.94 ms |
| 128 | 4.27 ms |

### Honest remaining work before the *true* headline benchmark
- **Release build** (10–30×) — the numbers above are debug.
- **Interior Merkle** — leaf hashing is now incremental, but the interior rebuild is still O(n) on change; a full sparse Merkle tree gives O(log n) interior updates.
- **Networked (multi-node) throughput** — these are single-node, in-process; they exclude gossip/propagation and are not directly comparable to another chain's live TPS.
- **PoU cost + AEVOR-vs-Sui privacy overhead** — now measurable on real range proofs (M20); to be captured once the above land.
