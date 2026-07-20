# AEVOR — Remediation Changelog

Tracks changes to the codebase as production-readiness remediation proceeds. This scaffold is seeded with the review baseline; append an entry under **Unreleased** each time a register (`01`) item is swapped in or an alignment (`02`) edit is applied, then move it into a dated/version section when a milestone ships.

Format: [Keep a Changelog](https://keepachangelog.com/) style. Reference register IDs (B1–B12) and alignment IDs (§3.1–§3.3) so every change is traceable to the review.

---

## [Unreleased]

### Milestone 29 — Combined throughput study: the pieces measured together + the dual-DAG scaling model (2026-07-18) ✅ DONE
Not six isolated matrices — the interaction, to find the *true* throughput and how it scales as validators expand.
- **NEW `bench_combined_pou_scaling`** measures, together: (Part 1) a fine batch-size sweet-spot sweep for both execution modes; (Part 2) the dual-DAG network model — per-lane execute rate and per-verifier attest rate measured, then aggregate throughput as concurrent macro-DAG lanes (validators) expand, in both the full-verification and sharded-verification regimes.
- **NEW `docs/review/15_COMBINED_THROUGHPUT_AND_DUAL_DAG_SCALING.md`** — the analysis tying it together.
- **Key measured findings:** re-execute is flat (~11.5–12.1k tx/s) at every batch size; **verify-attest has a real sweet spot at ~1k–10k (~1.0–1.1M tx/s)** and degrades past 15k (472k at 50k). The **dual-DAG turns per-lane numbers into network throughput**: aggregate = N lanes × per-lane, measured per-verifier ceiling ~1.12M tx/s ⇒ **full-verification caps at ~96 lanes**, while **sharded verification scales linearly with N (uncapped)** — 512 lanes ≈ 6M tx/s, 3,000 ≈ 35M, and it stays secure because every lane is still attestation-verified by a quorum with O(1) BLS finality across all N.
- **Interaction insights:** PQ cost is **contained to producing lanes** (verifiers don't re-check tx signatures under PoU), so PQ-opt-in is cheap network-wide; **security level sets confirmation latency, not throughput** (finality is O(1) in validator count).
- **Honest correction (caught while dwelling on the numbers):** the sparse Merkle tree does **NOT** fix the verify-path large-batch knee — applying n deltas through a 256-deep tree is ~16–24× *more* work than the sorted-leaf tree's single O(n) rebuild. Sparse Merkle wins for single-key updates and proofs, not batch application. The real throughput lever is **more lanes at the sweet-spot batch size**, not a different tree.
- **Honesty on scope:** per-lane and per-verifier rates are measured on real code; the aggregate N-lane figure is *modelled from those measured components* (the node doesn't yet run N producers in one process). A live multi-node run is the next measurement.

### Milestone 28 — Real sparse Merkle tree (O(depth) interior updates + proofs) (2026-07-18) ✅ DONE
The last pure-software O(n) gap: `SparseMerkleTree` is now a genuine sparse Merkle tree, not a flat-hash placeholder.
- **Real 256-deep sparse Merkle tree** keyed by `BLAKE3(key)`: insert / update / remove / prove / verify are all **O(depth) — constant in the number of keys**. Empty subtrees use precomputed default hashes, so storage is sparse (only occupied paths). Membership proofs are direction-aware (the path is implied by the key hash) with a matching O(depth) verifier.
- **Tested:** insert→prove→verify round-trip (wrong value rejected, absent key has no proof), update changes root+proof, remove reverts the root, and **order-independent roots** (same key-set ⇒ same root regardless of insert order). 4 new tests, aevor-crypto now 87 lib tests.
- **Measured (`bench_sparse_merkle_scaling`):** prove and verify are **flat at ~30 µs / ~37 µs from 1k to 100k keys** — O(depth), independent of tree size. The sorted-leaf `MerkleProver` is O(n) per proof (milliseconds at 100k); this is the O(log n) structure for incremental and proof-heavy workloads.
- **Honest scope:** the engine's state tree remains the sorted-leaf `MerkleProver`, which is O(n) to rebuild but **optimal for a single large batch commit** (the flat ~14k tx/s). The sparse Merkle tree is the better structure for single-key updates and proof-heavy paths; making it the engine's default state tree is a *deliberate tradeoff* (batch commit O(n·log n) vs O(n)) and a separate wiring decision, not a strict win — so it is delivered real, tested, and benchmarked, ready to wire where the workload favors it.
- **Verified:** full workspace builds; lib clippy **0**; benchmark compiles and runs.

### Milestone 27 — PoU verify-by-attestation fast path + BLS finality wired into the default path + PQ throughput (2026-07-18) ✅ DONE
The Proof-of-Uncorruption speed thesis, implemented and measured — plus the BLS aggregate now live in the default finality path.
- **PoU verify-by-attestation fast path (NEW, `node::engine`):** `produce_attested_batch` (the producing validator executes once in its TEE and emits an `ExecutionAttestation` over the state transition + the state delta) and `apply_attested_batch` (a verifying validator checks the attestation and applies the delta — **no VM execution, no per-tx signature re-check**). Round-trip tested (verifier reproduces the producer's exact state root; corrupted delta and forged attestation both rejected). **Measured: 48–93× faster than re-executing** (~479k–879k tx/s verify-attest vs ~9.4k–10k tx/s re-execute across 1k–50k-tx batches). This is "valid until proven corrupted," implemented — the lever that turns a flat single-node number into uncapped *network* throughput. (Simulation attestation today; real hardware swaps in behind the same interface.)
- **BLS aggregate finality wired into the DEFAULT path:** `CommitteeMember` now carries a BLS consensus key; `finalize_block` aggregates every validator's BLS signature into one and **verifies it in O(1)** against the committee's aggregate public key. `FinalityOutcome` reports `bls_verified` + the real aggregate; the e2e finality tests assert `bls_verified`. The no-degradation-as-validators-join property (measured flat to 50k in M25) is now *live* by default, not just demonstrated.
- **DRY refactor:** the execution core is now a single `verify_execute_commit` helper shared by `process_block` and `produce_attested_batch` — one execution codepath.
- **PQ vs non-PQ vs mixed THROUGHPUT (NEW benchmark):** all-Ed25519 **13,014 tx/s**, all-ML-DSA-65 **2,086 tx/s** (~6.2× slower to verify), mixed 50/50 **3,207 tx/s**. Combined with M26's 14.6× wire bloat, the full quantified case that PQ is opt-in.
- **Attestation model corrected in docs:** each validator normally runs one TEE device and carries one attestation; the five platforms are supported *options*, not a fused multi-attestation; a wallet may run multiple devices but each is a separate validation.
- **Verified:** full workspace builds; **14 e2e tests pass** (incl. the PoU round-trip and the `bls_verified` asserts); lib clippy **0**; all new benchmarks compile and run.

### Milestone 26 — PQ wire-bloat measurement + honest mainnet readiness assessment (2026-07-18) ✅ DONE
Real numbers for the post-quantum bandwidth cost, and a truthful "are we ready?" verdict instead of a rubber stamp.
- **NEW benchmark `bench_signature_wire_size`** — measured transaction wire size by scheme (identical payload): **Ed25519 380 B → ML-DSA-65 5,545 B (14.6×) → Hybrid 5,641 B**. PQ signatures add ~5,165 B/tx — ~493 MB of extra signature data per 100k-tx block. Quantifies why the right posture is crypto-agility (classical default, PQ/hybrid opt-in), which the code already supports.
- **NEW `docs/review/14_BENCHMARKS_AND_READINESS.md`** — consolidates all real measured numbers (execution flat ~14k tx/s to 100k; BLS finality O(1) ~1.3 ms to 50k validators; PQ wire bloat) **and** a component-by-component readiness verdict. **Honest bottom line: devnet-ready; testnet-ready except for real TEE validators; NOT beta-mainnet-ready.** The #1 blocker is that **TEE attestation is simulation on all five platforms** (`is_production: false`) — real hardware attestation is not integrated. Also enumerated: default finality still uses the BLAKE3 placeholder (BLS primitive proven but not wired as default), Groth16/Halo2 ZK still stubbed (Bulletproofs are real), interior sparse Merkle still a flat-hash placeholder, feeless-subnet economics unverified end-to-end.
- **NEW `docs/mainnet/00_MAINNET_DOCUMENTATION_INDEX.md`** — the ~210-doc mainnet documentation plan (10 parts, prioritized P0/P1/P2), so the "200+ docs" effort is a roadmap, not ad hoc.
- **Accuracy fix:** removed a stale "Dilithium stub" comment in `post_quantum/mod.rs` — the hybrid PQ component is real ML-DSA-65 (confirmed by the 5,641 B measurement).
- **Verified:** full workspace builds; lib clippy 0; benchmark compiles and runs.

### Milestone 25 — BLS aggregate finality verification: the no-degradation-as-validators-join proof (2026-07-18) ✅ DONE
The decentralization differentiator, implemented and measured. Finality verification is now O(1) in committee size.
- **`aevor_crypto::bls` gains the O(1) verification path:** `aggregate_public_keys(&[BlsPublicKey])` lets a committee precompute its aggregate public key once, and `BlsAggregateSignature::verify_with_aggregate_key(message, &key)` then verifies any finality proof in **a single pairing check — constant time regardless of validator count**. Plus `BlsKeyPair::from_ikm` for deterministic committee keys. Round-trip unit-tested (valid aggregate accepted; wrong message / wrong committee rejected).
- **Measured (`bench_bls_finality_scaling`, debug), committee 128 → 50,000:** per-block verification is **flat at ~1.3 ms** (1,497 µs @128 → 1,267 µs @50,000 — no growth). Aggregation and key-precompute are O(N) but amortized (once per block / once per membership change). This is the "no degradation as more validators join" property, measured.
- **Why it matters:** Sui caps its validator set at ~100 because its all-to-all consensus messaging degrades as the set grows. AEVOR pays finality *verification* in O(1) via BLS aggregation, so the validator set can grow into the tens of thousands without finality verification degrading — decentralization without the finality penalty. (Honest scope: this is the *verification* bound, which was the O(N) problem; wire-gathering of signatures is a separate networking concern.)
- **Status:** the O(1) BLS primitive is real, tested, and measured. The remaining wiring — making the default `finalize_round` emit this BLS aggregate (validators signing with BLS consensus keys; `aggregate_signature` carrying the real point instead of today's BLAKE3 placeholder) — is the next code milestone; its mechanism is now proven. Documented in `12_PERFORMANCE_AND_POU_SCALING.md` §5.4.
- **Verified:** aevor-crypto 83 tests pass; full workspace builds; lib clippy **0**; benchmark compiles and runs.

### Milestone 24 — Performance analysis, PoU fast-path design, higher-scale benchmark (2026-07-18) ✅ DONE
Study of the flatline + the uncapped/PoU scaling story, with the benchmark extended to the scales that test it.
- **New design doc `docs/review/12_PERFORMANCE_AND_POU_SCALING.md`** answering: (1) why throughput flatlined and why that is the correct "scales-with-volume" shape; (2) how to go higher (release ~10–30×, interior sparse Merkle, parallel scaling, and the PoU fast path); (3) **the PoU fast path** — grounded in the whitepaper's real-time corruption detection (§823+) and line 719 — where validators *verify a batch attestation instead of re-executing every transaction*, i.e. "valid until proven corrupted," which is the actual source of uncapped throughput; (4) an honest Sui framing (don't claim "faster" without same-hardware measurement); (5) TPS measurement methodology and its blind spots; (6) a higher-scale benchmark plan (1k→1M txs, 4→50k validators, per-security-level, plus the re-execute-vs-PoU comparison that empirically proves the thesis); (7) the granular deployment model — permissionless/permissioned/hybrid × fee'd/**feeless** × object-level privacy — confirmed present in both `aevor-config/src/deployment` (`DeploymentMode`) and the whitepaper (feeless permissioned subnets, line 416).
- **Execution benchmark extended to 100k txs** and **measured flat**: 14,635 → 13,906 tx/s across 1k→100k (a 100× batch increase with no per-tx degradation) — the uncapped-execution shape, measured, not asserted.
- **Finality benchmark extended to 3,000 validators** and the misleading "BLS-style" comment corrected. **Confirmed honest finding:** the finality path collects **N individual Ed25519 signatures** (O(N)), it does *not* aggregate — so **BLS12-381 aggregation (N→1, O(1) verify) is a required change before 3k/10k/50k committees are meaningful.** The extended sweep is set up to show this linear growth empirically.
- **Scope:** analysis + benchmark (test) + docs; no production-code behavior change. Full workspace builds; lib clippy 0; benchmark compiles and the execution sweep runs.

### Milestone 23 — Production recursive DNS resolver (hickory-resolver) (2026-07-18) ✅ DONE
The last register seam. Recursive resolution is now real production code, not a stub.
- **`RecursiveResolver` now uses the audited `hickory-resolver` crate** for real recursive DNS resolution over UDP/TCP against the configured upstreams, with **DNSSEC validation** enabled when configured (hickory rejects responses whose signatures don't validate for signed zones). The previous `resolve()` returned an empty record set; it now returns real A/AAAA records.
- **Together with M19's real DNSSEC signing/verification**, both halves of the name-service security story are now real: signed-record validation *and* recursive resolution.
- **Sandbox-honest testing:** resolver construction is offline and unit-tested; the two live-lookup tests are marked `#[ignore]` (they need a live network) and run with `cargo test -p aevor-ns -- --ignored` for validation against real DNS outside the sandbox — exactly the "finalize here, validate live" arrangement.
- **Verified:** aevor-ns builds clean, 48 offline tests pass (2 live tests ignored); full workspace builds; production (lib) clippy: **0 warnings**.

### Milestone 22 — Client `NodeConnection` socket seam (both transports now real) (2026-07-18) ✅ DONE
The last transport seam. The client can now talk to a node over a real socket, not just in-process.
- **`TcpNodeConnection` (client side, `aevor-client::transport`)** implements the *same* `NodeConnection` trait as the in-process `EngineConnection`, so `Client` code is byte-for-byte identical whether the node is in-process or across a network. It speaks a request/response protocol (`NodeRequest`/`NodeResponse`) over length-prefixed **bincode** frames.
- **`NodeServer` (node side, `node::server`)** listens on TCP and serves those requests against a shared `Arc<Mutex<NodeEngine>>`, running the exact same engine logic (`submit` → mempool; `prove_object` → inclusion proof) the in-process connection runs. The lock is released before the response is written, so a submit doesn't block a subsequent block production.
- **End-to-end over a real socket:** a new e2e test has the client build+sign a transaction, submit it **over a loopback TCP socket**, the node produce a block, and the client **query the object back over the socket and verify its Merkle proof** before trusting the data — the full user path, remote.
- **Both transport seams are now real:** gossip (`TcpTransport`, M19) and client (`TcpNodeConnection`, M22). Only the in-process implementations existed before; now remote and in-process are interchangeable behind the same traits.
- **Verified:** all **13** end-to-end tests pass (12 prior + the socket round-trip); full workspace builds clean; production (lib) clippy: **0 warnings**.

### Milestone 21 — Performance: parallel execution + O(n) conflict detection + incremental Merkle (2026-07-18) ✅ DONE
The performance milestone from the canonical design review. The benchmark's superlinear slowdown is **gone** — throughput is now flat with batch size — and the win is *measured*, not asserted.
- **Parallel execution (micro-DAG wired into the executor).** The executor ran the accepted transactions sequentially. It now runs in three passes: (1) sequential, deterministic **conflict rejection** → the independent set; (2) that independent set's VM programs **execute in parallel** (rayon) — they have disjoint read/write sets by construction, so execution is order-independent and the result is deterministic; (3) sequential, in-order **apply** (persist writes / record failures). This is the micro-DAG's independent set actually running in parallel.
- **O(n) conflict detection (was O(n²)).** The pairwise scan (each tx vs every prior accepted tx) is replaced by two `HashSet`s (accepted writes / reads); a tx conflicts iff any of its writes hits an accepted write/read or any of its reads hits an accepted write — the *exact* `ConflictDetector` relation, aggregated. This was the main source of the superlinear slowdown on large batches.
- **Incremental Merkle.** `MerkleProver` now (a) keeps a **precomputed leaf hash per key** so a rebuild never re-hashes unchanged values (O(1) amortized per write vs O(n) per root), and (b) **caches the root**, invalidated on mutation, so the several `root()`/`prove()` calls the engine makes per block don't each rebuild the tree.
- **Measured impact (debug build, single-node, in-process):**
  - Execution throughput: **flat ~14k tx/s across 1k→25k txs** (was 13.4k → **3.8k**, degrading). At 25k that's a **~3.8× improvement**, and the superlinear shape is eliminated.
  - Merkle proof generation at 25k objects: **~20 ms → ~5.1 ms** (~4×), from the cached leaf hashes.
  - Finality-proof aggregation unchanged and still fast (0.13 ms at 4 validators → 4.3 ms at 128).
  - **Determinism preserved:** all 12 end-to-end tests pass (conflict rejection, two-node convergence, multi-block, etc.).
- **Honest scope:** still a debug build — release would add the usual 10–30×. Leaf hashing is now incremental, but the *interior* tree rebuild is still O(n) on change; a full sparse Merkle tree for O(log n) interior updates is the next Merkle step (the existing `SparseMerkleTree` is currently a flat-hash placeholder). Parallel execution helps the VM constant factor; the flat *shape* comes from the O(n) conflict fix + cached Merkle.
- **Verified:** `cargo test --workspace` → **0 failures** (1,645+ tests across all crates). Production (lib) clippy: **0 warnings**.

### Milestone 20 — B1: real Bulletproofs range proofs (confidential amounts complete) (2026-07-18) ✅ DONE
The ZK privacy primitive is now real end-to-end — this is what makes the privacy comparison with Sui *measurable on real proofs* rather than asserted.
- **Real range proofs.** `aevor-zk::bulletproofs` now uses the audited `bulletproofs` crate (v5.0.0) to produce and verify **real zero-knowledge range proofs** that a committed amount is in `[0, 2^64)` without revealing it. Verified it resolves to the **same** `curve25519-dalek` v4.1.3 the rest of the stack already uses — no second curve library.
- **Coherent confidential-amount stack.** Commitments use the Bulletproofs Pedersen generators, so a commitment and its range proof match; a homomorphic **balance check** (`Σ inputs − Σ outputs == excess·B_blinding`) runs on those same commitments — hidden amounts, proven non-negative, with supply integrity checked without revealing any value. Tests cover honest-verifies, tampered-commitment-rejected, tampered-proof-rejected, and balanced-vs-unbalanced transactions.
- **DRY consolidation.** Removed M19's stepping-stone amount commitment from `aevor-crypto` (it used a *different* H generator, so it could never be range-proved under Bulletproofs' generators — a footgun). The confidential-amount commitment now lives in exactly one place, coherent with its range proof; `aevor-crypto` keeps only the general-data `commit_bytes` its commitment module needs.
- **Heavy dependency isolated.** Bulletproofs is pulled only by `aevor-zk` and its three dependents (`node`, `aevor-governance`, `aevor-bridge`) — not the whole workspace, so core crates stay light.
- **Verified:** `cargo test --workspace` → **1,645 passed, 0 failed**. Production (lib) clippy: **0 warnings**.

### Milestone 19 — B9 (DNSSEC), real socket transport, B1 (Pedersen commitments) (2026-07-18) ✅ DONE
Three register items in one pass. Two subsystems made real, one made cryptographically real at its commitment layer.
- **B9 — DNSSEC verification was a validation bypass** (`DnssecVerifier::verify` returned `true` for everything). It now performs **real Ed25519 verification** (DNSSEC algorithm 15 / RFC 8080): the signer produces genuine RRSIGs, the verifier checks them, and a signature over different data is **rejected** (new test). The recursive/upstream DNS path is genuinely network I/O (needs a vetted resolver crate + live network) and remains a documented seam; the security-critical validation is now real.
- **Real socket transport.** Added `TcpTransport`, a real `std::net` TCP implementation of the same `MessageTransport` trait the node already uses — length-prefixed, dependency-free wire framing, background accept loop. New integration test sends a `NetworkMessage` **across a real loopback TCP socket** and drains it on the other side. Node logic is unchanged whether it runs over the in-process bus or a real socket.
- **B1 (partial) — real Pedersen commitments.** Added a real elliptic-curve Pedersen commitment (`C = value·G + blinding·H` over Ristretto via curve25519-dalek) — the confidential-amount primitive Sui's confidential transfers also build on. It is **binding**, **hiding**, and **homomorphic** (`C(a)+C(b)=C(a+b)`), with a real **confidential-balance check** (`Σ inputs − Σ outputs == excess·H` proves supply integrity without revealing any amount). Verified by 6 tests including balanced-vs-unbalanced transactions.
  - **DRY consolidation:** the crate already had a *hash-based* (fake) `PedersenCommitment` in the commitment module — misnamed and redundant with `HashCommitment`. Its commitment math now **delegates to the one real EC primitive**, so there is a single source of commitment logic. The remaining ZK piece — a full **Bulletproofs range proof** (proving a committed amount is in `[0, 2^n)`, which stops inflation via "negative" values) — needs the vetted `bulletproofs` crate and is called out as a focused follow-on.
- **Verified:** `cargo test --workspace` → **1,642 passed, 0 failed** (+7). Production (lib) clippy: **0 warnings**.

### Milestone 18 — B11: real client attestation verification (shared evidence primitive) (2026-07-18) ✅ DONE
Completes the light-client trust story: a client can now **cryptographically verify** that a validator's execution attestation is genuine, not just that a field is non-empty.
- **Client (`aevor-client`):** `AttestationVerifier::verify` was a structural stub (`!raw_report.is_empty()`). It now verifies the attestation **evidence seal** (a real signature over the canonical body) plus a non-zero execution input — the *same* check a validator performs.
- **Shared evidence primitive promoted to `aevor-crypto::attestation`:** `canonical_evidence_body` / `seal_evidence` / `verify_evidence` now live once in aevor-crypto, and **both** `aevor-consensus` and `aevor-client` delegate to them. (This also removed the brief per-crate copy from M17 — the client dep on aevor-crypto, not aevor-consensus, made aevor-crypto the correct shared home.) One key, one canonical body, one verify — across the TEE layer, the consensus layer, and the client.
- **Light-client trust now has both legs:** Merkle proof verification (state inclusion) *and* attestation verification (execution correctness), both real and both sharing their crypto with the full node.
- **Verified:** `cargo test --workspace` → **1,635 passed, 0 failed**. Production (lib) clippy: **0 warnings**.
- **Disk note (answering the sandbox question):** the sandbox pressure is the `target/` build cache (~5 GB), *not* the milestone archives (~16 MB total, and on a separate effectively-unlimited filesystem). Each milestone archive captures the **full workspace** (verified: 635 files / all 284 `.rs` / all 23 crates, `target/` excluded) — the latest is always complete and self-contained.

### Milestone 17 — B3: real TEE attestation verification (sealed reports, shared primitive) (2026-07-18) ✅ DONE
Turns attestation from a structural stub into **real cryptographic verification** at both the TEE and consensus layers, without introducing a fork — the two layers share one signing key and one sign/verify implementation.
- **TEE layer (`aevor-tee`):** attestation reports are now **sealed** — signed over a canonical body (platform, code + signer measurements, nonce, `is_production`, svn, user_data). `AttestationVerifier::verify` was `!raw_report.is_empty()`; it now checks the **signature** plus a non-degenerate code measurement. All five platform backends (SGX/SEV/TrustZone/Keystone/Nitro) seal the reports they generate.
- **Shared primitive (`aevor-crypto::attestation`):** the simulation attestation trust-root key and `sim_sign`/`sim_verify` live **once** in aevor-crypto. Both the TEE layer and the consensus layer build their own (type-specific) canonical body and call the shared primitive — one key, one signature scheme, no drift.
- **Consensus layer (`aevor-consensus`):** `AttestationVerifier::verify` for `AttestationEvidence` was also a structural stub; it now verifies the sealed evidence via the shared primitive. Validators submit sealed evidence; `verify_with_policy` still layers the production-vs-simulation acceptance policy on top (that separation is unchanged).
- **Honest trust model:** the simulation key is a well-known stand-in for a hardware vendor's attestation root — it carries **no real hardware trust**; it lets simulation builds exercise the *real* verification path. Production hardware cert-chain verification (Intel DCAP / AMD SNP / Nitro document) is the documented feature-gated extension; the production-vs-simulation *acceptance* decision stays at the consensus layer.
- **Tampering is now caught:** new tests prove a report/evidence with a mutated measurement, mutated nonce, garbage quote, or zero measurement is **rejected** — exactly what the old stub let through.
- **Verified:** `cargo test --workspace` → **1,635 passed, 0 failed** (+6). Production (lib) clippy: **0 warnings**.

### Milestone 16 — PoU/E2E benchmark harness + TEE/privacy design review + Sui comparison (2026-07-18) ✅ DONE
Adds a benchmark harness for the Proof-of-Uncorruption path, and two review docs grounding the TEE/privacy design against the papers and against Sui's 2026 privacy work.
- **Benchmark harness (`node/tests/benchmarks.rs`, `#[ignore]`-d):** measures the single-node in-process pipeline — execution throughput (verify → DAG conflict check → VM → persist → Merkle commit), finality-proof aggregation latency over committees (4/16/64/128), and Merkle proof generation. Reuses the production transaction builders (no logic duplication). Run with `cargo test -p node --test benchmarks --release -- --ignored --nocapture`.
- **Honest baseline captured (debug build):** ~13.4k tx/s at 1k txs falling to ~3.8k at 25k (sequential execution + per-block Merkle rebuild); finality 0.12 ms (4) → 3.82 ms (128); proofs 0.64 ms → 20 ms. Documented with the gap analysis vs the whitepaper's >200k target (debug vs release, sequential vs parallel execution, per-block tree rebuild).
- **`docs/review/10_BENCHMARKS.md`:** methodology, what-is-and-isn't-measured, the captured numbers, and a cross-chain comparison *framework* (with heavy apples-to-oranges caveats) for AEVOR/Sui/Aptos/Solana/Ethereum.
- **`docs/review/11_TEE_PRIVACY_AND_SUI_COMPARISON.md`:** confirms the **5 TEE platforms** (Intel SGX, AMD SEV, ARM TrustZone, RISC-V Keystone, AWS Nitro); clarifies **who uses TEE** (validators provide + attest for PoU; dApps consume via TEE-as-a-Service; users benefit); summarizes the **object-level Mixed Privacy** model (TEE+ZK hybrid, architecturally enforced); and gives an **evenhanded Sui comparison** — AEVOR's design is broader in scope (confidential computation, not just transfer amounts) with a different (TEE+ZK) trust model, but less mature than Sui's shipped range-proof transfers; no evidence of copying in either direction.
- No production code changed; workspace remains **1,629 tests, 0 failures**, lib clippy **0**.

### Milestone 15 — Transaction-type convergence: one canonical transaction (2026-07-18) ✅ DONE
Resolves the last type fork (raised in review): there is now **one** transaction type across the whole workspace. Done now, deliberately, while the fork was still small — before more code could build on either side.
- **`aevor_core::transaction::SignedTransaction` is the single canonical type**, and it is now **agility-aware**: `sender_public_key` is a `MultiPublicKey` and `signature` is a `MultiSignature`, so any wallet scheme (Ed25519, ML-DSA-65, Hybrid) signs the *same* rich transaction (which carries nonce, gas, chain_id, inputs/outputs, privacy level, …).
- **The minimal agility `SignedTransaction` (formerly in `aevor_client::exec`) is gone.** Everything — node engine, client, `aevor-execution` — uses the one core type.
- **Signing/verifying live once in `aevor-crypto`:** `sign_transaction` (stamps the wallet key, signs `Transaction::signing_bytes`) and `verify_transaction` (dispatches through `verify_multi`). `Transaction::signing_bytes` (in aevor-core) now covers `chain_id` and `nonce`, so the signature binds **replay/cross-chain protection** — a security improvement over the old minimal bytes.
- **The node engine consumes the canonical transaction:** it verifies via `verify_transaction`, derives the DAG read/write set from the body (`declared_read_set`/`declared_write_set`, keyed by the transaction hash), and runs the *same* proven ComposedExecutor pipeline. `Transaction::new_simple(...)` keeps construction concise so tests and the client didn't balloon.
- **Behavior-preserving:** `cargo test --workspace` → **1,629 passed, 0 failed** (all 12 e2e flows — Ed25519, ML-DSA, Hybrid, tamper-rejection, client, node modes — green through the new path). Production (lib) clippy: **0 warnings**.
- **Net effect:** one type, richer than either predecessor, agility-aware, with replay protection, executing through the unchanged pipeline — and no remaining drift surface.

### Milestone 14 — Node modes drive the engine (one engine, three policies) (2026-07-18) ✅ DONE
Turns the `FullNode`/`ValidatorNode`/`LightNode` skeletons (flag-flippers) into real, engine-backed roles — and does so *without* introducing parallel types: all three compose the **same** `NodeEngine` and differ only in policy. That is itself a single-source-of-truth win (one execution engine, three thin policy layers).
- **`FullNode::produce_block(engine)`** — executes transactions and produces blocks (full state); refuses to produce before `start()`. A full node does *not* finalize on its own.
- **`ValidatorNode::produce_and_finalize(engine, committee)`** — does everything a full node does *plus* collects committee attestations into a finality proof; refuses unless `Active`.
- **`LightNode::verify_object(proof, trusted_root)`** — the light client's defining behavior: verifies an inclusion proof against a trusted root using the canonical `MerkleProof::verify`, with **no engine and no full state**. Rejects a proof rooted anywhere other than the trusted root.
- **End-to-end harness grown to 12 tests:** `node_modes_apply_distinct_policies` exercises all three policies against real engines (full node produces; validator produces + finalizes over a 3-member committee; light node accepts a valid proof and rejects one rooted elsewhere), plus the negative guards (unstarted full node, inactive validator).
- **Verified:** `cargo test --workspace` → **1,629 passed, 0 failed**. Production (lib) clippy: **0 warnings**.

### Milestone 13 — Eliminate duplication: canonical hashing, single source of truth (2026-07-18) ✅ DONE
Addresses a real maintainability risk (raised in review): logic duplicated across crates can drift, so a change to one copy silently breaks the other. Fixed the genuine cases.
- **Merkle hashing unified (the real drift risk):** the prover (`aevor-storage`) had its own `leaf_hash`/`node_hash`, and `MerkleProof::verify` (`aevor-core`) had a second inline copy of the same domain-separated hashing. Both now call **canonical `aevor_core::storage::merkle_leaf_hash` / `merkle_node_hash`** — one definition, so generation and verification update together and *cannot* drift. (This is exactly the class of bug that produced the earlier verification stub.)
- **BLAKE3 hasher canonicalized:** `Blake3Hasher`/`Blake3Hash` now live once in **`aevor_core::hash`** (the base crate every crate can reach — `aevor-core` itself could not import the old wrapper from `aevor-crypto` without a cycle, which is why the split existed). `aevor-crypto` now **re-exports** them, so all existing `aevor_crypto::hash::{Blake3Hasher, Blake3Hash}` imports (10+ crates) keep working while pointing at the single definition.
- **Verified:** `cargo test --workspace` → **1,628 passed, 0 failed** (behavior-preserving refactor). Production (lib) clippy: **0 warnings**.
- **Honest note on the transaction types:** the agility-aware `SignedTransaction` is now single-definition (in `aevor_client::exec`, re-exported by the node). A *separate* legacy `aevor_core::transaction::SignedTransaction` (Ed25519-only, richer body: nonce/gas/inputs/outputs) is still used by the execution pipeline. Unifying them is a larger, tracked item — it means upgrading the core `Transaction` to be agility-aware (MultiSignature/MultiPublicKey) and migrating the pipeline, which ripples through consensus/storage/execution. It is a *type* fork (confusion), not a silent-drift risk like the hashing was, so it is deferred deliberately rather than rushed.

### Milestone 12 — Client submission/query path + real Merkle proof verification (2026-07-18) ✅ DONE
Completes the user-facing loop (**client builds/signs/submits → node → client queries and verifies**) and fixes a real verification stub found while wiring it.
- **Reconciled the transaction type:** there were two — `aevor_core::transaction::SignedTransaction` (Ed25519-only, predates agility) and the node engine's agility-aware one. The agility-aware transaction now lives in **`aevor_client::exec`** (shared client↔node vocabulary; carries a scheme-tagged `MultiSignature`/`MultiPublicKey`, so Ed25519/ML-DSA/Hybrid wallets can all submit) and the node re-exports it.
- **`aevor_client::exec` (new):** `SignedTransaction` (+ `build` from any `Signer`), a `NodeConnection` trait (`submit_transaction` / `query_object`), and a `Client` that builds+signs+submits and **verifies the Merkle proof on every queried object before trusting the data**. `NodeConnection` is the seam a real transport (HTTP/gRPC/QUIC) implements. The node ships `EngineConnection`, an in-process implementation over `NodeEngine`.
- **Fixed a real stub — `aevor_core::MerkleProof::verify`:** it was a *structural* check (`!siblings.is_empty() && len ≤ 256`) that even rejected valid single-entry proofs. It now does **real cryptographic inclusion verification** (commutative, domain-separated BLAKE3), byte-identical to the prover, and `aevor-storage`'s `MerkleProver::verify` delegates to it — one canonical verification shared by prover and client.
- **End-to-end harness grown to 11 tests:** `client_submits_and_queries_verified_state` — a client submits a transaction over a connection, the node produces a block, and the client queries the object back and verifies its proof (a non-existent object returns `None`).
- **Verified:** `cargo test --workspace` → **1,628 passed, 0 failed**. Production (lib) clippy: **0 warnings**.
- **Remaining (B10):** the real socket transport (HTTP/gRPC/QUIC) behind the `NodeConnection` seam; transaction status/finality polling wired to the connection.

### Milestone 11 — Account continuity + key migration across the classical→PQ transition (2026-07-18) ✅ DONE
Answers a concrete user question: create a key as *either* type, switch *without a new wallet*, and keep a non-PQ wallet safe when quantum arrives. Both PQ and non-PQ signing were already proven working end-to-end (M9); this adds the **account/identity migration layer** on top.
- **Real hybrid key pair (completes the B2 hybrid follow-up):** `HybridKeyPair` now composes **real Ed25519 + real ML-DSA-65** (the BLAKE3 stub PQ half is gone). `sign`/`verify` require **both** components. Wired into agility: `Signer` impl + `verify_multi` dispatch for `HybridEd25519MlDsa65` (packs Ed25519 64 B ‖ ML-DSA 3309 B signature, 32 B ‖ 1952 B public key). Proven that a hybrid signature with a valid Ed25519 half but broken ML-DSA half is **rejected** — i.e. safe when Ed25519 falls.
- **`aevor-crypto::account` (new) — the migration layer:**
  - `AccountId` is a **stable identity independent of the controlling key** (AEVOR's `Address` is a raw 32-byte id, not a key hash, which makes this possible). Assets/identity bind to the `AccountId`, so rotating keys never changes who you are.
  - **Create as any scheme** — Ed25519, ML-DSA-65, or Hybrid (`AccountKeyRecord::open`).
  - **Switch without a new wallet** — `rotate` changes the controlling key, authorized by the *current* key; `AccountId` and assets are preserved. Unauthorized rotation is rejected.
  - **Quantum-safe migration pre-commitment** — commit `hash(future_pq_key)` while the classical key is still secure (`set_pq_commitment`), then later reveal the PQ key to take control (`activate_pq_migration`) **even if the classical key has since been broken** — the commitment is the authorization and is preimage-resistant, so a quantum attacker who broke Ed25519 still cannot forge it. Wrong-key reveal and unauthorized commitment are both rejected.
- **End-to-end harness grown to 10 tests:** `hybrid_wallet_transacts_end_to_end` — a hybrid wallet transacts through the node (Ed25519, ML-DSA, and Hybrid wallets now all proven through the full pipeline).
- **New unit tests:** 6 account/migration tests + hybrid dual-guarantee test + real-hybrid round-trip.
- **Verified:** `cargo test --workspace` → **1,627 passed, 0 failed**. Production (lib) clippy: **0 warnings**.

### Milestone 10 — Networking transport + mempool + multi-node propagation (2026-07-18) ✅ DONE
Closes the biggest remaining *connection* gap: nodes can now propagate transactions and converge across a network — proven, not assumed.
- **`aevor-network::gossip` (new) — real message transport, honest seam:** a `MessageTransport` trait (`broadcast` / `drain_inbound`) plus an in-process `LocalNetwork` bus that connects multiple nodes via shared queues and moves **wire-serialized** `NetworkMessage`s between them. This exercises the real gossip/propagation and convergence logic; a socket-backed transport (QUIC/TCP) implements the same trait for production, and the node logic never depends on the concrete transport. +2 tests.
- **Node mempool:** `NodeEngine` gains a mempool with `submit` (verifies the signature up front — the single admission path for both local and peer-received transactions), `pending_count`, and `produce_block` (drains the mempool and runs the full pipeline). `SignedTransaction` is now `serde`-serializable so it crosses the transport.
- **End-to-end harness grown to 9 tests:** `transaction_propagates_across_nodes_and_they_converge` — a transaction submitted to node A is **serialized, broadcast over the transport, received and deserialized by node B**, admitted to its mempool, and both nodes (building blocks independently) **converge to an identical state root and block hash**. Mempool + gossip + deterministic execution proven together.
- **Verified:** `cargo test --workspace` → **1,619 passed, 0 failed**. Production (lib) clippy: **0 warnings**.
- **Remaining networking:** the real socket transport behind the `MessageTransport` seam, block (not just tx) propagation wired to erasure coding, peer discovery, and the `FullNode`/`ValidatorNode`/`LightNode` mode variants driving the engine + transport.

### Milestone 9 — Real post-quantum signatures (B2): ML-DSA-65 behind the agility trait (2026-07-18) ✅ DONE
Applied the **same overhead/performance analysis used for the storage decision** to the crypto primitive — and it lands on the opposite conclusion, for the same underlying reason.
- **Decision:** real ML-DSA via the vetted **pure-Rust `fips204`** crate, *not* from scratch. From-scratch won for storage because the workload matched Bitcask and the alternative was a heavyweight C++ engine; for ML-DSA a pure-Rust expert implementation exists (so the C++-avoidance motive is absent), from-scratch would be **slower** (NTT/rejection-sampling are expert-tuned), and the real "overhead" for crypto is the **silent side-channel risk surface** of hand-rolled lattice code. Consistent with AEVOR already using `ed25519-dalek` and `blst`; the property AEVOR owns is agility, not the primitive internals.
- **`aevor-crypto::post_quantum::ml_dsa` (new):** `MlDsa65KeyPair` (generate/sign/public-key-bytes) + `verify`, via `fips204` (FIPS 204, ML-DSA-65 / NIST category 3, pure Rust). Sizes: PK 1952 B, SK 4032 B, SIG 3309 B.
- **Agility wiring:** `verify_multi` now dispatches `SignatureSchemeId::MlDsa65` to real verification (Valid/Invalid), and `MlDsa65KeyPair` implements the `Signer` trait — so anything signing through agility can use PQ transparently.
- **End-to-end harness grown to 8 tests:** `post_quantum_wallet_transacts_end_to_end` — an ML-DSA-65 wallet signs a transaction the node verifies and processes; a tampered PQ tx is dropped. The tx-builder is now generic over any `Signer` (Ed25519 or ML-DSA).
- **New unit tests:** ML-DSA round-trip / tamper / wrong-key / malformed-input (`aevor-crypto`), plus a real ML-DSA-through-agility test; the "unsupported vs invalid" test now targets SLH-DSA (still unimplemented) to preserve that distinction.
- **Dependency:** `fips204 = "0.4.6"` added (pure Rust; pulls `sha3`, `zeroize` — all pure Rust).
- **Verified:** `cargo test --workspace` → **1,616 passed, 0 failed**. Production (lib) clippy: **0 warnings**.

### Milestone 8 — Real state reconstruction, multi-node determinism, B7 erasure coding (2026-07-18) ✅ DONE
Continues the "prove it connects" thread and closes the durability gap flagged in Milestone 7 — no stubs on these paths.
- **Authenticated state reconstruction on startup (durability made real):** added `StorageBackend::scan` (implemented for `LogBackend` and `MemoryBackend`), `ObjectStore::all_records`, and `ComposedExecutor::committed_objects`. `NodeEngine::open` now **rebuilds the Merkle state tree from durable storage**, so the state root — not just the value store — survives a restart. This capability also serves validator state-sync.
- **B7 — real Reed-Solomon erasure coding** (`aevor-network`, pure Rust, no dependency): GF(256) arithmetic (`0x11D`), systematic Vandermonde-derived coding matrix, Gauss-Jordan field inversion. `data+parity` shards where **any `data_shards` reconstruct** — recovers up to `parity_shards` losses. Replaces the chunk/concat stub; API is now position-indexed reconstruction.
- **End-to-end harness grown (7 real-environment tests):**
  - `state_reconstructs_from_durable_log_on_restart` — object survives restart, stays provable, and the **reconstructed state root matches** the pre-restart root.
  - `two_independent_nodes_converge_to_identical_state` — two independent nodes given the same block compute **byte-identical state roots and block hashes** (the canonical determinism property underpinning consensus).
  - (replaces the weaker "reopens and continues" placeholder test from M7.)
- **New unit tests:** erasure coding recovery/failure/systematic/field-axiom tests (`aevor-network`).
- **Verified:** `cargo test --workspace` → **1,609 passed, 0 failed**. Production (lib) clippy: **0 warnings**.

### Milestone 7 — Real node engine + progressive end-to-end integration test (2026-07-18) ✅ DONE
Addresses the gap that everything prior was *isolated unit tests*: this milestone wires a **runnable node** and proves the subsystems actually connect via a real-environment test — not stubs, not demos-in-name-only.
- **`node::engine::NodeEngine` (new)** — instantiates and runs the real subsystems, replacing the flag-flipping skeleton for the actual work path. It opens **durable `LogBackend` storage**, composes the executor (`ComposedExecutor::with_backend` — new; wires the real backend, addressing a B5 follow-up), maintains an **authenticated Merkle state tree**, and finalizes over a validator committee. `process_block` runs the full path: signature verify → DAG conflict rejection → VM execution → durable persist → Merkle commitment; `finalize_block` produces a real finality proof. Node unused deps ~20 → 15 (now wires consensus/core/crypto/dag/execution/storage).
- **`ComposedExecutor`**: added `with_backend` constructor and `written_object_ids` on `ProgramOutcome` so the node can commit executed writes into the state tree.
- **`node/tests/end_to_end.rs` (new) — the progressive integration harness.** 6 real-environment tests, no isolation:
  - `full_pipeline_wallet_to_finality`: create wallet (keypair) → sign txs → verify → conflict-check → VM execute → durable persist → Merkle commit → **inclusion proof verifies** → **finalize over a 3-validator committee (real finality proof)**.
  - `bad_signature_is_dropped_before_execution`, `conflicting_transactions_are_rejected`, `failed_program_rejects_and_commits_no_state` (no partial commit), `node_reopens_on_durable_log_and_continues`, `multi_block_height_advances_and_root_evolves`.
- **Verified:** `cargo test --workspace` → **1,606 passed, 0 failed** (incl. the 6 end-to-end). Production (lib) clippy: **0 warnings**.
- **Honest scope note:** full Merkle-state reconstruction from the durable log on startup is a tracked follow-up (the value store is durable; the in-memory commitment tree currently rebuilds from replayed blocks). Networking/API/governance subsystems are not yet wired into the engine (remaining unused node deps).

### Milestone 6 — Crypto agility + B5 (pure-Rust durable storage + real Merkle) (2026-07-18) ✅ DONE
Two decisions were made explicitly (not by inertia): **RocksDB is out** (C++ dependency, contrary to AEVOR's from-scratch/pure-Rust posture — the `RocksDbBackend` was only a no-op placeholder from the original tree), and the signature layer is **widened via an additive tagged envelope**, not by changing the core `Signature` type.

- **Crypto agility layer (new):**
  - `aevor-core::crypto`: `SignatureSchemeId` (Ed25519, BLS, ML-DSA-44/65/87, FN-DSA-512, SLH-DSA-128s, FAEST-128s, Hybrid) + variable-length tagged `MultiSignature` / `MultiPublicKey` envelopes. One wire type for all schemes; adding a scheme is additive.
  - `aevor-crypto::agility`: `Signer` trait + `verify_multi` dispatch. Ed25519 fully implemented; post-quantum schemes are *recognized* and return `MultiVerify::Unsupported` (distinct from `Invalid`) until their backends land. +5 tests.
  - This makes non-PQ↔PQ and PQ↔PQ switching a data change, not a code migration; B2 becomes "implement real ML-DSA behind the trait."
- **B5 storage — DONE, pure Rust, no C/C++:**
  - `aevor-storage::backend::LogBackend` — a from-scratch log-structured (Bitcask-family) durable store chosen for AEVOR's exact access pattern (hashed keys, point lookups, write-heavy, atomic batch commit): sequential-append writes (no write amplification), in-memory offset index with lock-free positioned reads (values on disk), WAL crash recovery via per-batch commit markers + CRC-32, atomic `commit_batch`, and background `compact`. Replaces the no-op `RocksDbBackend`. +5 tests (crud, durability-across-reopen, atomic batch, torn-tail recovery, compaction).
  - `aevor-storage::merkle::MerkleProver` — a **real binary Merkle tree** with genuine inclusion proofs and verification (domain-separated commutative BLAKE3 hashing; odd nodes carried up, avoiding duplication malleability). Replaces the `siblings = vec![ZERO]` stub. +4 tests (real proof verifies, tampered value fails, stale-root fails, single-entry).
- **Verified:** `cargo test --workspace` → **1,600 passed, 0 failed**. Workspace clippy: **0 warnings**.
- See new `09_CRYPTO_AGILITY_AND_PQC.md` for the selection rationale and the BLS-finality post-quantum gap.

### Milestone 5 — Alignment re-applications + B6 + B8 + VM-executing pipeline (2026-07-18) ✅ DONE
No deferral: each follow-up handled in-pass. Canonical designs upheld throughout.
- **Alignment §3.1/§3.2/§3.3 DONE** (the three edits lost to the sandbox reset, now permanently re-applied):
  - `aevor-core`: `CONFIRMATION_MS_*_MAX` → `TYPICAL_CONFIRMATION_MS_*` (+ ordering assertions) — now consistent with `aevor-consensus`.
  - `aevor-storage`: `MAX_BATCH_SIZE` → `DEFAULT_BATCH_SIZE` (per-node tuning, not a ceiling).
  - `aevor-security`: `AUDIT_LOG_MAX_ENTRIES` doc clarified (rotation threshold, not a throughput ceiling; name kept).
- **B6 DONE** — `aevor-dag`: replaced the identity "topological order" with a real **Kahn's algorithm** over directional (acyclic) dependency edges, and added `parallel_execution_levels()` computing execution **waves** (independent txs run concurrently — AEVOR's parallel model). +5 tests.
- **Bytecode codec (B13 follow-up) DONE** — `aevor-vm`: `BytecodeCodec::encode/decode` between `Vec<u8>` and the instruction stream (compact opcode format; rejects unknown opcodes / truncated operands). +4 tests.
- **Pipeline↔VM wiring (B13 follow-up) DONE** — `aevor-execution`: `ComposedExecutor::process_program_batch` now **executes each accepted transaction's bytecode on the VM** before persisting; a failed execution (out of gas, abort, div-by-zero) **rejects the transaction and commits no state** (canonical: verified result or rejection, never a partial commit). Wires `aevor-vm` into execution (execution unused deps 3 → 2). +5 tests.
- **B8 DONE** — `aevor-metrics`: real Laplace(0, scale) noise via inverse-CDF transform + seeded `SplitMix64` (no new dependency; deterministic per seed for verifiability). +4 tests incl. a zero-mean statistical check.
- **Verified:** `cargo test --workspace` → **1,588 passed, 0 failed**. Workspace clippy: **0 warnings**.

### Milestone 4 — Consensus↔crypto (B4) + real VM interpreter (B13) (2026-07-18) ✅ DONE
Continued integration, adhering to canonical designs (BLAKE3 hashing, BLS-aggregation target for finality, deterministic cross-platform VM).
- **B4 DONE** — `aevor-consensus`: `ProposalMessage::content_hash` now real BLAKE3; `finalize_round` builds a real populated `FinalityProof` (signatures, participant bitmap, signed weight, security level) with a BLAKE3 commitment binding all signatures. Wires `aevor-crypto`. Consensus unused deps 2 → 1. +3 tests. (Follow-up: `aggregate_signature` → true BLS point aggregate once validators sign attestations with BLS.)
- **B13 DONE** — `aevor-vm`: new deterministic `Interpreter` executing the full instruction set with real gas metering, stack/memory/TEE tracking, and guaranteed termination; `AevorVm::execute` added. +18 tests. (Follow-up: bytecode decoder + wire into the tx pipeline.)
- **Verified:** `cargo test --workspace` → **1,573 passed, 0 failed**. Workspace clippy: **0 warnings**.

### Milestone 3 — Cleanup + first integration edge (2026-07-18) ✅ DONE
**Phase A — cleanup (spotless base):**
- Clippy: auto-fixed the mechanical lints + 4 manual fixes (RFC7748 hex clamp in crypto; merged identical slashing match arms; `#[allow(struct_field_names)]` on `ConsensusClock`; added `# Errors` doc to `Faucet::new`). **Workspace clippy: 0 warnings.**
- Resolved the `ApiError` name collision: renamed the wire-body **struct** `types::ApiError` → `ApiErrorResponse` (updated `rest` + prelude); the crate error **enum** `ApiError` is unchanged.

**Phase B — first real integration edge:**
- New module `aevor-execution/src/composed/mod.rs` — a `ComposedExecutor` that genuinely wires **`aevor-dag`** (real `ConflictDetector`/`PreExecutionBatch` pre-execution rejection), **`aevor-crypto`** (real BLAKE3 content hashing), and **`aevor-storage`** (real `ObjectStore` + `MemoryBackend` persistence) into the core write path: *txs → DAG conflict rejection → persist accepted writes → record rejections*. Backend-agnostic (swap `MemoryBackend` → RocksDB once B5 lands).
- 6 integration tests (disjoint-accept, write-write reject, read-write conflict, read-read safe, cross-batch version increment, real-BLAKE3 content hash) — all pass.
- **`aevor-execution` unused deps: 6 → 3** (dag/crypto/storage now wired; consensus/tee/vm remain).
- **New finding → register B13:** the VM (`aevor-vm`) has **no bytecode interpreter** (no `execute`/`run`); it models bytecode/gas/instructions but doesn't execute. Added to `01_STUB_AND_SIMULATION_REGISTER.md`.
- **Verified:** `cargo test --workspace` → **1,552 passed, 0 failed**. Clippy: 0 warnings.

### Milestone 2 — Whitepaper alignment & integration audit (2026-07-18) ✅ DONE (docs only, no code change)
Full tool-driven audit — see `08_WHITEPAPER_ALIGNMENT_AND_INTEGRATION_AUDIT.md`.
- **Whitepaper coverage: COMPLETE** — 108/110 committed identifiers exist in code; the 2 misses are a citation (`SplitStream`) and an example module (`PrivateAuction`). All S-series alignment types verified present.
- **Redundancy: near-clean** — no duplicate `mod tests` remain; one duplicate type *name* (`ApiError` struct vs enum in aevor-api) flagged to rename.
- **Cleanliness: clean** — release build warning-free; ~14 trivial clippy lints catalogued (auto-fixable).
- **Utilization gap identified** — 10 orphaned public types (notably `AccountState`, `GraphQlServer`, `HandshakeMessage`, `CrossContractExecution`, `ValidatorAdmission`); and the headline finding: implementation crates are largely **islands** (dag/vm/storage/execution/network/zk used by no other crate), `aevor-execution` imports only `aevor-core`, and `node` is a lifecycle skeleton (20 unused declared deps). Runtime/service integration is the largest remaining gap and the structural root of B4/B5/B10/B11.
- **`03_PRODUCTION_READINESS_CHECKLIST.md` updated** — integration layer added as the top-priority mainnet gate (§0), above individual swap-ins.
- Code unchanged from Milestone 1 (source files byte-identical; only `docs/review/` updated).

### Milestone 1 — Compiles + tests green (2026-07-18) ✅ DONE
The archive as received **did not compile**. Fixed all build breakage (botched-edit damage from the sandbox reset, clustered in the speculative→pre-execution-transformed modules). Full detail in `07_BUILD_FIX_LOG.md`.
- **aevor-consensus** `slashing/mod.rs`: removed a fully duplicated block (45 errors → 0).
- **aevor-vm** `parallel/mod.rs`: restored a deleted `#[test] fn` header for an orphaned test body.
- **aevor-client** `multi_network/mod.rs`: appended a missing `mod tests` closing brace.
- **aevor-execution** `speculative/mod.rs`: removed a stale duplicate `tests` module referencing removed types (all capability verified preserved under new names; also clears **B12**).
- **aevor-dag** `speculative/mod.rs`: removed a redundant `tests` module, kept the superset (2 extra invariant tests).
- **aevor-api** `middleware`+`network_routing`: added `Default` derives needed for server construction.
- **aevor-ns** `tee_discovery/mod.rs`: corrected invalid `TeeServiceType::Execution/Attestation` → canonical `Compute/Storage`.
- **aevor-cli** `main.rs`: fixed 3 tests invoking `status` without its required subcommand.
- **Cargo.toml**: bumped `rust-version` `1.75` → `1.85` (a transitive dep, `base64ct`, now requires `edition2024`; the workspace cannot build on 1.75).
- **Verified:** `cargo test --workspace` → **1,546 passed, 0 failed** (48 test binaries). Builds on current stable (1.97.1).

### Pending — alignment re-applications (from `02`, lost to the sandbox reset)
- [ ] **§3.1** `aevor-core`: rename `CONFIRMATION_MS_*_MAX` → `TYPICAL_CONFIRMATION_MS_*` (+ update the 3 ordering assertions in tests). Match the pattern already present in `aevor-consensus`.
- [ ] **§3.2** `aevor-storage`: rename `MAX_BATCH_SIZE` → `DEFAULT_BATCH_SIZE` (+ doc: per-node tuning, not a ceiling).
- [ ] **§3.3** `aevor-security`: clarify `AUDIT_LOG_MAX_ENTRIES` doc (rotation threshold, not a throughput ceiling; keep the `MAX_` name).

### Pending — mainnet-gating swap-ins (from `01`/`03`)
- [ ] **B3** `aevor-tee`: real attestation on ≥1 production platform (SGX / SEV-SNP / Nitro). *(L)*
- [ ] **B4** `aevor-consensus`: real `content_hash` (BLAKE3) + `finality_proof` (BLS aggregation). *(S/M)*
- [ ] **B5** `aevor-storage`: wire `rocksdb`; real Merkle authentication paths; real receipt-root tree. *(M)*
- [ ] **B6** `aevor-dag`: real topological sort over the existing (correct) edge set. *(S)*
- [ ] **B10** `aevor-client`: wire `reqwest`/`tonic`/`tokio-tungstenite` transport. *(M)*
- [ ] **B11** `aevor-client`: delegate `AttestationVerifier::verify` to `aevor_tee` (after B3). *(S)*

### Pending — launch-quality swap-ins (from `01`/`03`)
- [ ] **B1** `aevor-zk`: real provers (`arkworks`/`halo2_proofs`/`winterfell`/`bulletproofs`). *(L)*
- [ ] **B2** `aevor-crypto`: real Dilithium via `pqcrypto-dilithium` (classical half already real). *(S/M)*
- [ ] **B7** `aevor-network`: real erasure coding via `reed-solomon-erasure`. *(S/M)*
- [ ] **B8** `aevor-metrics`: real Laplace noise sampling. *(S)*
- [ ] **B9** `aevor-ns`: real recursive resolver + DNSSEC via `hickory-dns`. *(M)*
- [ ] **B12** `aevor-execution`: remove the stale `// stub` comment in `speculative/mod.rs:124`. *(S)*

### Pending — process / CI (from `03`)
- [ ] CI grep-gate: reject new `TODO`/`FIXME`/`unimplemented!`/`todo!`/`mock`/`stub`/`placeholder` in non-test code.
- [ ] CI grep-gate: alignment invariants (no ceiling-implying `MAX_*` without a clarifying doc; no speculative/rollback/prefetch vocabulary).
- [ ] Keep TEE simulation backends behind a `simulation` feature flag (do not delete).
- [ ] Re-run `test_aevor.sh` after each swap-in; keep the 1,541-test baseline green and grow it.

---

## [0.0.0-review] — 2026-07-18 — Read-only review baseline

### Reviewed
- Full read-only review of `AEVOR.zip`: 22-crate workspace + `node`, 272 `.rs` files, 43,497 LOC, 1,541 tests.
- Verified against finalized `WHITEPAPER.md` (28 sections), `Tokenomics.md`, and `README.md` (canonical designs confirmed captured and aligned).

### Verified present (survived prior sessions)
- **R1–R11**: speculative/rollback → pre-execution conflict rejection; MVCC "rejected; sender may resubmit."
- **C1–C7**: `DEFAULT_PRODUCERS_*`, `DEFAULT_MAX_BLOCK_PARENTS`, `DEFAULT_PARALLEL_LANES`.
- **T1**: `DEFAULT_TX_EXECUTION_TIMEOUT_MS`.
- **N1**: "topology-aware dependency propagation" (no "predictive prefetch").
- `aevor-consensus`: `TYPICAL_CONFIRMATION_MS_*` (the reference for the pending `aevor-core` fix).

### Found missing (regressions vs. last session — to re-apply)
- **§3.1 / §3.2 / §3.3** as listed under Unreleased. Root cause: this archive predates the last session's edits (sandbox reset).

### Catalogued (no code changed)
- 12 interface-faithful simulations (**B1–B12**) with exact swap-in targets, dependencies, and effort — see `01_STUB_AND_SIMULATION_REGISTER.md`.
- Anti-pattern baseline: **zero** `TODO`/`FIXME`/`unimplemented!`/`todo!`/`mock` in non-test code. All `stub`/`placeholder`/`simplified` occurrences catalogued.
- Legitimate patterns confirmed *not* to touch: cover traffic ("dummy"), no-ceiling docs ("hardcoded"), slashing "temporary reward reduction", zero-value sentinels, DNS `NotImplemented` RCODE, governance `ParameterSimulation` feature, `TeeMode::Simulation` dev flag.

### Delivered
- `00_CODEBASE_OVERVIEW.md`, `01_STUB_AND_SIMULATION_REGISTER.md`, `02_PENDING_WHITEPAPER_ALIGNMENT.md`, `03_PRODUCTION_READINESS_CHECKLIST.md`, `04_REVIEW_NOTES_BY_CRATE.md`, `05_TEE_DEVELOPER_GUIDE.md`, `06_USER_GUIDE.md`, and this changelog.

---

### Entry template (copy for each change)

```
## [version/date] — short milestone name

### Changed
- <crate>: <what changed> (register Bx / alignment §x.x). Interface unchanged: yes/no.

### Added
- <new real implementation> replacing <simulation>; dependency <crate> added; tests <added/updated>.

### Verified
- test_aevor.sh: <N> tests passing. Anti-pattern grep: clean. Alignment invariants: hold.
```
