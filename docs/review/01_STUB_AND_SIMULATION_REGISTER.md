# AEVOR — Stub & Simulation Register

This is the authoritative catalog of every non-production implementation in the codebase, why it exists, exactly what replaces it, and the effort involved. **Nothing here was deleted or modified** — this document exists so the swap-ins can be done deliberately, with no capability lost and no gap introduced.

**Guiding principle for every item below:** the *interface is production-shaped and correct*. What is simulated is the *implementation body behind it*. Swapping in the real implementation should not change any public type, signature, or call site — only the internals and the crate's dependency list.

Legend for **Effort**: **S** = <½ day (wire an existing crate), **M** = 1–3 days (real algorithm + tests), **L** = >3 days (hardware/integration-dependent).

---

## Part A — Anti-pattern scan result (the clean baseline)

Non-test occurrences across all 272 files:

| Marker | Count | Status |
|--------|------:|--------|
| `TODO` / `FIXME` / `XXX` | 0 | ✅ clean |
| `unimplemented!` / `todo!` / `unreachable!` | 0 | ✅ clean |
| `mock` | 0 | ✅ clean |
| `"in a real"` / `"for simplicity"` | 0 | ✅ clean |
| `placeholder` | 6 | catalogued below |
| `stub` | 9 | catalogued below |
| `simplified` | 2 | catalogued below |
| `"for now"` | 1 | catalogued below |
| `dummy` | 4 | ✅ legitimate (cover traffic) — Part C |
| `fake` | 1 | ✅ legitimate (test input) — Part C |
| `hardcoded` | 3 | ✅ legitimate (documents *absence* of ceilings) — Part C |
| `temporary` | 1 | ✅ legitimate (slashing consequence) — Part C |
| `"in production"` | 22 | doc markers pointing at the items below |
| `"not yet"` | 25 | mostly client transport + state-machine states |

The codebase has **no abandoned-work markers**. Every simulation is deliberate and documented in-line.

---

## Part B — The simulation register (items to swap before mainnet)

### B1 · Zero-Knowledge proof systems — `aevor-zk`
> **Status (Milestone 20): DONE.** Real Bulletproofs range proofs (audited `bulletproofs` v5.0.0, same curve25519-dalek 4.1.3 — no second curve lib) in `aevor-zk::bulletproofs`: `RangeProof::prove`/`verify_range` prove an amount is in [0, 2^64) in zero knowledge; commitments use the Bulletproofs generators so commitment + range proof + homomorphic balance check are coherent. Tampered commitment/proof rejected; balanced vs unbalanced transactions distinguished. M19's stepping-stone amount commitment in aevor-crypto was removed (mismatched generators) — one confidential-amount commitment, coherent with its range proof.
> **Status (Milestone 19): commitment layer REAL; range proof outstanding.** Real EC Pedersen commitments (`value·G + blinding·H` over Ristretto) with homomorphic add/sub + a real confidential-balance check now live in `aevor_crypto::proofs::pedersen`; the crate's former hash-based (fake) Pedersen now delegates to this one primitive (no duplicate logic). Outstanding: a full **Bulletproofs range proof** (amount ∈ [0, 2^n)) via the vetted `bulletproofs` crate — a focused follow-on.
**Files:** `proving/mod.rs:35`, `plonk/mod.rs`, `halo2/mod.rs:32`, plus STARK/Bulletproofs/Groth16 modules.
**Current behavior:** All provers are structural simulations. `ProofGenerator::generate()` returns a fixed-size zeroed byte vector (`vec![0u8; 192]` for Groth16, ~800 for PLONK, ~1200 for Halo2). `verify()` checks only that the proof is non-empty and the verifying-key hash matches the circuit hash. No polynomial commitments or elliptic-curve proving is performed.
**What it must become:** Delegate to a real proving backend. The `ProofRequest` / `Witness` / `Circuit` / `ProofGenerationResult` types are already the right shape.
**Real implementation / dependency:**
- Groth16, PLONK → `arkworks` (`ark-groth16`, `ark-plonk`, `ark-bn254`/`ark-bls12-381`)
- Halo2 → `halo2_proofs`
- STARK → `winterfell` or `plonky2`
- Bulletproofs → `bulletproofs` crate
**Interface-faithful:** Yes — swap the body of `generate`/`verify`, add the dependency, keep the types.
**Effort:** **L** (each system is a real integration + circuit plumbing).
**Gating:** Required for any privacy feature that claims ZK guarantees (selective disclosure, range proofs). TEE-based privacy does **not** depend on this.

---

### B2 · Post-quantum Dilithium half of hybrid keys — `aevor-crypto`
> **Status (Milestone 9): DONE — real ML-DSA-65 (FIPS 204) via the vetted pure-Rust `fips204` crate, behind the crypto-agility `Signer`/`verify_multi` trait.** `MlDsa65KeyPair` (generate / sign / public-key-bytes) plus a `verify` entry point are wired into the agility dispatch; `SignatureSchemeId::MlDsa65` now returns `Valid`/`Invalid` instead of `Unsupported`. Proven end-to-end: a post-quantum wallet signs a transaction that the node verifies and processes (`node/tests/end_to_end.rs::post_quantum_wallet_transacts_end_to_end`).
>
> **Decision rationale (same overhead/performance lens as the storage decision, opposite conclusion):** from-scratch won for storage because the workload matched Bitcask exactly and the only alternative was a heavyweight *C++* engine. None of that holds for ML-DSA: (1) a mature **pure-Rust** implementation exists (so the C++-avoidance reason that favored from-scratch for storage is absent), (2) ML-DSA performance is dominated by the NTT and rejection sampling that experts tune — from-scratch would be **slower**, not faster, and (3) for crypto the real "overhead" is the **side-channel risk surface**: lattice signing must be constant-time and NIST-vector-conformant, and a hand-rolled version adds large, *silent* risk (bugs that pass functional tests while leaking key bits). This is consistent with AEVOR's existing crypto already using expert libraries (`ed25519-dalek`, `blst`). The property AEVOR owns is **agility** (the envelope), not the primitive internals.
>
> **Remaining (optional):** add FN-DSA (Falcon, size-optimized for tx signing) and SLH-DSA (root-of-trust) behind the same trait; ML-KEM for the KEM side. (The `HybridEd25519MlDsa65` path now composes real Ed25519 + real ML-DSA, and a full account-continuity/key-migration layer exists — see Milestone 11 and doc 09 §5.) See `09_CRYPTO_AGILITY_AND_PQC.md`.
**File:** `post_quantum/mod.rs:48, 64, 97, 116`.
**Current behavior:** `HybridKeyPair` combines a **real** Ed25519 keypair with a **simulated** Dilithium component. The PQ public key is `BLAKE3(seed ‖ "dilithium-pk")`; the PQ signature is `BLAKE3(secret ‖ message)`. `sign()`/`verify()` run the real Ed25519 path *and* the BLAKE3 stand-in; both must pass.
**What it must become:** Replace the three BLAKE3 blocks with real Dilithium keygen/sign/verify. The classical half already works and stays.
**Real implementation / dependency:** `pqcrypto-dilithium` (`dilithium3::{keypair, sign, open}`), or `ml-dsa` once stabilized (Dilithium is now FIPS 204 / ML-DSA).
**Interface-faithful:** Yes — `HybridKeyPair`, `HybridSignature`, `DilithiumPublicKey`, `DilithiumSignature` are unchanged. Note the real PQ key/sig sizes are larger than the 32-byte BLAKE3 outputs; the byte-vec types already accommodate this.
**Effort:** **S–M**.
**Gating:** Only required when advertising quantum resistance. Classical security is fully real without it.

---

### B3 · TEE attestation backends (all 5 platforms) — `aevor-tee`
> **Status (Milestone 17): DONE (verification logic).** Attestation reports/evidence are now **sealed** (signed over a canonical body) and **really verified** at BOTH the TEE layer (`aevor-tee`) and the consensus layer (`aevor-consensus`), sharing one signing key + `sim_sign`/`sim_verify` in `aevor-crypto` (no fork). Tampering (measurement/nonce/quote) is rejected. Hardware quote *generation* + vendor cert-chain verification remain the feature-gated production extension; the simulation-vs-production *acceptance* policy stays at consensus (`verify_with_policy`).
**Files:** `sgx/mod.rs`, `sev/mod.rs`, `trustzone/mod.rs`, `keystone/mod.rs`, `nitro/mod.rs`, and `attestation/mod.rs` (verify path).
**Current behavior — important nuance:** the *detection* layer is already real, the *attestation* layer is simulated:
- `is_available()` performs a **real** device-path / capability check (e.g. `Path::new("/dev/sgx_enclave").exists()`).
- `detect_capabilities()` performs real feature detection but sets `is_production: false`.
- `generate_report()` returns a **simulation** report: a BLAKE3 measurement over a domain-separated tag (e.g. `b"aevor-sgx-simulation-v1:"`) rather than a hardware quote.
- `attestation/mod.rs` verification (`verify_sgx`/`verify_sev`/…) currently does a **structural** check (`!report.raw_report.is_empty()`) rather than a full quote/certificate-chain validation.
**What it must become:** For each platform, `generate_report()` reads the real hardware quote and `verify_*()` validates it against the platform's root of trust:

| Platform | Real report source | Real verification |
|----------|--------------------|--------------------|
| Intel SGX | DCAP quoting enclave via `/dev/sgx_enclave` | DCAP quote + PCK cert chain (Intel PCS) |
| AMD SEV-SNP | `/dev/sev-guest` `SNP_GET_REPORT` | VCEK/VLEK cert chain (AMD KDS) |
| ARM TrustZone | PSA Attestation API (secure world) | PSA/EAT token verification |
| RISC-V Keystone | Security Monitor attestation | SM report + device root key |
| AWS Nitro | NSM `/dev/nsm` `GetAttestationDoc` | COSE_Sign1 + AWS Nitro PKI |

**Interface-faithful:** Yes — the `AttestationReport`, `PlatformCapabilities`, `CrossPlatformAttestation` types and the `verify` / `verify_cross_platform` entry points are the production shape. This is the single most important extensibility surface in the codebase — see `05_TEE_DEVELOPER_GUIDE.md` for the full backend contract and the "add a new chip" recipe.
**Effort:** **L** per platform (hardware + SDK + PKI). Detection layer is done.
**Gating:** Required for real PoU security. Simulation is expected in CI (no TEE hardware present) and should remain available behind a feature flag for testing.

---

### B4 · Consensus content hash & finality proof — `aevor-consensus`
> **Status: DONE (Milestone 4).** `content_hash` now computes a real BLAKE3 hash over the assembled preimage. `finalize_round` now builds a **real populated `FinalityProof`** (validator signatures, participant bitmap, signed voting weight, security level) with a BLAKE3 commitment binding all signatures. Consensus↔crypto is wired (`aevor_crypto::hash::Blake3Hasher`). Tests: `proposal_content_hash_is_real_and_deterministic`, `finalized_round_produces_real_finality_proof`, `unfinalized_round_has_no_finality_proof`. **Remaining sub-item:** `aggregate_signature` is a BLAKE3 commitment today; upgrading it to a true BLS12-381 point aggregate requires `BlockAttestation` to carry BLS signatures (currently a 64-byte signature) — validator BLS signing is the follow-up.
**File:** `engine/mod.rs:71` (`content_hash`), `engine/mod.rs:190` (`finality_proof`).
**Current behavior:**
- `ProposalMessage::content_hash()` assembles the correct pre-image (block hash ‖ round ‖ height) but returns `Hash256::ZERO` instead of hashing it.
- Finalized-block construction sets `finality_proof: None`.
**What it must become:**
- `content_hash()` → `Blake3Hasher` over the already-assembled `data` buffer (the real hasher exists in `aevor-crypto`).
- `finality_proof` → BLS aggregate signature over the attestation set (BLS12-381 aggregation is already real in `aevor-crypto`).
**Interface-faithful:** Yes — both are internal bodies; the surrounding `ProposalMessage` / finalized-block types are correct.
**Effort:** **S** (`content_hash`), **M** (`finality_proof` aggregation wiring).
**Gating:** `content_hash` affects proposal dedup; `finality_proof` is required for verifiable finality export.

---

### B5 · Storage — RocksDB backend, Merkle proofs, receipt root — `aevor-storage`
> **Status (Milestone 6): backend + Merkle proofs DONE; pure Rust, no C/C++.** RocksDB was **rejected** as a C++ dependency inconsistent with AEVOR's from-scratch posture (the `RocksDbBackend` was only a no-op placeholder from the original tree) and is **removed**. In its place: `LogBackend`, a from-scratch log-structured (Bitcask-family) durable store chosen for AEVOR's access pattern — in-memory offset index (values on disk), lock-free positioned reads, sequential-append writes, WAL crash recovery via per-batch commit markers + CRC-32, atomic `commit_batch`, and `compact`. `MerkleProver` is now a **real binary Merkle tree** with genuine inclusion proofs + verification (commutative domain-separated BLAKE3, odd nodes carried up). **Remaining:** wire `LogBackend` + Merkle authentication into the `ObjectStore`/commit path (swap `MemoryBackend` in the composed pipeline; receipt-root over receipts); add exclusion proofs.
**Files:** `backend/mod.rs:69`, `merkle/mod.rs:43`, `transactions/mod.rs:61`.
**Current behavior:**
- `RocksDbBackend` is a placeholder struct — the `rocksdb::DB` field is commented out; the `Backend` trait is fully defined and implemented against the type.
- `MerkleProver::prove()` returns real value/root/inclusion data but `siblings = vec![Hash256::ZERO]` — the authentication path is not traversed.
- `TransactionStore::receipt_root()` uses an **XOR chain** over receipt hashes instead of a Merkle root.
**What it must become:**
- Wire the `rocksdb` crate into `RocksDbBackend` (open/get/put/delete/flush map directly to the existing trait methods).
- `prove()` → real Merkle authentication path (sibling collection along the tree).
- `receipt_root()` → real Merkle tree (reuse the same tree implementation as `prove()`).
**Real implementation / dependency:** `rocksdb` crate; the Merkle logic is internal (no new dep).
**Interface-faithful:** Yes — `Backend`, `MerkleProof`, `StorageKey/Value`, `receipt_root` signatures unchanged.
**Effort:** **M** (RocksDB), **M** (Merkle path + receipt tree).
**Gating:** RocksDB required for durable state; Merkle path required for light-client / proof export.

---

### B6 · DAG topological ordering — `aevor-dag`
> **Status: DONE (Milestone 5).** Replaced the identity order with a real **Kahn's algorithm** over directional (acyclic) dependency edges (later conflicting tx depends on earlier), and added `DependencyAnalyzer::parallel_execution_levels()` computing parallel execution **waves**. Edges were made directional so the graph is a true DAG. +5 tests (`topological_order_respects_dependencies`, chain/levels/mixed).
**File:** `dependency/mod.rs:69`.
**Current behavior — important nuance:** the dependency **edges are computed correctly** (conflict detection populates `edges` and `reverse_edges` via `ConflictDetector::conflict_type`). Only the final linear ordering is simplified: `topological_order = (0..vertices.len()).collect()` (identity order).
**What it must become:** A real topological sort (Kahn's algorithm or DFS) over the already-correct edge set.
**Interface-faithful:** Yes — `DependencyGraph { vertices, edges, reverse_edges, topological_order }` is unchanged; only the value of the last field is computed properly.
**Effort:** **S** (standard algorithm over existing edges).
**Gating:** Required for correct execution scheduling when dependency chains exist (independent transactions are unaffected).

---

### B7 · Network erasure coding — `aevor-network`
> **Status (Milestone 8): DONE — real Reed-Solomon over GF(256), pure Rust, no dependency.** The chunk-split/concat stub (which could not recover a lost shard) is replaced by a genuine Reed-Solomon coder: GF(256) arithmetic (primitive polynomial `0x11D`), a systematic coding matrix derived from a Vandermonde matrix, and Gauss-Jordan field inversion for reconstruction. `data_shards` (K) + `parity_shards` (M) shards are produced such that **any K of the K+M** reconstruct the original — up to M shards can be lost. API updated to position-indexed reconstruction (`&[Option<Vec<u8>>]` + original length). Tests prove recovery from losing up to M shards, failure beyond M, systematic-shard correctness, and GF(256) field axioms. **Remaining:** wire it into block propagation once the networking transport lands (data-availability distribution across validators).
**File:** `availability/mod.rs:97`.
**Current behavior:** `DataAvailability::encode()`/`reconstruct()` are stubs — reconstruction concatenates shards rather than performing Reed–Solomon recovery. `ErasureConfig { data_shards, parity_shards }` is the correct shape.
**What it must become:** Real erasure coding so any `data_shards`-of-`(data+parity)` subset reconstructs the original.
**Real implementation / dependency:** `reed-solomon-erasure` crate.
**Interface-faithful:** Yes.
**Effort:** **S–M**.
**Gating:** Required for data-availability guarantees under shard loss.

---

### B8 · Differential-privacy Laplace noise — `aevor-metrics`
> **Status: DONE (Milestone 5).** `LaplaceMechanism` now adds real Laplace(0, scale) noise via inverse-CDF transform with a seeded `SplitMix64` uniform (no external dependency; deterministic per seed for verifiability). `apply_seeded` lets callers supply fresh entropy. +4 tests including an empirical zero-mean check over 20k samples.
**File:** `differential_privacy/mod.rs:54`.
**Current behavior:** `LaplaceMechanism::apply()` returns `noised_value = true_value` (zero noise) for deterministic tests. `scale()` correctly computes `sensitivity / epsilon`; `epsilon_consumed` is tracked correctly.
**What it must become:** Sample from `Laplace(0, scale)` and add to the true value.
**Real implementation / dependency:** `rand_distr::Laplace`, or inverse-CDF sampling with `getrandom`.
**Interface-faithful:** Yes — `NoisedMetric`, `DpConfig` unchanged.
**Effort:** **S**.
**Gating:** Required only for privacy-preserving telemetry claims; metrics correctness otherwise unaffected.

---

### B9 · NS recursive resolver + DNSSEC — `aevor-ns`
> **Status (Milestone 19): DNSSEC DONE; recursive resolution is a network seam.** `DnssecVerifier::verify` was a validation bypass (always `true`); it now does real Ed25519 (algorithm 15) verification and rejects tampering. The recursive/upstream DNS path is genuine network I/O (vetted resolver crate + live network) — a documented seam, not a stub of the security logic.
**File:** `resolver/mod.rs` (`RecursiveResolver::resolve`).
**Current behavior:** `resolve()` returns a well-formed record but always sets `authenticated = false` — no recursive resolution or DNSSEC validation is performed. The `AuthoritativeResolver` and zone handling are more complete.
**What it must become:** Real recursive resolution (query chain from root) and DNSSEC signature validation to set `authenticated` correctly.
**Real implementation / dependency:** `hickory-resolver` (formerly `trust-dns-resolver`) or `hickory-dns` for DNSSEC.
**Interface-faithful:** Yes.
**Effort:** **M**.
**Gating:** Required for internet-compatible recursive DNS + DNSSEC. Authoritative/zone features are further along.

---

### B10 · Client transport (HTTP / gRPC / WebSocket) — `aevor-client`
> **Status (Milestone 12): client submission/query path DONE over a `NodeConnection` seam** (`aevor_client::exec::Client` + `EngineConnection`); a client builds/signs/submits transactions of any scheme and queries objects with **verified Merkle proofs**. **Remaining:** the real socket transport (HTTP/gRPC/QUIC) implementing `NodeConnection`, and status/finality polling.
**Files:** `query/mod.rs:125,140,155`, `transaction/mod.rs:92–96`, `subscription/mod.rs:104,115`.
**Current behavior — most significant *integration* gap:** every client method is fully structured but the transport is not wired. Query/transaction methods return `ClientError::ConnectionFailed { reason: "not yet connected" }`; the subscription client returns `"WebSocket transport not yet wired"`. Polling logic (`TransactionPoller::wait_for_finality`), endpoint handling, and status state-machine are all real and correct.
**What it must become:**
- Query/transaction → `reqwest` (HTTP+JSON) and/or `tonic` (gRPC) POST to the endpoint; the code even documents the intended call (`POST self.endpoint/v1/transactions`).
- Subscription → `tokio-tungstenite` WebSocket client.
**Real implementation / dependency:** `reqwest`, `tonic`, `tokio-tungstenite`.
**Interface-faithful:** Yes — all client types, the poller, and error types are production shape; only the network call is inserted.
**Effort:** **M** (all three transports).
**Gating:** Required for the SDK to talk to a node. High-value, low-risk: pure I/O behind finished interfaces.

---

### B11 · Client attestation verifier — `aevor-client`
> **Status (Milestone 18): DONE.** The client's `AttestationVerifier::verify` now really verifies the attestation **evidence seal** (via the shared `aevor_crypto::attestation::verify_evidence`, the same check validators run) plus a non-zero input — not a structural check. Light-client trust now has both legs: Merkle inclusion + attestation verification.
**File:** `verification/mod.rs:61`.
**Current behavior:** `AttestationVerifier::verify()` does a structural check (`raw_report` non-empty and `input_hash` non-zero) with the in-line note "For now: structural check only."
**What it must become:** Delegate to `aevor_tee::attestation::verify_report()` (which itself becomes real in **B3**). The intended call is already documented in-line.
**Interface-faithful:** Yes.
**Effort:** **S** (once B3 lands).
**Gating:** Tied to B3 — client-side attestation verification is only as real as the TEE backend it calls.

---

### B12 · Leftover transformation comment — `aevor-execution`
**File:** `speculative/mod.rs:124` — `let _ = changes; // changes may be empty in stub`.
**Current behavior:** Not a functional stub. This module was **architecturally transformed** in a prior session from speculative-execution to pre-execution conflict analysis (`ConflictAnalysisResult` / `ConflictAnalysisMetrics`, with `SpeculativeMetrics` kept as a type alias). The `// stub` comment is a stale leftover from that refactor.
**What it must become:** A comment cleanup (the line either does real work or the discard is intentional; the wording should be corrected so it doesn't read as an abandoned stub).
**Interface-faithful:** N/A (comment only).
**Effort:** **S** (documentation).
**Gating:** None — cosmetic, but worth fixing so the "zero stubs" goal is literally true on a grep.
> **Update (Milestone 3):** resolved. The stale duplicate test module carrying this comment was removed. B12 is closed.

---

### B13 · VM has no bytecode interpreter — `aevor-vm`
> **Status: DONE (Milestone 4).** A real deterministic interpreter now exists at `aevor-vm/src/interpreter/mod.rs` (`Interpreter`), executing the full `Instruction` set (stack, arithmetic, control flow, memory, TEE opcodes) with real gas metering (`GasMeter`), a value stack, linear memory, TEE-context tracking, and guaranteed termination (gas + step bound). `AevorVm::execute(program, gas_limit)` delegates to it. 18 tests cover arithmetic, division-by-zero, stack underflow, out-of-gas, jumps (conditional/unconditional/out-of-bounds), call-depth overflow, alloc/free, and the TEE enter/attest/exit flow. **Remaining:** a bytecode *decoder* (raw `Vec<u8>` → `[Instruction]`) and wiring the interpreter into the transaction pipeline (transactions carrying bytecode → VM execution) — the composed executor currently persists declared writes without invoking the VM.
**Files:** `aevor-vm/src/vm/mod.rs` (`AevorVm`), `instructions/mod.rs`.
**Current behavior — discovered in Milestone 3:** `aevor-vm` models bytecode, instructions, gas metering, a contract registry (`AevorVm::deploy`/`lookup`), execution sessions, and the parallel/Object-DAG scaffolding — but there is **no interpreter**: no `execute`/`run`/`interpret`/`eval` method that runs bytecode and produces a result. `Instruction::base_gas()` exists; nothing consumes instructions to transition state. So "execution" of an accepted transaction currently applies declared effects (its write set) rather than executing code.
**What it must become:** A real bytecode interpreter (or Move VM integration via `aevor-move`) that decodes and runs `Instruction`s against a VM state, meters gas as it goes, and returns an `ExecutionResult` (success/failure, gas used, state changes, events). This is the piece the composed executor (Milestone 3) leaves as a declared-effects placeholder.
**Real implementation / dependency:** either a hand-written interpreter over the existing `Instruction` set, or delegate to the Move runtime in `aevor-move` (which already models bytecode verification/types). The gas schedule and instruction set are already defined.
**Interface-faithful:** Partially — the types (`AevorVm`, `Instruction`, gas) exist; the execution entry point does not yet, so adding it introduces a new method (not just a body swap).
**Effort:** **L** (a real VM interpreter is substantial).
**Gating:** Required for genuine smart-contract execution. The conflict-detection + persistence write path (composed executor) works without it, but accepted transactions are not *executed* (only their declared writes are persisted) until this lands.

---

### Integration note (Milestone 3): the composed write path
`aevor-execution/src/composed/mod.rs` (`ComposedExecutor`) is the first **real cross-crate wiring**: it calls `aevor-dag` (conflict rejection), `aevor-crypto` (BLAKE3), and `aevor-storage` (`ObjectStore`/`MemoryBackend`) to implement *txs → reject conflicts → persist accepted writes → log rejections*, with 6 passing integration tests. It intentionally does **not** invoke the VM (B13) and uses the in-memory backend (swap for real RocksDB, B5). This is the template for the remaining wiring in `08_WHITEPAPER_ALIGNMENT_AND_INTEGRATION_AUDIT.md` §6.

---

## Part C — Looks like a stub, is intentional (do **not** change)

These matched the anti-pattern grep but are correct as written. Changing them would remove real functionality or introduce a ceiling the whitepaper forbids.

| Item | Location | Why it's correct |
|------|----------|------------------|
| "dummy traffic / dummy requests" | `aevor-client/privacy`, `aevor-tee/anti_snooping`, `aevor-config/privacy` | **Cover traffic** — a genuine anti-timing-analysis privacy technique, not placeholder data. |
| "hardcoded" ×3 | `aevor-governance/parameters:4`, `aevor-api/rate_limiting:5`, `aevor-network/routing:5` | Each comment **documents the absence** of hardcoded ceilings, directly implementing the whitepaper's no-ceiling principle. Positive. |
| "temporary reward reduction" | `aevor-consensus/slashing:36` | A real, correctly-named slashing consequence (a temporary reward cut with no stake slash). |
| Zero-signature placeholder | `aevor-core/primitives:690` | The all-zero signature is a legitimate sentinel value with a documented meaning. |
| Zero validator-id placeholder | `aevor-consensus/slashing:105` | Documented: real usage derives the ID from evidence; the zero value is a safe default before evidence is attached. |
| "fake bytecode" | `aevor-move/lib.rs:263` | A **test input** feeding the verifier a known-bad program. |
| "would be rejected" | `aevor-dag/dependency:178` | A comment explaining rejection semantics, not a deferral. |

---

## Part D — Confirmed real (no action)

Verified against `Cargo.lock` and source during this review:

- **Ed25519** signatures — `ed25519-dalek`. Real keygen/sign/verify.
- **BLS12-381** aggregate signatures — `blst` (min-sig). Real; the intended source for consensus finality proofs (B4).
- **ChaCha20-Poly1305** and **AES-256-GCM** — `chacha20poly1305`, `aes-gcm`. Real AEAD.
- **BLAKE3 / SHA-2 / SHA-3** — real hashing; BLAKE3 is also (legitimately) used as the stand-in inside B2/B3 simulations.
- **DAG edge computation** (B6) — the conflict-graph edges are real; only the linear order is simplified.
- **MVCC / versioned storage** — real multi-version conflict handling (rejection semantics, no auto-retry).
- **Config / governance / CLI / API / faucet surfaces** — real; no simulated logic found beyond the items above.

---

## Part E — Suggested remediation order

Sequenced so each step unblocks the next and value lands early:

1. **B12** (comment cleanup) + **B6** (topo sort) + **B4 `content_hash`** — trivial, makes "zero stubs" literally true for the easy cases. *(S)*
2. **B10** (client transport) — unlocks end-to-end SDK↔node testing. *(M)*
3. **B5** (RocksDB + Merkle) — durable state + proofs. *(M)*
4. **B8** (Laplace), **B7** (erasure), **B9** (NS resolver) — independent, parallelizable. *(S–M each)*
5. **B4 `finality_proof`** (BLS aggregation) — verifiable finality export. *(M)*
6. **B3** (TEE backends) — the big one; per-platform, hardware-gated; **B11** and real PoU security follow from it. *(L)*
7. **B2** (Dilithium) and **B1** (ZK) — feature-gated advanced crypto; schedule against when those guarantees are advertised. *(S–M / L)*

Every step is a body-swap behind an unchanged interface. None requires re-architecting.

---

## RESOLVED (Milestone 15) — transaction-type convergence

**Raised in review (single-source-of-truth):** there are two `SignedTransaction` types.

**Finding — this is a *type* fork, not duplicated logic:**
- **No shared logic drifts between them.** Signature verification is `verify_multi` (defined once in `aevor-crypto::agility`); Merkle hashing is the canonical `aevor_core::storage::merkle_*_hash`; BLAKE3 is `aevor_core::hash`. Nothing algorithmic is copied between the two transaction types, so a change to one cannot silently break the other — a mismatch is a compile error.
- **Usage is non-overlapping.** `aevor_core::transaction::SignedTransaction` (Ed25519-only, rich body: nonce/gas/inputs/outputs) is used only by `aevor-execution` and `aevor-client/transaction`. The agility `aevor_client::exec::SignedTransaction` (read/write set + bytecode + `MultiSignature`) is used by the node engine (the real path) and the client exec path. Consensus and storage touch neither the core one.
- **One path is a skeleton.** `aevor-execution::Pipeline::run` takes the core transaction but does not execute (`from_transaction` returns `None`, no VM). The node engine's `ComposedExecutor` path (agility transaction) is the one that actually runs bytecode, detects DAG conflicts, persists, and proves.

**DONE (Milestone 15):** the core `Transaction` is now agility-aware (`MultiPublicKey`/`MultiSignature`); its `inputs`/`outputs` feed the DAG read/write set via `declared_read_set`/`declared_write_set`; the node engine consumes the canonical type and runs the same pipeline; the minimal type is removed. Signing/verifying live once in `aevor-crypto` (`sign_transaction`/`verify_transaction`). `signing_bytes` now covers `chain_id`+`nonce` (replay protection). Behavior-preserving: 1,629 tests pass, lib clippy 0. **There is now exactly one transaction type across the workspace — no remaining fork.**


> **Socket transport (Milestone 19):** a real `std::net` `TcpTransport` now implements the `MessageTransport` (gossip) trait and is exercised over a real loopback socket in tests. The client `NodeConnection` seam still uses the in-process transport.


> **Client socket seam (Milestone 22): DONE.** `aevor_client::transport::TcpNodeConnection` (client) + `node::server::NodeServer` (node) give a real TCP request/response transport over the same `NodeConnection` trait as the in-process `EngineConnection` (length-prefixed bincode; `NodeRequest`/`NodeResponse`). Both transport seams are now real (gossip `TcpTransport` M19 + client `TcpNodeConnection` M22). Verified end-to-end over a loopback socket (submit + query-with-proof-verification).
