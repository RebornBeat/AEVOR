# AEVOR — Per-Crate Review Notes

Notes from the read-only review, one section per crate, in build-path order. Each entry records what the crate contains, what was checked, and any findings (cross-referenced to register IDs in `01` and alignment IDs in `02`). "Clean" means no simulations or alignment issues were found in that crate.

A note on completeness: a full anti-pattern sweep was run across all 272 files for `TODO`/`FIXME`/`unimplemented!`/`todo!`/`mock`/`stub`/`placeholder`/`simplified`/`no-op`/`not implemented`/`simulate`, plus manual inspection of every flagged line. Hits that turned out to be false positives (e.g. `noop` matching "snoop**ing**", the DNS `NotImplemented` RCODE, governance's `ParameterSimulation` *feature*) are noted where relevant so they don't get "fixed" by mistake.

---

## PATH 0 — Foundation

### aevor-core (18 files, 9,088 LOC)
The type substrate for the whole system. Modules: `block, consensus, coordination, crypto, economics, error, execution, network, primitives, privacy, protocol, state, storage, tee, traits, transaction, validator`.
**Checked:** primitives (hashes, signatures, IDs), the trait surface, state-transition semantics, privacy/TEE type definitions.
**Findings:**
- **Alignment §3.1:** `CONFIRMATION_MS_*_MAX` constants (lines ~263–273) still use ceiling naming and "ceiling" doc language; `aevor-consensus` already moved to `TYPICAL_CONFIRMATION_MS_*`. Re-apply the rename here.
- The all-zero signature at `primitives:690` is a **legitimate sentinel** (documented), not a stub.
- `state/mod.rs` "no-op" transitions (lines 238, 332) are correct semantic descriptions of empty transitions.
- Otherwise clean: the crate is definitions, not logic, and the definitions are production-shaped.

### aevor-config (10 files, 2,103 LOC)
Configuration types. Modules: `consensus, defaults, deployment, economics, loader, network, privacy, tee, validation`.
**Checked:** the TEE mode enum, deployment/network/privacy config, loader.
**Findings:** Clean. Note `TeeMode::Simulation` (`tee/mod.rs:88–89`) is a **deliberate development-mode flag** that pairs with the TEE simulation backends — keep it; it's how non-hardware environments select simulation explicitly.

### aevor-crypto (12 files, 2,442 LOC)
Modules: signatures, encryption, hashing, proofs, bls, post_quantum.
**Checked:** every primitive against `Cargo.lock`.
**Findings:**
- **Real:** Ed25519 (`ed25519-dalek`), BLS12-381 (`blst`, min-sig — aggregation and dedup logic verified real), ChaCha20-Poly1305 + AES-256-GCM, BLAKE3/SHA-2/SHA-3.
- **Register B2:** the Dilithium half of `HybridKeyPair` (`post_quantum/mod.rs:48–116`) is a BLAKE3 stand-in; the Ed25519 half is real. Swap to `pqcrypto-dilithium`.
- `bls/mod.rs:108` `return Ok(())` is duplicate-index dedup, not a bypass.

### aevor-tee (14 files, 3,254 LOC)
The TEE abstraction and the five platform backends. Modules include `attestation, sgx, sev, trustzone, keystone, nitro, anti_snooping`.
**Checked:** detection layer, report generation, verification path, cross-platform attestation, anti-snooping.
**Findings:**
- **Register B3:** all five backends generate **simulation** attestation reports and the verify path is **structural**. Importantly, the **detection layer is already real** (`is_available()` probes real device paths; `detect_capabilities()` does real feature detection with `is_production: false`). This is the primary extensibility surface — see `05_TEE_DEVELOPER_GUIDE.md`.
- `anti_snooping` "dummy requests" is **real cover traffic**, not placeholder.
- `nitro/mod.rs:61` "Simulate PCR0" is part of B3.

---

## PATH 1 — Core Blockchain

### aevor-consensus (12 files, 2,780 LOC)
Proof of Uncorruption engine. Modules: `engine, timing, checkpoint, slashing, security levels`, etc.
**Checked:** proposal/attestation flow, finality construction, security-level thresholds, slashing.
**Findings:**
- **Register B4:** `ProposalMessage::content_hash()` (`engine:71`) assembles the right pre-image but returns `Hash256::ZERO`; finalized-block `finality_proof` is `None` (`engine:190`). Wire BLAKE3 + BLS aggregation (both real in `aevor-crypto`).
- **Alignment (already landed):** `TYPICAL_CONFIRMATION_MS_*` present and asserted (`lib.rs:239–251, 290–292`). This is the reference pattern for the `aevor-core` fix.
- `slashing:36` "temporary reward reduction" and `slashing:105` zero validator-id placeholder are both **legitimate** (documented).
- `checkpoint:23` "simulated checkpoints" is a doc note on the `None` verification case.

### aevor-dag (11 files, 2,170 LOC)
Micro-DAG + macro-DAG + dependency graph. Modules include `dependency, speculative` (now pre-execution), conflict.
**Checked:** conflict detection, edge construction, topological ordering, the transformed speculative module.
**Findings:**
- **Register B6:** edges/reverse-edges are computed **correctly** via `ConflictDetector`; only `topological_order = (0..n).collect()` (`dependency:69`) is simplified. Add a real Kahn/DFS sort over the existing edges.
- **Alignment (already landed):** `DEFAULT_PRODUCERS_*`, `DEFAULT_MAX_BLOCK_PARENTS`, `DEFAULT_PARALLEL_LANES` present; `PreExecutionDecision`/`ConflictFreeSet`/`PreExecutionBatch` present. R-series and C-series confirmed.
- `dependency:178` "would be rejected" is an explanatory comment on rejection semantics.

### aevor-storage (13 files, 2,283 LOC)
State store. Modules: `backend, merkle, transactions, versioned` (MVCC), etc.
**Checked:** backend trait, Merkle prover, receipt root, MVCC.
**Findings:**
- **Register B5:** `RocksDbBackend` is a placeholder (trait fully implemented; `rocksdb::DB` field commented out); `MerkleProver::prove()` returns `siblings = vec![Hash256::ZERO]` (`merkle:43`); `receipt_root()` uses an XOR chain (`transactions:61`). Wire `rocksdb` + real Merkle paths.
- **Alignment §3.2:** rename `MAX_BATCH_SIZE` → `DEFAULT_BATCH_SIZE` (`lib.rs:231`). Neighboring `DEFAULT_CACHE_CAPACITY` already models the correct no-ceiling doc.
- MVCC uses **rejection** semantics ("rejected; sender may resubmit"), not retry — R9–R11 confirmed. `transactions:38` idempotent no-op is correct.

### aevor-vm (15 files, 2,376 LOC)
AevorVM Double-DAG execution. Modules: `bytecode, context, cross_contract, gas, instructions, jit, memory, move_runtime, objects, parallel, privacy, stdlib, tee_integration, vm`.
**Checked:** gas metering, instruction set, parallel execution, TEE integration hooks, JIT module.
**Findings:** Clean of catalogued stubs. The VM depends on `aevor-tee` at runtime, so its end-to-end security inherits B3. No simulation markers found in the VM logic itself.

### aevor-execution (12 files, 1,452 LOC)
Transaction execution + pre-execution conflict analysis + rejection log. Modules: `aggregation, context_factory, cross_contract, lifecycle, metrics, multi_tee, pipeline, privacy_boundaries, rollback, scheduler, speculative`.
**Checked:** the rollback→rejection transformation, scheduler, pipeline, multi-TEE path.
**Findings:**
- **Register B12:** `speculative/mod.rs:124` carries a stale `// changes may be empty in stub` comment left over from the speculative→pre-execution refactor. Cosmetic cleanup so the "zero stubs" claim is literally grep-true.
- **Alignment (already landed):** `rollback/mod.rs` exposes `RejectionReason` incl. `PreExecutionConflict`; no `RolledBack`/`SpeculativeConflict`. R-series confirmed.
- `DEFAULT_TX_EXECUTION_TIMEOUT_MS` present (T1 confirmed).

---

## PATH 2 — Network + Security

### aevor-network (13 files, 1,385 LOC)
P2P networking. Modules: `routing, availability`, topology-aware propagation, etc.
**Checked:** routing, data availability, propagation language.
**Findings:**
- **Register B7:** `DataAvailability::encode/reconstruct` (`availability:97`) is a stub (concat, not Reed–Solomon). Wire `reed-solomon-erasure`.
- **Alignment (already landed):** "topology-aware dependency propagation" throughout; no "predictive prefetch." N1 confirmed. `routing:5` documents the **absence** of hardcoded path/table ceilings (positive).

### aevor-security (12 files, 1,306 LOC)
Modules: `audit, auth, byzantine, cross_platform, metrics, mitigation, network_security, slashing, tee_integrity, threat_detection, validation`.
**Checked:** audit log, byzantine detection, threat detection, TEE integrity.
**Findings:**
- **Alignment §3.3:** `AUDIT_LOG_MAX_ENTRIES` (`lib.rs:211`) is a **legitimate safety bound** (rotation threshold) — keep the `MAX_` name, just apply the doc clarification that it is not a throughput ceiling.
- Otherwise clean.

---

## PATH 3 — Language + Cross-Chain

### aevor-move (11 files, 837 LOC)
Move integration + AEVOR extensions. Modules: `attributes, compiler, cross_chain, privacy_extensions, registry, runtime, stdlib, tee_extensions, types, verifier`.
**Checked:** verifier, privacy/TEE attribute extensions, cross-chain.
**Findings:** Clean. `lib.rs:263` "fake bytecode" is a **test input** to the verifier. The `#[privacy]`/`#[tee_required]`/`#[cross_chain]` attribute machinery is present.

### aevor-zk (14 files, 1,554 LOC)
ZK proof systems. Modules: `proving, plonk, halo2, groth16, stark, bulletproofs`, etc.
**Checked:** every prover.
**Findings:**
- **Register B1:** all provers are structural simulations (fixed-size zeroed proofs; verify checks non-empty + vkey-hash match). `plonk:31` "simulated universal SRS" and `halo2:32` "1200 bytes in this stub" are part of B1. Swap to `arkworks`/`halo2_proofs`/`winterfell`/`bulletproofs`. The `ProofRequest`/`Witness`/`Circuit` types are the right shape.

### aevor-bridge (11 files, 833 LOC)
Cross-chain bridge. Modules: `assets, evm, message_queue, move_chain, privacy, relayer, utxo, verification`.
**Checked:** verification, relayer, asset handling, EVM/UTXO/Move-chain adapters.
**Findings:** Clean of catalogued stubs. Bridge verification should be re-tested against **real** consensus finality once B4 lands (its correctness partly depends on verifiable finality proofs).

---

## PATH 4 — Governance + Naming

### aevor-governance (11 files, 1,023 LOC)
Modules: `delegation, parameters, proposals, quorum, records, timing, treasury, upgrades, validator_governance, voting`.
**Checked:** parameters, voting, quorum, treasury, upgrades.
**Findings:** Clean. `parameters:4` documents the **absence** of hardcoded values (positive). `ParameterSimulation` (`parameters:17`) is a **governance feature** (projected-impact analysis of a parameter change) — not a stub.

### aevor-ns (11 files, 1,143 LOC)
DNS/naming. Modules: `resolver, protocol`, zones, etc.
**Checked:** recursive + authoritative resolvers, protocol types.
**Findings:**
- **Register B9:** `RecursiveResolver::resolve` always returns `authenticated = false` (no real recursion/DNSSEC). Authoritative/zone handling is further along. Wire `hickory-dns`/`hickory-resolver`.
- `protocol:27` `NotImplemented` is the **standard DNS RCODE 4** enum variant, not a stub.

---

## PATH 5 — External Interface

### aevor-metrics (12 files, 734 LOC)
Modules: `differential_privacy`, collectors, etc.
**Findings:**
- **Register B8:** `LaplaceMechanism::apply` (`differential_privacy:54`) returns `true_value` (zero noise) for deterministic tests; `scale()` is correct. Sample real `Laplace(0, scale)`.

### aevor-api (13 files, 1,083 LOC)
Modules: `auth, graphql, grpc, middleware, network_routing, privacy_responses, rate_limiting, rest, types, versioning, websocket`.
**Findings:** Clean. `rate_limiting:5` documents the **absence** of a hardcoded request ceiling (positive). The REST/GraphQL/gRPC/WebSocket surfaces are defined.

### aevor-client (11 files, 2,307 LOC)
SDK. Modules: `query, transaction, subscription, verification, privacy`.
**Findings:**
- **Register B10:** query/transaction/subscription methods are fully structured but return `ConnectionFailed { "not yet connected" }` / `"WebSocket transport not yet wired"`. Polling, endpoints, and status state-machine are real. Wire `reqwest`/`tonic`/`tokio-tungstenite`.
- **Register B11:** `AttestationVerifier::verify` (`verification:61`) is structural "for now"; delegate to `aevor_tee::attestation::verify_report()` once B3 lands.
- `privacy` "dummy requests" is **real cover traffic**.

### aevor-cli (13 files, 1,019 LOC)
Modules: `args, config, context, governance, keys, network, node, output, status, tee, validator`.
**Findings:** Clean. `output:50` "print is a no-op" under `quiet=true` is correct behavior.

---

## PATH 6 — Final

### aevor-faucet (10 files, 1,022 LOC)
Modules: `cooldown, faucet, http, pow, rate_limiting, records, validator_coordination`.
**Findings:** Clean. Testnet faucet with PoW anti-abuse and cooldown.

### node (13 files, 1,303 LOC)
The node binary. Modules: `archive, config, full_node, health, init, light_node, orchestrator, process, shutdown, validator`.
**Checked:** orchestrator wiring, full/light/validator node modes, health, shutdown.
**Findings:** Clean of catalogued stubs. This is the integration point — end-to-end integration tests become meaningful once B3 (TEE), B5 (storage), and B10 (client transport) land.

---

## Summary table

| Crate | Register items | Alignment items |
|-------|----------------|-----------------|
| aevor-core | — | §3.1 |
| aevor-config | — | — |
| aevor-crypto | B2 | — |
| aevor-tee | B3 | — |
| aevor-consensus | B4 | (done) |
| aevor-dag | B6 | (done) |
| aevor-storage | B5 | §3.2 |
| aevor-vm | — | — |
| aevor-execution | B12 | (done) |
| aevor-network | B7 | (done) |
| aevor-security | — | §3.3 |
| aevor-move | — | — |
| aevor-zk | B1 | — |
| aevor-bridge | — | — |
| aevor-governance | — | — |
| aevor-ns | B9 | — |
| aevor-metrics | B8 | — |
| aevor-api | — | — |
| aevor-client | B10, B11 | — |
| aevor-cli | — | — |
| aevor-faucet | — | — |
| node | — | — |
