# AEVOR — Production-Readiness Checklist

A per-crate go/no-go view. Status reflects the **read-only review** of `AEVOR.zip` and is cross-referenced to the register (`01`) and alignment doc (`02`). Check items off as remediation lands.

**Status key:**
`✅ Ready` — real implementation, no gating items.
`🟡 Ready pending swap-in` — interface complete; a bounded drop-in remains (see register ID).
`🟠 Alignment pending` — functionally fine; a naming/doc edit from `02` needs re-applying.

---

> **Cross-reference (added by `08_WHITEPAPER_ALIGNMENT_AND_INTEGRATION_AUDIT.md`):** a crate being "ready" or "green in isolation" does **not** mean it is connected. The audit found the implementation crates are largely **islands** and the `node` is a lifecycle skeleton. The **integration layer (§0 below) is the top-priority mainnet gate** — above the individual swap-ins.

## 0. Integration layer — TOP-PRIORITY GATE (from audit `08`)

> **PROGRESS (through Milestone 25):** BLS aggregate finality verification is real and **measured flat at ~1.3 ms from 128→50,000 validators** — the no-degradation-as-validators-join proof, the concrete differentiator vs Sui's capped ~100-validator set (`bench_bls_finality_scaling`; doc §5.4). Execution throughput stays flat at ~14k tx/s 1k→100k. Remaining: wire the BLS aggregate into the default finalize_round path; interior sparse Merkle; verify-by-attestation. Then the full mainnet documentation suite. lib clippy 0.\n>\n> **PROGRESS (through Milestone 24):** All register seams closed (B1–B13); both transports real (gossip + client socket); DNS is production (hickory-resolver). ZK range proofs real (Bulletproofs, M20). Performance (M21): O(n) conflict detection + incremental Merkle → execution throughput measured **flat at ~14k tx/s from 1k→100k txs** (M24) — the uncapped-execution shape, measured. New design doc `12_PERFORMANCE_AND_POU_SCALING.md`: the PoU fast path (verify attestation, not re-execute — the real source of uncapped network throughput), the higher-scale benchmark plan (to 50k validators / 1M txs), and the confirmed granular permissionless/permissioned/**feeless**/privacy deployment model. **Confirmed gap:** finality collects N Ed25519 sigs (O(N)) — **BLS12-381 aggregation is the next code milestone** to make 3k/10k/50k validators meaningful. Optional: interior sparse Merkle; the verify-by-attestation code path. 13 e2e tests; lib clippy 0.
>
> **PROGRESS (through Milestone 15):** the transaction-type fork is **resolved** — one canonical `aevor_core::transaction::SignedTransaction`, agility-aware (any scheme signs it), used by the node engine, client, and execution crate; the minimal duplicate is gone. Signing/verifying are single-source in `aevor-crypto`; signed bytes now include chain_id+nonce (replay protection). 1,629 tests pass, lib clippy 0. No remaining transaction drift surface.
>
> **PROGRESS (through Milestone 14):** the three node modes are now real, engine-backed roles that all compose the **one** `NodeEngine` and differ only in policy — full node executes/produces, validator additionally finalizes over a committee, light node verifies proofs against a trusted root with no engine. E2E harness at 12 tests. (The transaction-type convergence is documented as a tracked architectural item in the stub register — a type fork, not a drift risk.)
>
> **PROGRESS (through Milestone 13):** eliminated real code duplication flagged in review. Merkle hashing is now **one canonical implementation** (`aevor_core::storage::merkle_leaf_hash`/`merkle_node_hash`) called by both the prover and the verifier — they can no longer drift. `Blake3Hasher`/`Blake3Hash` live once in `aevor_core::hash` and are re-exported by `aevor-crypto` (single definition reachable everywhere). A separate legacy Ed25519-only transaction type remains in `aevor-core` (used by the execution pipeline) — unifying it with the agility transaction is a larger tracked item.
>
> **PROGRESS (through Milestone 12):** the user-facing loop is closed — a **client** builds/signs/submits transactions (any scheme) over a `NodeConnection` seam and queries objects back with **real, verified Merkle proofs**. This also fixed a genuine stub: `aevor_core::MerkleProof::verify` was structural-only and is now real cryptographic verification, shared canonically by the prover and clients. E2E harness at 11 tests. Remaining for B10: the real socket transport behind the seam.
>
> **PROGRESS (through Milestone 11):** account continuity across the classical→PQ transition is now real. A key can be created as Ed25519, ML-DSA-65, or **Hybrid** (real Ed25519 + real ML-DSA); an account has a **stable identity** so keys can be **rotated without a new wallet**; and a pure-classical wallet stays safe when quantum arrives via a **quantum-safe migration pre-commitment** (activatable even after Ed25519 is broken). All tested, incl. adversarial cases; a hybrid wallet also transacts end-to-end. E2E harness at 10 tests. See doc 09 §5.
>
> **PROGRESS (through Milestone 10):** nodes now **propagate transactions and converge across a network** — an `aevor-network::gossip` transport (`MessageTransport` trait + in-process `LocalNetwork` bus) moves wire-serialized transactions between nodes, the node has a signature-verifying **mempool** (`submit`/`produce_block`), and an e2e test proves a tx submitted to node A reaches node B and both converge to the same state root. Honest seam: real QUIC/TCP implements the same trait. E2E harness at 9 tests.
>
> **PROGRESS (through Milestone 9):** post-quantum signatures are now **real** — ML-DSA-65 (FIPS 204) via the pure-Rust `fips204` crate is wired behind the crypto-agility trait and proven end-to-end (a PQ wallet transacts through the node). The choice of a vetted crate over from-scratch followed the *same* overhead/performance analysis as the storage decision, landing opposite for principled reasons (pure-Rust expert NTT is faster + avoids silent side-channel risk). Register B2 done. E2E harness at 8 tests.
>
> **PROGRESS (through Milestone 8):** durability is now real end-to-end — `NodeEngine` **reconstructs the authenticated Merkle state from durable storage on startup** (`StorageBackend::scan` → `committed_objects`), proven by an e2e test where the state root survives a restart. Two independent nodes are proven to **converge to identical state roots** (determinism). B7 erasure coding is now **real Reed-Solomon over GF(256)** (pure Rust). E2E harness at 7 tests.
>
> **PROGRESS (through Milestone 7):** a **runnable `NodeEngine`** now instantiates and runs the real subsystems and processes blocks end-to-end (`process_block`+`finalize_block`), proven by `node/tests/end_to_end.rs` — the first real-environment integration test (wallet→sign→verify→DAG conflict→VM→durable persist→Merkle proof→finality). This is the progressive harness that grows as more subsystems are wired. Node unused deps ~20→15.
>
> **PROGRESS (through Milestone 6):** storage is now real & pure-Rust (`LogBackend` — Bitcask-family durable store; RocksDB/C++ rejected) with real Merkle inclusion proofs; a crypto-agility layer (scheme-tagged `MultiSignature` + `Signer`/`verify_multi`) makes classical↔PQ switching additive (see `09`). Register B5 backend+Merkle done. Still outstanding: node orchestrator, wiring `LogBackend` into the commit path, real ML-DSA (B2), client transport (B10), finality-aggregation PQ gap.
>
> **PROGRESS (through Milestone 5):** the "islands" are connecting. `aevor-execution` now composes **dag + crypto + storage + vm** (conflict rejection → VM execution → persistence, with failed executions rejected and no partial commit). `aevor-consensus` wires `crypto` (real BLAKE3 `content_hash` + populated `finality_proof`). Execution unused deps 6 → 2; consensus 2 → 1. Register B4/B6/B8/B12/B13 done; alignment §3.1–3.3 done. **Still outstanding: the node orchestrator** (below), storage durability (B5), client transport (B10), and the remaining register swap-ins.

The single largest gap: the components are individually real and tested but are **not composed into a running node**. This must be built before mainnet, and it is the structural root of several register items (B4/B5/B10/B11).

- [x] **Execution composition** — `aevor-execution` calls `aevor-dag` → `aevor-vm` → `aevor-storage` (+ `aevor-crypto`). *(DONE M3–M5: `ComposedExecutor` / `process_program_batch`.)* Remaining: wire real RocksDB backend (B5) in place of `MemoryBackend`.
- [x] **Consensus↔crypto** — real `content_hash` + populated `finality_proof` (B4). *(DONE M4.)* Remaining: true BLS point aggregate once validators sign with BLS.
- [~] **Node orchestration** — `node::engine::NodeEngine` now instantiates and runs the real subsystems (consensus/crypto/dag/execution/storage) and processes blocks end-to-end (`process_block` + `finalize_block`); proven by `node/tests/end_to_end.rs` (wallet→sign→verify→conflict→VM→persist→Merkle proof→finality). *(Node unused deps ~20→15.)* Remaining: the real socket transport behind the `MessageTransport` seam (in-process transport + mempool + multi-node propagation DONE in M10), API/governance subsystems, and the `FullNode`/`ValidatorNode`/`LightNode` mode variants. *(Merkle-state reconstruction from the durable log on startup — DONE in M8.)*
- [ ] **API backend wiring** — `aevor-api` queries consensus/execution/storage (5 unused deps); wire `GraphQlServer`. *(M)*
- [ ] **Network composition** — wire block/tx propagation + `HandshakeMessage`; provide transport for `aevor-client` (B10). *(M)*
- [ ] **State integration** — integrate the orphaned `AccountState` into the storage/state machine; wire `CrossContractExecution`, `ValidatorAdmission`. *(M)*
- [ ] **Dependency hygiene** — after each edge, remove the corresponding unused dep; target zero unused declared deps (`cargo-udeps`/`cargo-machete` in CI). *(S, ongoing)*
- [~] **Node-level integration tests** — `node/tests/end_to_end.rs` is the progressive real-environment harness (6 tests through the full pipeline). It grows as subsystems are wired (add a networking scenario when networking lands, etc.). State reconstruction across restart, two-node determinism, and tx propagation+convergence across nodes (over a wire-serialized transport) are now asserted. Remaining: real socket-transport scenarios and block propagation. *(ongoing)*

See `08` §6 for the full wiring map in dependency order.

## 1. Per-crate status

| Crate | Status | Gating items (register / alignment IDs) |
|-------|--------|------------------------------------------|
| aevor-core | 🟠 Alignment pending | §3.1 rename `CONFIRMATION_MS_*_MAX` → `TYPICAL_CONFIRMATION_MS_*` |
| aevor-config | ✅ Ready | — |
| aevor-crypto | 🟡 Ready pending swap-in | **B2** Dilithium (classical crypto fully real) |
| aevor-tee | 🟡 Ready pending swap-in | **B3** 5 attestation backends (detection layer real) |
| aevor-consensus | 🟡 Ready pending swap-in | **B4** `content_hash` + `finality_proof` |
| aevor-dag | 🟡 Ready pending swap-in | **B6** topological sort (edges real) |
| aevor-storage | 🟡🟠 | **B5** RocksDB + Merkle + receipt root; §3.2 `MAX_BATCH_SIZE`→`DEFAULT_BATCH_SIZE` |
| aevor-vm | ✅ Ready | — (depends on aevor-tee at runtime) |
| aevor-execution | 🟡 Ready pending swap-in | **B12** stale `// stub` comment cleanup |
| aevor-network | 🟡 Ready pending swap-in | **B7** erasure coding |
| aevor-security | 🟠 Alignment pending | §3.3 `AUDIT_LOG_MAX_ENTRIES` doc clarification (keep name) |
| aevor-move | ✅ Ready | — |
| aevor-zk | 🟡 Ready pending swap-in | **B1** real provers (all systems) |
| aevor-bridge | ✅ Ready | — (verify against real consensus finality once B4 lands) |
| aevor-governance | ✅ Ready | — |
| aevor-ns | 🟡 Ready pending swap-in | **B9** recursive resolver + DNSSEC |
| aevor-metrics | 🟡 Ready pending swap-in | **B8** Laplace noise |
| aevor-api | ✅ Ready | — |
| aevor-client | 🟡 Ready pending swap-in | **B10** HTTP/gRPC/WS transport; **B11** attestation verifier (follows B3) |
| aevor-cli | ✅ Ready | — |
| aevor-faucet | ✅ Ready | — |
| node | ✅ Ready | — (integration-tests once B3/B5/B10 land) |

**Fully ready today (9):** aevor-config, aevor-vm, aevor-move, aevor-bridge, aevor-governance, aevor-api, aevor-cli, aevor-faucet, node.
**Swap-in pending (10):** crypto, tee, consensus, dag, storage, execution, network, zk, ns, metrics, client.
**Alignment-only pending (2, overlapping above):** core, security (+ storage's rename).

---

## 2. Mainnet gating items (must-have)

These block a security-meaningful mainnet launch:

- [ ] **B3 — TEE attestation backends real** on at least one production platform (SGX or SEV-SNP or Nitro). PoU security is only as strong as this. *(L)*
- [ ] **B4 — `finality_proof` via BLS aggregation** so finality is externally verifiable. *(M)*
- [ ] **B5 — RocksDB durable backend** so state survives restarts. *(M)*
- [ ] **B5 — Merkle authentication paths** so light clients and bridges can verify proofs. *(M)*
- [ ] **B10 — Client transport wired** so the SDK/CLI can reach a node. *(M)*
- [ ] **B11 — Client-side attestation verification** delegated to real `aevor-tee`. *(S, after B3)*
- [ ] **B6 — Real topological sort** so dependency-chained transactions schedule correctly. *(S)*
- [ ] All three **alignment re-applications** (§3.1/3.2/3.3) and the §4 invariants re-verified in CI. *(S)*

## 3. Launch-quality items (should-have)

Needed for advertised features but not for a minimal secure launch:

- [ ] **B1 — Real ZK provers** (gate to whenever ZK guarantees are advertised). *(L)*
- [ ] **B2 — Real Dilithium** (gate to whenever quantum resistance is advertised). *(S–M)*
- [ ] **B7 — Real erasure coding** for data-availability guarantees under shard loss. *(S–M)*
- [ ] **B8 — Real Laplace noise** for privacy-preserving telemetry. *(S)*
- [ ] **B9 — Recursive resolver + DNSSEC** for internet-compatible DNS. *(M)*
- [ ] **B12 — Comment cleanup** so a `// stub` grep is literally empty. *(S)*
- [ ] Multi-platform TEE coverage (more than one of SGX/SEV/TrustZone/Keystone/Nitro) for platform-diversity security. *(L)*

## 4. Process / CI items

- [ ] Add a CI grep-gate rejecting new `TODO`/`FIXME`/`unimplemented!`/`todo!`/`mock`/`stub`/`placeholder` in non-test code (the baseline is already clean except the catalogued items).
- [ ] Add a CI grep-gate for the §4 alignment invariants (no ceiling-implying `MAX_*` without a clarifying doc; no speculative/rollback/prefetch vocabulary).
- [ ] Keep the TEE simulation backends available behind a `simulation` feature flag for hardware-free CI (do **not** delete them — they are how the test suite runs without TEE hardware).
- [ ] Re-run `test_aevor.sh` after each swap-in; keep the 1,541-test baseline green and grow it per new real implementation.
- [ ] Preserve the seven-path build order (see `00_CODEBASE_OVERVIEW.md` §2) in build scripts.

## 5. Definition of "done" for a crate

A crate is production-ready when **all** of the following are true:
1. Every register (`01`) item for the crate is swapped to its real implementation, with tests exercising the real behavior (not the simulation).
2. Every alignment (`02`) edit touching the crate is applied and the §4 invariants hold.
3. No non-test anti-pattern markers remain (grep-clean).
4. The crate builds in path order and its tests pass in `test_aevor.sh`.
5. For `aevor-tee`: at least one real backend passes attestation against real hardware, and the simulation backend remains behind a feature flag.
