# AEVOR — Whitepaper Alignment & Integration Audit

A full cross-reference of the codebase against the whitepaper (capability coverage), plus a systematic audit of **redundancy**, **cleanliness**, and — most importantly — **whether the connections between components are actually utilized**. This is the "capture everything, find every gap, ensure every connection is used, keep it clean, no redundancy" pass.

Method: tool-driven, not from memory. Whitepaper vocabulary was extracted mechanically (all CamelCase identifiers) and diffed against every public item in the code; dependencies were checked declared-vs-used per crate; duplicate definitions and dead types were scanned across all 272 files; clippy was run workspace-wide.

---

## 0. Headline

Three of the four audit axes are in excellent shape. The fourth is the real story.

| Axis | Result |
|------|--------|
| **Whitepaper capability coverage** | ✅ **Complete** — 108/110 committed identifiers exist in code; the other 2 are a reference citation and an example module. |
| **Redundancy** | ✅ **Near-clean** — all duplicate `mod tests` fixed in Milestone 1; one duplicate type *name* remains (`ApiError`). |
| **Cleanliness** | ✅ **Clean** — release build warning-free; ~14 trivial clippy lints (all auto-fixable). |
| **Connections utilized** | ⚠️ **This is the gap.** The implementation crates are largely **islands**, and the `node` is a lifecycle skeleton. Type-level integration (via `aevor-core`) is complete; **runtime/service integration is mostly absent.** |

The fourth finding is the structural root of several simulation items in `01_STUB_AND_SIMULATION_REGISTER.md` and is the single largest body of remaining work. It is also **normal and expected**: the build is explicitly layered with `node` as "PATH 6 — Final," and that final composition step has not been done yet.

---

## 1. Whitepaper capability coverage — COMPLETE

**Method.** Extracted all 110 distinct CamelCase identifiers from `WHITEPAPER.md` (it contains no fenced code blocks — capabilities are named in prose) and diffed against the 1,196 public types in the code plus a variant/identifier search.

**Result.** 108 of 110 map to real code. The 2 that don't are not capabilities:
- `SplitStream` — an academic citation (Castro et al., 2003) in the References section.
- `PrivateAuction` — an *example* Move module in §12 (illustrative smart-contract code).

**Spot-verified present** (the types prior sessions added for whitepaper alignment, all confirmed in this archive): `SecurityLevelPolicy`, `EscalationTrigger`, `ValidatorTopologyScore`, `GraduatedSlashingPolicy`, `ViolationSeverity`, `SeverityClassifier`, `DelegationCapabilityScore`, `CrossSubnetEconomics`, `ServiceHealth`, `QosPolicy`, `ServiceMeshCoordinator`, `CrossNetworkServiceCoordinator`, `SecureDeploymentRecord`, `DataIntegrityProof`, `FederatedAnalyticsSession`, `EnterpriseIntegrationConfig`, `ConditionalDisclosure`, `ProgressiveDisclosure`, `PrivacyInheritanceRule`, `CrossNetworkPrivacyConfig`, `MetadataProtectionLevel`, `ExecutionDagTracer`.

Enum variants named in the whitepaper are present too (verified as variants, not top-level types): `EdgeDelivery`, `MultiPartyComputation` (`TeeServiceType`); `LowestLatency`, `HighestSecurity`, `GeographicProximity` (`AllocationStrategy`); `CommitmentOnly`, `ProofGated`, `SelectiveField`, `FullToAuthorized`, `WithAntiSnooping`, `InheritFromContext` (privacy enums); `MarketBased` (economics); `MaxOfComponents` (metadata level).

**Conclusion:** no missing whitepaper capabilities at the type/vocabulary level. The whitepaper↔code alignment work from prior sessions is verified thorough. (Naming/doc *alignment* — the `TYPICAL_CONFIRMATION_MS_*` etc. renames — is tracked separately in `02_PENDING_WHITEPAPER_ALIGNMENT.md`; those three re-applications are still outstanding.)

---

## 2. Redundancy audit — near-clean

- **Duplicate `mod tests`**: none remain (5 were fixed in Milestone 1 — see `07_BUILD_FIX_LOG.md`).
- **Duplicate type definitions within a crate**: exactly one — **`ApiError`** in `aevor-api`, defined as *both* a `struct` (`types/mod.rs:19` — `{ code, message }`, a wire error body) *and* an `enum` (`lib.rs:128` — the crate's `Result` error type). They live in different modules so it compiles, but the shared name is a real hazard. **Recommendation:** rename the struct to `ApiErrorResponse` (or `ErrorBody`) to disambiguate from the crate error enum.
- **Duplicate type definitions across crates**: none (the shared vocabulary lives once in `aevor-core`).

---

## 3. Cleanliness — clean

Release build: **zero warnings.** Clippy (workspace): **~14 trivial lints**, all auto-fixable with `cargo clippy --fix`. Full list with locations:

| Lint | Location |
|------|----------|
| doc missing backticks (×2) | `aevor-core/src/privacy/mod.rs:760` |
| `impl` can be derived | `aevor-core/src/consensus/mod.rs:106` |
| decimal literal for bitwise op | `aevor-crypto/src/keys/mod.rs:34` |
| manual `is_multiple_of` | `aevor-crypto/src/merkle/mod.rs:54` |
| doc missing backticks | `aevor-tee/src/service/mod.rs:176` |
| `map_or` can be simplified | `aevor-tee/src/service/mod.rs:180` |
| `map_or` can be simplified | `aevor-consensus/src/security_levels/mod.rs:122` |
| cast `u32→f64` via `From` | `aevor-consensus/src/security_levels/mod.rs:203` |
| identical match arms | `aevor-consensus/src/slashing/mod.rs:80` |
| manual `is_multiple_of` | `aevor-consensus/src/checkpoint/mod.rs:70` |
| all fields share prefix `current` | `aevor-consensus/src/timing/mod.rs:16` |
| missing `# Errors` doc | `aevor-faucet/src/faucet/mod.rs:43` |

None affect behavior. Suggested: run the auto-fix as a single cleanup commit, then add `#![deny(warnings)]` in CI to hold the line.

---

## 4. Orphaned public types — 10 (defined, never referenced)

Of 1,196 public types, only 10 appear exactly once in the entire codebase (defined but referenced nowhere, not even tests). Categorized by what they signal:

### 4a. Missing connections (capability defined but not wired) — review & wire
| Type | Location | Signal |
|------|----------|--------|
| **`AccountState`** | `aevor-core/src/state/mod.rs:255` | The **only** account type — full and correct (`address, balance, nonce, owned_objects, has_contract, staked_amount`) — but not integrated into storage/execution. Account state isn't tracked by the state machine. **Most significant orphan.** |
| `CrossContractExecution` | `aevor-execution/src/cross_contract/mod.rs:5` | Cross-contract call type (§12 capability) defined but never used → cross-contract execution path not wired. |
| `GraphQlServer` / `GraphQlConfig` | `aevor-api/src/graphql/mod.rs:3-4` | GraphQL API surface exists as a unit struct but is never started (node doesn't wire GraphQL). API surface incomplete. |
| `HandshakeMessage` | `aevor-network/src/protocol/mod.rs:9` | P2P handshake message defined but unused → handshake/protocol not wired (relates to B10 transport). |
| `ValidatorAdmission` | `aevor-governance/src/validator_governance/mod.rs:5` | Validator-admission governance type unused → admission flow not wired. |

### 4b. Future-telemetry holders (defined for later, low priority) — keep or wire when telemetry lands
`FaucetMetrics` (`aevor-faucet/metrics`), `NetworkMetricSummary` (`aevor-metrics/network`), `SecurityMetrics` (`aevor-security/metrics`), `ValidatorRateRecord` (`aevor-faucet/validator_coordination`). These are consistent metrics/record structs staged for telemetry that isn't collected yet. Not harmful; wire when the corresponding telemetry is implemented, or defer explicitly.

---

## 5. THE INTEGRATION GAP — connections not utilized

This is the core finding of the "all connections are utilized" question.

### 5.1 How the architecture is *meant* to connect
`aevor-core` (9,088 LOC) is a shared **type + trait** substrate. It defines 14 behavioral traits — `Verifiable`, `MathematicallyVerifiable`, `TeeCompatible`, `BlockchainObject`, `Parallelizable`, `PrivacyAware`, `Attestable`, `Committable`, `Executable`, `Metered`, `Serializable`, `StateAccessible`, `NetworkPropagatable`, `CrossPlatformConsistent` (+ `EconomicPrimitive`). Every crate depends on `aevor-core` and implements its slice against these shared types. **At this level, integration is complete and consistent** — everything speaks one vocabulary.

### 5.2 What's actually missing: service composition
The crates implement against core, but they are **not composed with each other**, and nothing composes them into a running node. Measured directly (which crates import each implementation crate):

| Implementation crate | Directly used by |
|----------------------|------------------|
| `aevor-crypto` | client, storage, tee, zk |
| `aevor-consensus` | security only |
| `aevor-tee` | client only |
| `aevor-dag` | **no one** |
| `aevor-vm` | **no one** |
| `aevor-storage` | **no one** |
| `aevor-execution` | **no one** |
| `aevor-network` | **no one** |
| `aevor-zk` | **no one** |

`aevor-execution` — the crate that *should* orchestrate execution — imports **only from `aevor-core`**: zero references to `aevor-vm`, `aevor-dag`, `aevor-storage`, or `aevor-tee`. It runs on core's abstract types, not the real subsystems.

> **Milestone 3 update:** partially addressed. `aevor-execution` now wires `aevor-dag` + `aevor-crypto` + `aevor-storage` via the new `composed` module (see `07`/register integration note) — its unused-dep count dropped 6 → 3 (consensus/tee/vm remain). The first island bridge is built; the pattern now extends to the rest of §6.

### 5.3 The node is a lifecycle skeleton
`node` declares dependencies on **all 21 crates** but its code imports from **`aevor-core` only** (4 references). `NodeOrchestrator::start()` sets `state = Running` and returns a handle with `tee_platforms: Vec::new()`; `FullNode::start()` sets `running = true`. **No subsystem is instantiated or run.** The node models modes/handles/lifecycle correctly, but does not assemble a blockchain.

### 5.4 Unused declared dependencies (the missing wiring, quantified)
Every crate below declares aevor dependencies it never references — the exact edges that need to be wired (or removed):

| Crate | Unused declared aevor-deps |
|-------|----------------------------|
| **node** | api, bridge, cli, client, config, consensus, crypto, dag, execution, faucet, governance, metrics, move, network, ns, security, storage, tee, vm, zk (**20**) |
| **aevor-execution** | consensus, crypto, dag, storage, tee, vm (**6**) |
| **aevor-api** | consensus, crypto, execution, storage, tee (**5**) |
| aevor-bridge | consensus, crypto, tee, zk (4) |
| aevor-governance | consensus, crypto, tee, zk (4) |
| aevor-cli | client, core, crypto (3) |
| aevor-move | crypto, storage, tee (3) |
| aevor-vm | crypto, storage, tee (3) |
| aevor-consensus, dag, faucet, metrics, network, ns, security | 2 each (typically crypto + tee) |
| aevor-storage, aevor-zk | 1 each (tee) |

**Two categories inside this table:**
- **(A) Redundant deps — cleanup.** Many crates reach crypto/tee *types* via `aevor-core` re-exports and don't need the direct dep. These can be removed to cut build time, OR (more likely correct) they should be wired to call the *real* crypto/tee implementations instead of using core's type placeholders.
- **(B) Missing service wiring — build it.** `node` (20), `aevor-execution` (6), `aevor-api` (5) are the load-bearing ones: the node must instantiate and run subsystems; execution must call VM/DAG/storage/TEE; the API must query consensus/execution/storage.

### 5.5 Why this matters / how it connects to the register
This gap is the **structural root** of several simulations in `01`:
- **B4** (consensus `content_hash` returns `Hash256::ZERO`; `finality_proof: None`) ↔ consensus doesn't call `aevor-crypto` (unused dep) → no real hashing/BLS.
- **B5** (storage RocksDB/Merkle placeholders) ↔ storage is used by no one → never exercised in a real pipeline.
- **B10/B11** (client transport / attestation) ↔ tee used only by client, network used by no one → transport/attestation not composed.

Fixing the integration wiring and the register swap-ins are **complementary**: wiring without real implementations gives a running system on placeholders; real implementations without wiring gives tested components that don't run together. Production needs both.

---

## 6. Connections needed — the wiring map

The concrete edges to build, in dependency order (each consumes the ones above). This is the PATH 6 integration that was deferred.

1. **Storage is the substrate.** Wire `aevor-storage` (real backend, B5) so state has a home. Integrate `AccountState` (orphan 4a) into the state store so accounts are tracked.
2. **Execution composes the core loop.** `aevor-execution` calls: `aevor-dag` (dependency analysis + topo order, B6) → `aevor-vm` (execute accepted txs) → `aevor-storage` (read/write state) → `aevor-tee` (attest execution, B3). Wire `CrossContractExecution` (orphan 4a) here.
3. **Consensus drives finality.** `aevor-consensus` calls `aevor-crypto` for real `content_hash`/`finality_proof` (B4) and consumes execution results; couples to `aevor-tee` attestations for PoU.
4. **Network moves data.** `aevor-network` wired for block/tx propagation + the `HandshakeMessage` protocol (orphan 4a); provides the transport `aevor-client` needs (B10).
5. **API exposes the node.** `aevor-api` (REST/gRPC/WebSocket/**GraphQL**) queries consensus/execution/storage; wire `GraphQlServer` (orphan 4a).
6. **The node orchestrates all of it.** `node`'s `NodeOrchestrator`/`FullNode`/`ValidatorNode`/`LightNode` instantiate the above subsystems per mode and run them — replacing the current flag-flipping skeleton, and consuming the 20 currently-unused deps.
7. **Governance/bridge/faucet/ns** hang off the running node (validator admission via `ValidatorAdmission`, cross-chain via bridge, etc.).

Each edge is a composition step against interfaces that already exist — not new design.

---

## 7. Cleanliness maintenance rules (to hold going forward)

1. **CI grep-gate** rejecting new non-test `TODO`/`FIXME`/`unimplemented!`/`todo!`/`mock`/`stub`/`placeholder`, and duplicate `mod tests` in a file (the Milestone-1 damage class).
2. **`#![deny(warnings)]` + clippy in CI** once the ~14 lints are auto-fixed.
3. **Dependency hygiene:** as each wiring edge lands, remove the corresponding unused dep (or wire it). Target: zero unused declared deps. Consider `cargo-machete`/`cargo-udeps` in CI to enforce.
4. **No new orphan public types:** a `pub` type should be referenced by something (impl, use, or test) in the same PR that adds it.
5. **One name, one type:** resolve `ApiError`; forbid re-introducing duplicate type names across a crate.
6. **Integration tests at the node level** (currently the node only has lifecycle unit tests) once §6 wiring exists — these are what prove the connections are utilized.

---

## 8. Cross-reference: updates to the other docs

- `03_PRODUCTION_READINESS_CHECKLIST.md` — updated to add the **integration layer as the top-priority mainnet gate** (§ new). The per-crate "ready pending swap-in" statuses remain, but a crate being green-in-isolation no longer implies it's connected.
- `01_STUB_AND_SIMULATION_REGISTER.md` — B4/B5/B10/B11 are now annotated as *also* requiring the wiring in §6 here, not just the local swap-in.
- `00_CODEBASE_OVERVIEW.md` §4 verdict — the "interface-faithful, drop-in replacements" characterization is accurate for the *components*; this audit adds that the *composition* of those components is the larger remaining task.
- `CHANGELOG.md` — this audit is recorded as the Milestone-2 (audit) entry; the wiring work becomes subsequent milestones.

---

## 9. One-paragraph verdict

The whitepaper is fully represented in the code, the code is clean and non-redundant, and every component speaks a single consistent type vocabulary through `aevor-core`. What does not yet exist is the **assembly**: the implementation crates are individually real and tested but are largely islands, and the `node` that should compose them into a running blockchain is still a lifecycle skeleton. This is the deferred PATH 6 integration, it is the structural reason several register items read as "simulated," and it — together with the register swap-ins — is the real distance between this codebase and a deployable node. None of it requires new architecture; it requires wiring the edges in §6 against interfaces that already exist.
