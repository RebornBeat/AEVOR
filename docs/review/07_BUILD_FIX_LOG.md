# AEVOR — Build-Fix Log (Milestone 1: Compiles + Tests Green)

This log records the transition of the `AEVOR.zip` archive from **not compiling** to **fully compiling with all tests passing**. It is the companion to the read-only review docs (`00`–`06`) and complements `CHANGELOG.md`.

## Starting state (as received in AEVOR.zip)

The archive **did not compile**. The recorded `aevor-test-results.log` had stopped at a compile failure in `aevor-vm`, and a fresh build revealed multiple crates broken by half-applied edits — the classic signature of the sandbox reset dropping edits mid-transaction (exactly the concern that prompted this review). Additionally, the pinned `rust-version = 1.75` can no longer build the dependency tree.

## Ending state

- `cargo check --workspace` → clean (libs + bins).
- `cargo test --workspace` → **1,546 passed, 0 failed** across 48 test binaries (lib + bin + doc tests).
- Toolchain: builds on current stable (verified on 1.97.1). Requires ≥1.85 (edition2024).

## Environment note — MSRV / toolchain

A transitive dependency (`base64ct` ≥1.8.3, pulled via the crypto stack) now requires Cargo's `edition2024` feature, which stabilized in **Rust 1.85**. The declared `rust-version = "1.75"` in the root `Cargo.toml` is therefore no longer accurate — the workspace cannot build on 1.75. **Recommendation:** bump `rust-version` to at least `"1.85"`. (This log does not change `Cargo.toml`; see CHANGELOG for the tracked recommendation.)

## Root-cause pattern

Every failure was **botched-edit damage**, not a design flaw, and clustered in the modules that were *transformed* in prior sessions (the speculative→pre-execution rejection work). The reset left those edits either duplicated or half-removed. In each case the **production code was correct**; the damage was in duplicated blocks, orphaned test bodies, missing braces, or stale test references.

## The eight fixes

Each fix preserved all capability. Where a removal was involved, the production types were verified to cover every referenced behavior *before* removing anything (per the explicit "ensure we have it in production" requirement).

### 1. `aevor-consensus/src/slashing/mod.rs` — duplicated block (45 errors → 0)
An entire section (`SlashingMechanism` struct + full `impl` with `new`/`double_sign_penalty_bps`/`liveness_penalty_bps`/`double_sign_slash`/`liveness_slash`, plus `SlashingEvidence`/`SlashingEvidenceType`/`SlashingPenalty`/`SlashingProof`/`DoubleSignEvidence`/`EquivocationEvidence`/`LivenessViolation` and a second `mod tests`) was defined **twice**. The first copy (lines 1–317) is a superset (it also defines `ViolationSeverity`/`SeverityClassifier`/`GraduatedSlashingPolicy`). **Fix:** removed the trailing duplicate (lines 318–477). Capability: none lost — the first copy retains everything.

### 2. `aevor-vm/src/parallel/mod.rs` — orphaned test body (brace mismatch → 0)
A test's `#[test] fn …() {` **header was deleted**, leaving its body (a three-disjoint-contracts `conflict_free` test) dangling after the previous test closed. This produced an "unexpected closing delimiter" and an off-by-one brace count. **Fix:** restored the missing header as `fn object_dag_three_disjoint_contracts_are_conflict_free()`. Capability: **restored** a test that had been silently destroyed.

### 3. `aevor-client/src/multi_network/mod.rs` — missing closing brace (unclosed delimiter → 0)
The `mod tests` block was missing its final `}` (opens 58 / closes 57). **Fix:** appended the closing brace. Capability: none lost.

### 4. `aevor-execution/src/speculative/mod.rs` — stale duplicate tests (8 errors → 0)
A second `mod tests` referenced **removed** pre-transformation types (`SpeculativeExecutor`, `ConflictDetectionResult`, `SpeculativeContext`, `CommitOrRollback`). **Before removing**, verified each capability lives in production under the new model:
- conflict detection → `ConflictAnalysisResult { accepted, conflicting_tx }`
- accept/reject + reason → `RejectionReason` enum + `RejectionRecord { transaction, reason, state_root_unchanged }` + `RejectionLog`
- metrics → `ConflictAnalysisMetrics` (with `SpeculativeMetrics` alias)
- `SpeculativeExecutor`/`SpeculativeContext` (accumulate-then-commit/rollback) → **intentionally gone** (the whitepaper forbids speculative execution + rollback).
**Fix:** removed the stale duplicate (also clears register item **B12**, the stale `// stub` comment). Capability: none lost — all preserved under new names or removed by design.

### 5. `aevor-dag/src/speculative/mod.rs` — duplicate tests module (1 error → 0)
Two `mod tests` for the same production types (`PreExecutionDecision`/`ConflictFreeSet`/`PreExecutionBatch`). The second was a **superset** (all 5 tests of the first plus 2 architectural-invariant tests: `rejected_transaction_never_appears_in_accepted_set`, `all_accepted_batch_is_fully_parallel`). **Fix:** removed the first (redundant) block, kept the superset. Capability: **maximized** — retained the stronger test set.

### 6. `aevor-api/src/{middleware,network_routing}/mod.rs` — missing `Default` (7 errors → 0)
`MiddlewareStack` and `MultiNetworkApi` are constructed via `::default()` when building `RestServer`/`GrpcServer`/`WsServer` in tests, but neither derived `Default`. Fields are trivially defaultable (`Option`→None, `bool`→false, `String`→""). **Fix:** added `Default` to the existing `#[derive(Clone)]`. Capability: **added** the missing default-construction the servers rely on.

### 7. `aevor-ns/src/tee_discovery/mod.rs` — invalid enum variants (4 errors → 0)
The discovery test referenced `TeeServiceType::Execution` and `::Attestation`, which do not exist. The canonical `TeeServiceType` (in `aevor-core::tee`) is `Compute`/`Storage`/`EdgeDelivery`/`Analytics`/`Deployment`/`MultiPartyComputation`/`ZkProving`/`Bridge`. **Fix:** mapped the test to two distinct real variants (`Compute`, `Storage`), preserving the discovery-filter intent. Capability: none lost; test now matches the canonical design.

### 8. `aevor-cli/src/main.rs` — required-subcommand parse abort (bin test failure → 0)
Three tests called `Cli::parse_from(["aevor", "status"])`, but `status` requires a subcommand (`node`/`network`/`validators`/`consensus`); clap called `process::exit(2)`, aborting the test binary. **Fix:** supplied a valid subcommand (`["aevor", "status", "node"]`) — the assertions (command type, default network, default output format) are unchanged. Capability: none lost.

## Verification

```
cargo +stable check --workspace   # clean
cargo +stable test  --workspace   # 1,546 passed; 0 failed (48 test binaries)
```

Per-crate lib-test counts after fixes: core 70, config 180, crypto 58, tee 94, consensus 95, dag 69, storage 70, vm 105, execution 59, network 87, security 111, move 27, zk 4, bridge 46, governance 22, ns 27, metrics 4, api (multiple), cli 22+5, faucet 33, node 40, client 97 (plus bin/doc tests → 1,546 total).

## Relationship to the other docs

- These fixes make the codebase **build and test clean** — the prerequisite for the register (`01`) swap-ins and the alignment (`02`) re-applications, which remain outstanding.
- The alignment re-applications (`02` §3.1/3.2/3.3) and register items (B1–B11) are **still pending** — the build being green does not mean production-ready. See `03_PRODUCTION_READINESS_CHECKLIST.md`.
