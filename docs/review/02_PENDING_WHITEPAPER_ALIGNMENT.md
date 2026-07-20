# AEVOR — Whitepaper-Alignment Status & Pending Re-Applications

**Why this document exists:** you flagged that a sandbox reset may have dropped edits from the most recent session before this archive was zipped. That concern is **correct and specific**. This document verifies, identifier by identifier, which alignment work survived into `AEVOR.zip` and which did not — and gives the exact old→new text for the three edits that need re-applying.

**No edits were applied.** These are captured for deliberate re-application.

---

## 1. Bottom line

> **STATUS (Milestone 5): all three re-applications are DONE.** §3.1 (`TYPICAL_CONFIRMATION_MS_*` in aevor-core), §3.2 (`DEFAULT_BATCH_SIZE` in aevor-storage), and §3.3 (`AUDIT_LOG_MAX_ENTRIES` doc in aevor-security) are applied and verified (`cargo test --workspace` green, clippy clean). The sections below are retained as the record of what was changed.

The large structural alignment work from prior sessions **survived intact**. Only **three small edits from the last session were missing** from this archive — all three are naming/doc-clarity changes, none is structural, and none is cross-referenced anywhere else (so re-applying them was safe and self-contained). **All three are now re-applied (Milestone 5).**

| Flag group | What it was | In this archive? |
|------------|-------------|:----------------:|
| **R1–R8** | Speculative-execution/rollback modules *transformed* to pre-execution conflict rejection | ✅ Present |
| **R9–R11** | MVCC "retry" → "rejected; sender may resubmit" | ✅ Present |
| **C1–C7** | `MAX_CONCURRENT_PRODUCERS_*` / `MAX_PARALLEL_*` / `MAX_BLOCK_PARENTS` → `DEFAULT_*` | ✅ Present |
| **N1** | "predictive prefetching" → "topology-aware dependency propagation" | ✅ Present |
| **T1** | `TX_EXECUTION_TIMEOUT_MS` → `DEFAULT_TX_EXECUTION_TIMEOUT_MS` | ✅ Present |
| **§7/8 consensus** | `CONFIRMATION_MS_*` → `TYPICAL_CONFIRMATION_MS_*` in **aevor-consensus** | ✅ Present |
| **P1 / §18 core** | Same rename in **aevor-core** | ❌ **Missing** — see §3.1 |
| **§17/21 storage** | `MAX_BATCH_SIZE` → `DEFAULT_BATCH_SIZE` | ❌ **Missing** — see §3.2 |
| **§19 security** | `AUDIT_LOG_MAX_ENTRIES` doc clarification | ❌ **Missing** — see §3.3 |

---

## 2. What survived (verified in this archive)

### R-series — speculative→pre-execution (present)
- `aevor-dag/src/speculative/mod.rs` exposes `PreExecutionDecision`, `ConflictFreeSet`, `PreExecutionBatch` (re-exported from `aevor-dag/src/lib.rs:136`). The old speculative-execution semantics are gone; the module is now pre-execution conflict analysis.
- `aevor-execution/src/rollback/mod.rs` exposes `RejectionReason` with variants `OutOfGas`, `PrivacyViolation`, `ExecutionFailed`, and crucially `PreExecutionConflict` ("conflict detected BEFORE execution"). No `RolledBack` / `SpeculativeConflict` variants remain.

### C-series — DEFAULT_* naming (present)
`aevor-dag/src/lib.rs` defines `DEFAULT_PRODUCERS_SMALL_NET = 8`, `DEFAULT_PRODUCERS_MEDIUM_NET = 24`, `DEFAULT_PRODUCERS_LARGE_NET = 32`, `DEFAULT_MAX_BLOCK_PARENTS = 32`, `DEFAULT_PARALLEL_LANES = 256`. A test comment even records the intent: *"`DEFAULT_MAX_BLOCK_PARENTS` is a per-node propagation budget, not a ceiling."* This is exactly the whitepaper's no-ceiling framing.

### T1 — execution timeout (present)
`aevor-execution/src/lib.rs:194` → `DEFAULT_TX_EXECUTION_TIMEOUT_MS = 5_000`.

### N1 — topology-aware language (present)
`aevor-network` uses "topology-aware dependency propagation" throughout (`lib.rs:11,13,34,53,328`, `routing/mod.rs:1,96`). No "predictive prefetch" language remains — validators *proactively receive blocks from DAG parents* (valid network-layer data delivery), not speculative state prefetch.

---

## 3. What's missing — the three pending re-applications

Each is presented as an exact find→replace. All three are self-contained: a workspace-wide grep confirms **none of these identifiers is referenced by any other crate** (only by each constant's own module tests), so renaming cannot break a downstream call site.

### 3.1 · aevor-core — `CONFIRMATION_MS_*_MAX` → `TYPICAL_CONFIRMATION_MS_*`
**File:** `aevor-core/src/lib.rs`, lines ~263–273.
**Problem:** the doc-comments call these a *"Confirmation time **ceiling**"* and the names carry `_MAX`. Both imply a ceiling. These are measured, hardware-dependent estimates — and `aevor-consensus` already uses the corrected `TYPICAL_CONFIRMATION_MS_*` names, so `aevor-core` is now the lone inconsistency.

Replace:
```rust
/// Confirmation time ceiling for minimal security in milliseconds.
pub const CONFIRMATION_MS_MINIMAL_MAX: u64 = 50;

/// Confirmation time ceiling for basic security in milliseconds.
pub const CONFIRMATION_MS_BASIC_MAX: u64 = 200;

/// Confirmation time ceiling for strong security in milliseconds.
pub const CONFIRMATION_MS_STRONG_MAX: u64 = 800;

/// Confirmation time ceiling for full security in milliseconds.
pub const CONFIRMATION_MS_FULL_MAX: u64 = 1_000;
```
With:
```rust
/// Typical confirmation time for minimal security in milliseconds
/// (measured on reference hardware; not a guaranteed bound or ceiling).
pub const TYPICAL_CONFIRMATION_MS_MINIMAL: u64 = 50;

/// Typical confirmation time for basic security in milliseconds
/// (measured on reference hardware; not a guaranteed bound or ceiling).
pub const TYPICAL_CONFIRMATION_MS_BASIC: u64 = 200;

/// Typical confirmation time for strong security in milliseconds
/// (measured on reference hardware; not a guaranteed bound or ceiling).
pub const TYPICAL_CONFIRMATION_MS_STRONG: u64 = 800;

/// Typical confirmation time for full security in milliseconds
/// (measured on reference hardware; not a guaranteed bound or ceiling).
pub const TYPICAL_CONFIRMATION_MS_FULL: u64 = 1_000;
```
**Also update** the three ordering assertions in `aevor-core/src/lib.rs` tests (lines ~342–344) that reference the old names, e.g. `CONFIRMATION_MS_MINIMAL_MAX < CONFIRMATION_MS_BASIC_MAX` → `TYPICAL_CONFIRMATION_MS_MINIMAL < TYPICAL_CONFIRMATION_MS_BASIC`. (These mirror the assertions already present and passing in `aevor-consensus/src/lib.rs:290–292`.)

---

### 3.2 · aevor-storage — `MAX_BATCH_SIZE` → `DEFAULT_BATCH_SIZE`
**File:** `aevor-storage/src/lib.rs`, line ~231.
**Problem:** batch size is a per-node throughput/resource decision, not an architectural ceiling — same class as the `DEFAULT_*` constants already corrected in `aevor-dag`. The neighboring `DEFAULT_CACHE_CAPACITY` already models the right pattern (its doc says *"No architectural ceiling exists"*).

Replace:
```rust
/// Maximum batch size for bulk operations.
pub const MAX_BATCH_SIZE: usize = 10_000;
```
With:
```rust
/// Default batch size for bulk operations.
///
/// This is a per-node throughput tuning parameter, not an architectural
/// ceiling. Nodes may configure larger batches as resources allow.
pub const DEFAULT_BATCH_SIZE: usize = 10_000;
```
No other crate references `MAX_BATCH_SIZE` (verified), so no downstream update is needed beyond this crate's own tests if any assert on the name.

---

### 3.3 · aevor-security — `AUDIT_LOG_MAX_ENTRIES` doc clarification (keep the name)
**File:** `aevor-security/src/lib.rs`, line ~211.
**Nuance — this one is different:** `AUDIT_LOG_MAX_ENTRIES` is a **legitimate safety bound** (a rotation threshold), *not* a throughput ceiling. Per the architecture rules, safety limits **keep** `MAX_*` naming. So the last-session edit here was **only a doc clarification**, not a rename.

Replace:
```rust
/// Maximum audit log entries before rotation.
pub const AUDIT_LOG_MAX_ENTRIES: usize = 1_000_000;
```
With:
```rust
/// Audit-log rotation threshold: the number of entries retained before the
/// log rotates. This is an operational retention bound (bounding memory/disk
/// for the in-memory audit ring), NOT a throughput ceiling — it does not
/// limit how many events the system can process or record over time.
pub const AUDIT_LOG_MAX_ENTRIES: usize = 1_000_000;
```

---

## 4. Consistency invariants to re-check after re-applying

Once the three edits are back in, confirm these still hold (they define the whitepaper alignment and should be part of CI going forward):

1. **No throughput-ceiling naming.** Grep for `MAX_` across all crates; every surviving `MAX_*` must be a security/safety bound (message size, object size, stack depth, byzantine fraction, audit rotation, batch *default* now renamed) — each with a doc line clarifying it is not a throughput ceiling.
2. **Confirmation constants aligned.** `aevor-core` and `aevor-consensus` both use `TYPICAL_CONFIRMATION_MS_*`; no `CONFIRMATION_MS_*_MAX` remains anywhere.
3. **No speculative/rollback vocabulary in identifiers or user-facing docs.** Rejection, not rollback; resubmission is application-layer.
4. **No "predictive prefetch"** language — only "topology-aware dependency propagation."
5. **All performance figures framed as measured reference floors**, never guarantees or ceilings (already true in `README.md` and `WHITEPAPER.md`).

---

## 5. Relationship to the simulation register

The items here are **orthogonal** to `01_STUB_AND_SIMULATION_REGISTER.md`. These three are naming/doc alignment (whitepaper consistency); the register items are implementation swap-ins (real crypto/I/O). A crate is not "done" until **both** its register items are addressed **and** these alignment invariants hold.
