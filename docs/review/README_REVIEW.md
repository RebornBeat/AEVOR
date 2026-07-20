# AEVOR — Production-Readiness Review (Index)

Read-only review of the AEVOR blockchain codebase against its finalized `WHITEPAPER.md`, `Tokenomics.md`, and `README.md`. **No code was modified.** Everything is captured in the documents below.

**Scope reviewed:** 22-crate Rust workspace + `node` · 272 `.rs` files · 43,497 LOC · 1,541 tests · Rust 2021 / 1.75 · MIT OR Apache-2.0.

## Start here

| # | Document | What it answers |
|---|----------|-----------------|
| 00 | [`00_CODEBASE_OVERVIEW.md`](./00_CODEBASE_OVERVIEW.md) | What is AEVOR, how are the crates organized, what are the canonical designs, what's real vs simulated (summary). |
| 01 | [`01_STUB_AND_SIMULATION_REGISTER.md`](./01_STUB_AND_SIMULATION_REGISTER.md) | **The core artifact.** Every simulated/placeholder item (B1–B12), exact swap-in target, dependency, effort. Plus what *looks* like a stub but isn't, and what's confirmed real. |
| 02 | [`02_PENDING_WHITEPAPER_ALIGNMENT.md`](./02_PENDING_WHITEPAPER_ALIGNMENT.md) | Which prior-session edits survived, and the **three edits lost to the sandbox reset** with exact re-application text. |
| 03 | [`03_PRODUCTION_READINESS_CHECKLIST.md`](./03_PRODUCTION_READINESS_CHECKLIST.md) | Per-crate go/no-go, mainnet-gating items, CI gates, definition of "done." |
| 04 | [`04_REVIEW_NOTES_BY_CRATE.md`](./04_REVIEW_NOTES_BY_CRATE.md) | Per-crate findings for all 22 crates + node. |
| 05 | [`05_TEE_DEVELOPER_GUIDE.md`](./05_TEE_DEVELOPER_GUIDE.md) | All 5 TEE platforms + a step-by-step recipe to **extend to new chips** (new RISC-V / open hardware), anchored on the real backend contract. |
| 06 | [`06_USER_GUIDE.md`](./06_USER_GUIDE.md) | User-facing docs by audience: validators, dApp devs, enterprises/subnets, end users, node operators. |
| 07 | [`07_BUILD_FIX_LOG.md`](./07_BUILD_FIX_LOG.md) | **Milestone 1.** How the archive went from *not compiling* to 1,546 tests passing — the 8 fixes, root causes, capability-preservation checks. |
| 08 | [`08_WHITEPAPER_ALIGNMENT_AND_INTEGRATION_AUDIT.md`](./08_WHITEPAPER_ALIGNMENT_AND_INTEGRATION_AUDIT.md) | **Milestone 2.** Whitepaper coverage (complete), redundancy, cleanliness, and the **integration gap** — the crates are islands and the node is a skeleton. Read this for "are all connections utilized." |
| — | [`CHANGELOG.md`](./CHANGELOG.md) | Scaffold to track remediation as it proceeds, seeded with this baseline. |

## Headline findings

1. **The architecture is fully present and interface-faithful.** The anti-pattern surface is clean: **zero** `TODO`/`FIXME`/`unimplemented!`/`todo!`/`mock` in non-test code. The gap to mainnet is a finite, enumerated set of **drop-in replacements behind already-correct interfaces**, not missing design.

2. **Real today:** Ed25519, BLS12-381, ChaCha20-Poly1305, AES-256-GCM, BLAKE3/SHA-2/SHA-3, the full type/trait surface, DAG edge computation, MVCC, and all config/governance/CLI/API/faucet/node surfaces.

3. **Twelve interface-faithful simulations to swap** (B1–B12): ZK provers, Dilithium PQ half, the 5 TEE attestation backends, consensus content-hash/finality-proof, storage (RocksDB/Merkle/receipt-root), DAG topo-sort, network erasure coding, metrics Laplace noise, NS recursive resolver, and client transport + attestation verifier. Each has a named crate to wire in and an effort estimate.

4. **Your sandbox-reset concern is confirmed and specific.** The big structural alignment work (R/C/T/N series) survived. **Three small edits from the last session did not** land in this archive — all naming/doc changes, none cross-referenced, exact re-application text in doc `02`.

5. **The TEE layer is built to extend.** New silicon is an additive, five-touch change (doc `05`); consensus/VM/execution/storage/client never special-case platforms.

## Suggested next action

Work the ordered remediation in `01` §E and `03` §2 — start with the trivial alignment re-applications (`02`) and the S-effort swap-ins (B6, B4-hash, B12), then the client transport (B10) to unlock end-to-end testing, then storage (B5), then the TEE backends (B3) toward a security-meaningful mainnet. Log each change in `CHANGELOG.md`.
