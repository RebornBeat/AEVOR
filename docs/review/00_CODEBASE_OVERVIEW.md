# AEVOR — Codebase Overview & Architecture Map

**Review type:** Read-only production-readiness review against finalized `WHITEPAPER.md`, `Tokenomics.md`, and `README.md`.
**Archive reviewed:** `AEVOR.zip` → 22-crate Rust workspace + `node`.
**Scale:** 272 `.rs` files, **43,497 LOC**, 1,541 tests (per `aevor-test-results.log`).
**Edition:** Rust 2021, `rust-version = 1.75`, license `MIT OR Apache-2.0`.
**No code was modified during this review.** Every finding is captured in the companion documents in this folder.

---

## 1. How to read this review

This folder contains eight companion documents. Read them in this order:

| # | File | Purpose |
|---|------|---------|
| 00 | `00_CODEBASE_OVERVIEW.md` (this file) | Architecture map, crate-by-crate purpose, canonical designs |
| 01 | `01_STUB_AND_SIMULATION_REGISTER.md` | **Every** simulated/placeholder item, what to swap in, effort — the core artifact |
| 02 | `02_PENDING_WHITEPAPER_ALIGNMENT.md` | Flag-register status + the 3 last-session edits that did **not** survive the archive |
| 03 | `03_PRODUCTION_READINESS_CHECKLIST.md` | Per-crate go/no-go checklist and mainnet gating items |
| 04 | `04_REVIEW_NOTES_BY_CRATE.md` | Per-crate review notes and findings |
| 05 | `05_TEE_DEVELOPER_GUIDE.md` | All 5 TEE platforms + how to extend for new chips (RISC-V / open hardware) |
| 06 | `06_USER_GUIDE.md` | User-facing docs by user type (validator, dApp dev, enterprise, end user) |
| — | `CHANGELOG.md` | Scaffold to track remediation as it proceeds |

---

## 2. The workspace at a glance

AEVOR is organized into **seven build paths** (a strict dependency ordering — each path compiles on the ones before it). This ordering is the canonical build/verification sequence and should be preserved.

```
PATH 0  Foundation ......... aevor-core · aevor-config · aevor-crypto · aevor-tee
PATH 1  Core Blockchain .... aevor-consensus · aevor-dag · aevor-storage · aevor-vm · aevor-execution
PATH 2  Network+Security ... aevor-network · aevor-security
PATH 3  Language+CrossChain  aevor-move · aevor-zk · aevor-bridge
PATH 4  Governance+Naming .. aevor-governance · aevor-ns
PATH 5  External Interface . aevor-metrics · aevor-api · aevor-client · aevor-cli
PATH 6  Final .............. aevor-faucet · node
```

### Per-crate size and role

| Crate | Files | LOC | Role |
|-------|------:|----:|------|
| **aevor-core** | 18 | 9,088 | Primitives, types, traits shared by everything. Largest crate; the type substrate. |
| **aevor-tee** | 14 | 3,254 | TEE abstraction + 5 platform backends (SGX/SEV/TrustZone/Keystone/Nitro) + attestation. |
| **aevor-consensus** | 12 | 2,780 | Proof of Uncorruption engine, security levels, slashing, checkpoints. |
| **aevor-crypto** | 12 | 2,442 | Signatures, encryption, hashing, proofs, post-quantum hybrid keys. |
| **aevor-vm** | 15 | 2,376 | AevorVM Double-DAG execution engine + TEE-secured runtime. |
| **aevor-client** | 11 | 2,307 | SDK: query / transaction / subscription / verification clients. |
| **aevor-storage** | 13 | 2,283 | State store, Merkle, versioned (MVCC), backend abstraction. |
| **aevor-dag** | 11 | 2,170 | Micro-DAG (object conflicts) + macro-DAG (block production) + dependency graph. |
| **aevor-config** | 10 | 2,103 | Network/privacy/deployment configuration types. |
| **aevor-zk** | 14 | 1,554 | ZK proof systems (Groth16/PLONK/STARK/Halo2/Bulletproofs) interfaces. |
| **aevor-execution** | 12 | 1,452 | Transaction execution, pre-execution conflict analysis, rejection log. |
| **aevor-network** | 13 | 1,385 | P2P networking, routing, availability, topology-aware propagation. |
| **aevor-security** | 12 | 1,306 | Security levels, audit log, threat detection, key management. |
| **node** | 13 | 1,303 | Node binary wiring the crates into a runnable validator/full node. |
| **aevor-ns** | 11 | 1,143 | DNS/naming infrastructure (internet-compatible + blockchain-native). |
| **aevor-api** | 13 | 1,083 | External API surface + rate limiting. |
| **aevor-governance** | 11 | 1,023 | On-chain governance, parameters (no hardcoded ceilings). |
| **aevor-faucet** | 10 | 1,022 | Testnet faucet. |
| **aevor-cli** | 13 | 1,019 | Command-line interface. |
| **aevor-move** | 11 | 837 | Move language integration + AEVOR privacy/TEE extensions. |
| **aevor-bridge** | 11 | 833 | Cross-chain bridge. |
| **aevor-metrics** | 12 | 734 | Metrics + differential privacy for telemetry. |

---

## 3. Canonical designs (from WHITEPAPER.md + README.md)

These are the load-bearing architectural commitments. The code, docs, and any future edits must remain consistent with them. Each has already been reflected in the README (verified during this review).

### 3.1 Proof of Uncorruption (PoU)
Mathematical certainty via TEE attestation, **not** probabilistic consensus. Finalized state is **immutable** — never unwound. Stronger than PoW/PoS/BFT because it rests on cryptographic hardware proof rather than economic assumptions.

### 3.2 Dual-DAG
- **Micro-DAG** — object-level dependency analysis. Conflicting transactions are **rejected before execution begins**; no state is ever speculatively applied and rolled back. `dag_parents: Vec<BlockHash>` is unbounded.
- **Macro-DAG** — concurrent multi-producer block production with no leader bottleneck. Corrupted **branches** are isolated from the frontier; finalized transactions are never reversed.

> **Architecture rule (must hold everywhere):** There is **no speculative execution + rollback**. Pre-execution conflict detection *rejects* conflicting transactions. Rejection ≠ rollback. Resubmission is an application-layer choice, never infrastructure auto-retry.

### 3.3 Security Level Accelerator (4 levels)
All figures are **measured estimates on reference hardware**, hardware-dependent, not specs:

| Level | Validators | Confirmation (approx.) |
|-------|-----------|------------------------|
| Minimal | ~2–3% | ~20–50 ms |
| Basic | ~10–20% | ~100–200 ms |
| Strong | >33% | ~500–800 ms |
| Full | >67% | <1 s |

### 3.4 AevorVM — Double DAG
Object DAG (ownership/access mapping) + Execution DAG (attested execution flow). Cross-platform-consistent results across all TEE platforms. Every execution is either a verified result or a rejection — **never a partial commit**.

### 3.5 Mixed Privacy (4 levels, object-level, architecturally enforced)
`Public / Protected / Private / Confidential`, set per object. Privacy violations cause **operation rejection**, never silent downgrade. TEE overhead ≈ **1.1–1.3×** (measured) vs FHE's 1000×–1,000,000×. **AEVOR excludes full homomorphic encryption entirely.**

### 3.6 TEE-as-a-Service (6 service types)
Compute · Storage · EdgeDelivery · Analytics · Deployment · MultiPartyComputation. Validator-provided; failures result in rejection + failover, not degraded delivery.

### 3.7 No artificial throughput ceilings
All TPS/latency figures are **measured floors on reference hardware** that scale unboundedly with resources. Constants that imply throughput ceilings use `DEFAULT_*` naming. Security limits (message size, stack depth, byzantine fraction, audit-log rotation) keep `MAX_*` naming **with clarifying docs** — they are safety bounds, not throughput ceilings.

### 3.8 Economic model
Infrastructure primitives are separated from application policies. Feeless permissioned subnets are supported (`FeePolicy::Free`). Validator rewards split consensus + TEE service + treasury (governance-configurable bps). Total supply 1,000,000,000 AEVOR. All economic figures are measured reference points that adapt with market conditions.

### 3.9 Five TEE platforms
Intel SGX · AMD SEV(-SNP) · ARM TrustZone · RISC-V Keystone · AWS Nitro Enclaves. Behavioral consistency across all. This set is designed to be **extensible** — see `05_TEE_DEVELOPER_GUIDE.md`.

---

## 4. What is real vs. simulated (executive summary)

The codebase is **structurally complete and interface-faithful throughout**. The gap between it and a mainnet build is a well-bounded set of **drop-in replacements**, not missing architecture. Full detail is in `01_STUB_AND_SIMULATION_REGISTER.md`.

**Production-grade and real today (verified via `Cargo.lock` + source):**
- Ed25519 signatures (`ed25519-dalek`)
- BLS12-381 aggregate signatures (`blst`, min-sig)
- ChaCha20-Poly1305 and AES-256-GCM encryption
- BLAKE3 / SHA-2 / SHA-3 hashing
- The entire type system, trait surface, DAG dependency **edge computation**, MVCC versioning, config/governance/CLI/API surfaces.

**Interface-faithful simulations to swap before mainnet (the whole list):**
1. ZK provers (all systems) — structural, return fixed-size proofs.
2. Post-quantum Dilithium half of hybrid keys — BLAKE3 stand-in (Ed25519 half is real).
3. Five TEE attestation backends — simulation reports; real device paths are already probed.
4. Consensus `content_hash` / `finality_proof` — zeroed placeholder / `None`.
5. Storage: RocksDB backend, Merkle proof siblings, transaction receipt root (XOR chain).
6. DAG topological ordering (edges are correct; only the linear order is simplified).
7. Network erasure coding (availability).
8. Metrics Laplace differential-privacy noise.
9. NS recursive resolver + DNSSEC authentication flag.
10. Client transport (HTTP/gRPC/WebSocket) — structure present, wire absent.
11. Client attestation verifier — structural check pending delegation to `aevor-tee`.

**Looks like a stub but is intentional (do not "fix"):**
- "dummy traffic" (cover traffic — a real privacy technique)
- "hardcoded" mentions ×3 (all *document the absence* of ceilings — positive)
- "temporary reward reduction" (a real slashing consequence)
- zero-signature / zero-validator-id placeholders (legitimate zero-value sentinels)
- "fake bytecode" (a test input)

---

## 5. Test & build entry points

- `test_aevor.sh` — workspace test runner.
- `aevor-test-results.log` — last recorded run (1,541 tests).
- `ISSUE_TRACKER.md` — in-repo issue log.
- Build in path order (Section 2) for the cleanest dependency resolution.

---

## 6. One-paragraph verdict

AEVOR is an unusually complete pre-mainnet codebase: the architecture described in the whitepaper is present in the crates, the anti-pattern surface is clean (**zero** `TODO`/`FIXME`/`unimplemented!`/`todo!`/`mock`), and the remaining work is a finite, enumerable set of drop-in cryptographic and I/O implementations behind already-correct interfaces. The two things that need attention before calling any crate "done" are (a) executing the swap-ins in `01_STUB_AND_SIMULATION_REGISTER.md`, and (b) re-applying the three whitepaper-alignment renames that did not survive into this archive (`02_PENDING_WHITEPAPER_ALIGNMENT.md`).
