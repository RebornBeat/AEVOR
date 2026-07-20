# AEVOR — Real Benchmarks & Honest Readiness Assessment

You asked me to confirm everything is finalized — no stubs, no placeholders, TEE ready, testnet/beta-mainnet/devnet all wired. I'm not going to rubber-stamp that, because it isn't true yet, and you've been clear you want the honest version. This document gives you (1) the **real measured numbers**, and (2) a **component-by-component readiness verdict** with the specific blockers.

Bottom line up front: **the pure-software core is in good shape and measures well; the hardware-trust layer (TEE) is still simulation, and a few subsystems are still placeholders.** That means **devnet-ready today, testnet-ready for everything *except* real TEE validators, and *not* beta-mainnet-ready** until the items in §3 are closed. **Update:** two former blockers (default BLS finality wiring, and the PoU verify-by-attestation fast path) are now **done + measured** this milestone; the dominant remaining blocker is real TEE hardware attestation (§3.1).

---

## 1. Real measured benchmarks

All numbers are **debug build, single machine, in-process** unless stated. They are honest floors, not marketing numbers — release + networked figures are **not yet captured** (that is itself an open item, §3).

### 1.1 Execution throughput — flat (uncapped shape), measured to 100k txs
Full write path per tx: verify → DAG conflict check → VM execute → persist → incremental Merkle commit.

| txs | time | throughput |
|----:|-----:|-----------:|
| 1,000 | 68 ms | 14,635 tx/s |
| 5,000 | 359 ms | 13,912 tx/s |
| 10,000 | 708 ms | 14,121 tx/s |
| 25,000 | 1,809 ms | 13,818 tx/s |
| 50,000 | 3,514 ms | 14,228 tx/s |
| 100,000 | 7,191 ms | 13,906 tx/s |

**Flat within noise across a 100× batch increase.** This is the payoff of the M21 O(n)-conflict + incremental-Merkle work: per-tx cost is constant, so throughput doesn't degrade with volume. Release build is expected to multiply this ~10–30× (not yet measured).

### 1.2 BLS aggregate finality verification — O(1), measured to 50,000 validators
All validators sign one block hash; proposer aggregates to one signature; committee caches its aggregate public key; each proof verifies in one pairing check.

| validators | per-block **verify** | aggregate (amortized) | key precompute (amortized) |
|-----------:|---------------------:|----------------------:|---------------------------:|
| 128 | 1,497 µs | 9.6 ms | 13.1 ms |
| 1,024 | 1,443 µs | 76.6 ms | 108.2 ms |
| 10,000 | 1,325 µs | 772.3 ms | 1,046 ms |
| 50,000 | 1,267 µs | 4,033 ms | 5,195 ms |

**Verification is flat (~1.3 ms) from 128 to 50,000 validators** — no degradation as the set grows. This is the concrete decentralization advantage over a capped ~100-validator BFT set. *(Caveat: this is the verification bound, which was the O(N) problem; wire-gathering of signatures across a live network is a separate networking cost. Also: this primitive is proven but not yet the default finality path — see §3.)*

### 1.3 Post-quantum wire bloat — classical vs ML-DSA-65 vs hybrid (NEW)
Identical transaction payload, different signature scheme; bincode-serialized `SignedTransaction`.

| scheme | tx wire size | vs classical |
|--------|-------------:|-------------:|
| Ed25519 (classical) | 380 bytes | 1.0× |
| ML-DSA-65 (post-quantum) | 5,545 bytes | **14.6×** |
| Hybrid (Ed25519 + ML-DSA-65) | 5,641 bytes | 14.8× |

**PQ signatures bloat a transaction ~14.6×** (+5,165 bytes each). At 100k tx/block that is **~493 MB of extra signature data per block** for PQ alone. Implication for strategy: do **not** default everything to PQ over the wire — the bandwidth/storage cost is severe. The right posture is what the code already supports (crypto-agility): classical Ed25519 by default, PQ/hybrid opt-in for high-value or long-lived accounts, and a migration path when quantum threat is imminent. This measurement is the argument for that posture, quantified.

### 1.4 What is NOT yet measured (honest gaps)
- **Release-build** throughput (the real headline number).
- **Networked, multi-node** throughput incl. gossip propagation (M19 `TcpTransport`) and end-to-end finality latency under load.
- **The PoU re-execute-vs-verify comparison** (needs the verify-by-attestation path, §3) — the plot that would empirically prove the PoU advantage.
- **A dedicated VM microbenchmark.** The VM is exercised inside §1.1 (a `Ld,Ld,Add` program per tx), but a compute-heavy per-opcode throughput number for dApp workloads is not yet isolated.
- **Confidential-transfer overhead** (TEE + Bulletproofs range proof) head-to-head vs a transparent transfer.

---

## 2. What IS real (verified this session and prior)
- **Execution pipeline**: real conflict rejection (O(n)), real parallel execution (rayon), real VM, real durable storage (log-structured), real incremental Merkle **leaf** hashing.
- **Classical crypto**: Ed25519, BLAKE3/SHA-2/SHA-3, ChaCha20Poly1305, AES-256-GCM — all real, vetted crates.
- **Post-quantum**: ML-DSA-65 (FIPS 204 via `fips204`) and Ed25519+ML-DSA **hybrid** — real (confirmed by §1.3 sizes). *(A stale "Dilithium stub" comment was removed this session; the implementation is real ML-DSA.)*
- **BLS12-381 aggregation**: real aggregate + **O(1) verify** primitive, measured (§1.2).
- **Range proofs**: real Bulletproofs (M20) — confidential amounts work.
- **Both transports**: real gossip `TcpTransport` (M19) and real client `TcpNodeConnection` + `NodeServer` (M22).
- **DNS**: real recursive resolution + DNSSEC via `hickory-resolver` (M23).
- **Merkle proofs**: real inclusion proofs, canonically shared prover/verifier.
- **Deployment model**: `DeploymentMode` (public / enterprise-subnet / hybrid) is real config; feeless-subnet economics is specified.

---

## 3. What is NOT finalized — the blockers, by severity

### 🔴 Blocking for real TEE testnet / beta-mainnet
1. **TEE attestation is SIMULATION on all five platforms.** SGX, SEV, TrustZone, Keystone, and Nitro all run in simulation mode (`is_production: false`, `aevor-<platform>-simulation-v1:` seeds). The sealing/verification *logic* is real and the attestation *shape* is correct, but there is **no genuine hardware attestation** — the well-known `SIM_ATTESTATION_SEED` provides no real hardware trust. **You cannot meaningfully test real TEE validators until each platform's real SDK/quoting path is integrated.** This is the single biggest gap between "runs" and "is AEVOR." It is the #1 item.
2. **~~Default finality still uses the BLAKE3 placeholder aggregate.~~ RESOLVED (this milestone).** `CommitteeMember` now carries a BLS consensus key; `finalize_block` aggregates every validator's BLS signature into one and **verifies it in O(1)** against the committee aggregate key, reporting `bls_verified` in `FinalityOutcome`. The e2e finality tests assert it. The no-degradation property is now *live* in the default path, not just demonstrated. (Minor cleanup remains: retire the legacy Ed25519 per-validator collection in favour of BLS-only votes.)

### 🟠 Blocking for beta-mainnet (not for devnet)
3. **ZK beyond range proofs is stubbed.** Bulletproofs are real, but the **Groth16** prover returns a 192-byte placeholder and **Halo2** is a ~1,200-byte stub. Any feature depending on general ZK (not just confidential amounts) is not real yet.
4. **~~Interior sparse Merkle tree is a flat-hash placeholder.~~ DONE as a real component (this milestone).** `SparseMerkleTree` is now a genuine 256-deep sparse Merkle tree with **O(depth) insert/update/prove/verify** (measured flat ~30 µs prove/verify from 1k→100k keys), tested including order-independent roots. Remaining decision (not a defect): whether to make it the engine's *default* state tree — a deliberate tradeoff, since the current sorted-leaf prover is O(n) but batch-optimal (the flat ~14k tx/s). Delivered ready to wire where the workload is proof-heavy or single-key-update-heavy.
5. **Feeless-subnet economics not verified end-to-end.** The `DeploymentMode`/config exists and the whitepaper specifies feeless permissioned subnets, but the fee/feeless switch has not been audited through to transaction admission. Must confirm before advertising feeless subnets.
6. **Transaction-root uses an XOR placeholder** in one storage path (`aevor-storage/src/transactions`) rather than a full Merkle root.

### 🟡 Designed, not built (performance upside, not correctness)
7. **~~The PoU verify-by-attestation fast path is specified but not implemented.~~ BUILT + MEASURED (this milestone).** `NodeEngine::produce_attested_batch` (producer executes once + attests) and `apply_attested_batch` (verifier checks the attestation + applies the delta, no VM, no per-tx sig check) are implemented, round-trip tested, and measured at **48–93× faster than re-executing**. This is the lever that turns the flat single-node number into uncapped *network* throughput. (Uses simulation attestation today; real hardware attestation swaps in behind the same interface — see blocker #1.)

### ⚪ Cosmetic / path-specific (not functional blockers)
8. A zero-signature named constant (used as an explicit sentinel) and a zero `validator_id` placeholder in one slashing path — both intentional sentinels, not missing logic. Worth cleaning up for clarity.

---

## 4. Readiness verdict by environment

| Environment | Verdict | Rationale |
|-------------|---------|-----------|
| **Devnet** | ✅ **Ready** | The pure-software path runs end-to-end: wallet → sign (any scheme) → mempool → conflict-reject → parallel VM → durable persist → Merkle proof → finality → client query over a real socket. 13 e2e tests green. TEE simulation is fine for devnet. |
| **Testnet (general)** | ✅ **Ready** *(with simulated TEE)* | Same path, networked. Usable to exercise consensus, transactions, privacy objects, RPC, DNS. |
| **Testnet (real TEE validators)** | ❌ **Not ready** | Blocked by §3.1 — TEE is simulation on all platforms. This is *the* thing "test TEE validators" requires, and it is not there. |
| **Beta-mainnet** | ❌ **Not ready** | Blocked by §3.1, §3.2, and the 🟠 set (§3.3–3.6). Real value/security cannot rest on simulated attestation, a placeholder finality aggregate, or unverified feeless economics. |

---

## 5. The shortest honest path to each milestone
- **To real-TEE testnet:** integrate one platform's real attestation first (AWS Nitro is usually the least friction), prove a real attested validator, then fan out to SGX/SEV/TrustZone/Keystone. *(This is the biggest single piece of remaining work and deserves its own milestone track.)*
- **To beta-mainnet:** the above, **plus** wire BLS aggregate into default finality (§3.2), make Groth16/Halo2 real or scope them out of v1 (§3.3), real interior sparse Merkle (§3.4), audit feeless economics (§3.5), and capture release + networked benchmarks (§1.4).
- **Then** the PoU fast path (§3.7) for the uncapped *network* throughput story, and the mainnet documentation suite (`aevor-docs/00_MAINNET_DOCUMENTATION_INDEX.md`).

None of this contradicts the architecture — the design is sound and the software core measures well. The gap is honest engineering distance on the hardware-trust layer and a few subsystems, not a flaw in the model.
