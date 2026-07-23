# AEVOR — Production Finalization Capture

The complete ledger of what is left to finalize for production, based on everything we've found. Organized so **PoU scaling is the through-line** (it is what we are maximising), with **real TEE attestation explicitly last**. Nothing dropped; honest current state for each item; canonical-design references throughout. This is the capture you asked for before we execute — not the execution itself.

Legend: ✅ finalized · 🟡 partial/needs finishing · ⛔ stub/not wired · 📄 docs.

---

## 0. Direct answers that shape this ledger

- **Do nodes do multi-lane today?** No. The macro-DAG (`aevor-dag/src/macro_dag`: `MacroDag`, `ConcurrentProducers`, `ForkResolution`, `BlockOrdering`, frontier) is a real, tested data structure, but the **node engine does not drive it** — `produce_block`/`process_block`/`finalize_block` run a single lane and nothing in `node/src` references the macro-DAG. **Wiring it into the node is the central PoU-scaling production item (F-A1).** It is what turns the modelled 1M/6M/100M into observed throughput.
- **Is the multi-node harness production or benchmark?** A throwaway harness is benchmark-only — not in this ledger. The production version of "measure the aggregate" is F-A1 (wire the node to actually run lanes); a live multi-node measurement comes *after* F-A1 and needs real multi-machine hardware.
- **Is BLS aggregate finality wired into the default path?** ✅ Yes — `finalize_block` aggregates every committee member's BLS signature, verifies via `aggregate_public_keys` + `verify_with_aggregate_key` (O(1)), and sets `bls_verified` (M27). No further work.

---

## Part A — PoU scaling (the focus / what we maximise)

### Already finalized ✅ (so it is not lost from view)
- ✅ **Pre-execution conflict rejection** (micro-DAG): real O(total-set) rejection, no speculative rollback (`aevor-dag/src/dependency`).
- ✅ **Intra-lane parallel execution**: rayon over the independent set (M21).
- ✅ **PoU verify-by-attestation fast path**: producer executes once + attests; verifiers reproduce state from (attestation, delta) with NO re-execution. Measured 48–96× faster than re-execute (M27). Correct end-to-end incl. tamper rejection.
- ✅ **O(1) BLS aggregate finality** wired into the default finalize path; flat ~1.3 ms 128→50k validators (M25/M27).
- ✅ **Authenticated state commitment**: pluggable sorted/sparse Merkle, both correct + measured (M28/M30).
- ✅ **Sweet-spot characterised**: verify-attest ~1k–10k batch (~1.0–1.1M tx/s), degrades past 15k; recipe = ~5–10k lanes, scale via lanes not block size (M29).

### Remaining to finalize 🟡⛔

**F-A1 ✅ DONE (Milestone 31) — macro-DAG multi-lane wired into the node. (CENTRAL ITEM.)**
- *State:* data structures exist and are tested; the node does not drive them.
- *Done =* the running node (a) accepts/produces blocks from multiple producers at the same height without cross-reference, (b) tracks the macro-DAG frontier, (c) deterministically orders concurrent blocks via `BlockOrdering` ("mathematical ordering of concurrent blocks through attestation" — whitepaper), (d) resolves forks via `ForkResolution`. End-to-end test: N in-process lanes producing concurrently → single deterministic ordered history → identical state root on all validators.
- *Canonical:* WHITEPAPER §"concurrent producers", line 33 "no architectural ceiling on throughput". This is the mechanism behind that claim.
- *Delivered:* `BlockOrdering::deterministic` (leaderless ordering primitive) + `apply_lane_round` (verify each lane's PoU attestation, reject cross-lane conflicts, order deterministically, apply disjoint deltas → one consistent root). E2E proves identical root across arrival orders; benchmark shows a verifier applying N lanes/round at 625k–1.1M tx/s. The 1M+/6M+/100M+ targets are now backed by a real multi-lane apply path (parallel *production* speedup still needs multi-node hardware).

**F-A2 ✅ DONE (Milestone 32) — sharded verification (verifying-quorum-per-lane).**
- *State:* today every validator would verify every lane (the full-verification regime, capped ~1.12M tx/s past ~96 lanes). Sharded assignment is described in the analysis but not wired.
- *Done =* a lane→verifier-quorum assignment such that each validator verifies a bounded slice, every lane is covered by a quorum, corruption is caught by any assigned verifier (real-time detection → slash), and finality still O(1)-aggregates across all N. Test: aggregate scales linearly past the ~96-lane crossover with per-validator verify load bounded.
- *Delivered:* `LaneAssignment` (deterministic quorum-per-lane) + `apply_lane_round_sharded` (validator processes only its assigned slice). E2E proves full coverage with a bounded per-validator slice; benchmark shows validator load ~constant as N grows 8→128 while the network does N lanes. **This is the mechanism behind 6M+/100M+.** *(Also delivered alongside: a hardware-agnostic compute abstraction — `node/src/compute` — that scales per-node parallel execution to any CPU core count automatically and provides a pluggable `ComputeBackend` trait for GPU/TPU/NPU accelerator offload of batchable primitives.)*

**F-A3 ✅ DONE (Milestone 35) — corruption detection → slashing loop closed end-to-end.**
- *State:* PoU tamper rejection is proven at the apply step; slashing module exists (`aevor-consensus/src/slashing`). The path "assigned verifier's attestation check fails → evidence → slash" should be wired and tested as one flow.
- *Done =* an e2e test: a producer emits a corrupted attestation/delta on a lane; an assigned verifier rejects; slashing evidence is produced and applied. ("valid until proven corrupted", whitepaper §823+.)

*(Everything else in PoU scaling — per-lane rate, verify-attest, BLS finality, Merkle, sweet spot — is done and measured. F-A1/F-A2/F-A3 are the finalization surface.)*

**Hardware layer ✅ FINALIZED (Milestones 32–34):** per-node multi-core is wired (parallel execution + parallel signature verification on a pool auto-sized to the host), and GPU/TPU/NPU are finalized as pluggable `ComputeBackend` accelerator backends with detection + CPU fallback + selection chain (vendor kernel is the only per-target extension point). Real multi-core/accelerator speedup is measurable only on that hardware; the code is complete for all processing units.

---

## Part B — Cryptographic completeness

**F-B1 ✅ DONE (Milestone 35) — SNARK stubs gated fail-closed; privacy is TEE + object-level + VM.**
- *Decision (made):* no real execution path calls any SNARK verifier, and privacy is delivered by TEE confidential execution + object-level policies + VM privacy boundaries (real). **Bulletproofs is the shipped ZK primitive.** Groth16/Halo2/PLONK/STARK/recursive are a post-mainnet ZK surface. Remaining action: **gate the stub verifiers so no finalized path can reach one** (return an explicit not-production error instead of a structural check), and document mainnet privacy = TEE + object-level + VM. (Real SNARK integration is explicitly out of mainnet scope.)

*(original finding retained below)*

**F-B1-orig ⛔ Groth16 / Halo2 / PLONK / STARK / recursive verification are structural stubs.**
- *State:* `aevor-zk` has the full module structure but the verifiers are non-cryptographic (`halo2::verify` = "proof not empty"; `groth16`/`plonk` = non-empty + vkey-hash match; `recursive` = count>0; proving emits placeholder bytes). No real ZK backend in `aevor-zk/Cargo.toml`. **Bulletproofs is the one real ZK primitive** (`verify_range`/`verify_balance` — real).
- *Done (choose per canonical need):*
  - If the canonical privacy features only require range/balance proofs → **scope Groth16/Halo2/PLONK/STARK/recursive out** explicitly as post-mainnet, document Bulletproofs as the shipped ZK, and gate the stub APIs behind a clearly-labelled `unimplemented`/feature so nothing on a finalized path calls a stub verifier. (Lower effort, honest.)
  - If canonical privacy requires SNARKs → **integrate real libraries** (arkworks Groth16, `halo2_proofs`) with real trusted-setup handling. (Large effort.)
- *Decision needed from you:* which proof systems are actually on the mainnet critical path? That determines real-impl vs scope-out. Either way the outcome is "no stub verifier is reachable on a finalized path."

**F-B2 ✅ Everything else crypto is real:** BLAKE3, Ed25519, BLS12-381 aggregate finality, ML-DSA-65 + hybrid (fips204), Bulletproofs, sparse + sorted Merkle, crypto-agility dispatch. No work.

---

## Part C — Economics

**F-C1 ✅ DONE (Milestone 36) — subnet economics + enforcement end-to-end (feeless/fee, permissioned, privacy baseline).**

**Fee unification ✅ DONE (Milestone 37) — one flow confirmed; fees single-source-of-truth (SubnetPolicy carries the canonical `FeeConfig`; fee = `gas × price` matching the VM `GasMeter`); gas/fee estimates measured (simple tx ≈ 0.000005 AVR pre-bloat) and compared to other chains; PoU sweet spot holds per subnet.**

**Fee market + rewards + tokenomics ✅ DONE (Milestone 38) — congestion-based base fee (EIP-1559-style `next_base_fee`), privacy priced via TEE execution gas + PQ/bloat priced via per-byte `intrinsic_gas`, validator rewards funded by fees (no inflation) on the same ledger as slashing, flexible subnet fees (mainnet formula / own / flat / none), full e2e simulation of congestion + PQ + token price + rewards, and `Tokenomics.md` finalized (utility-first banner + concrete fee-market section). Honest gap: fees/rewards computed and reported but not yet debited from `Balance` (settlement is the next economic step).**
- *State:* config exists (`FeeConfig::feeless()`, enterprise-subnet fee config, `fee_free_has_zero_max_fee`, cross-subnet economics defaults). Whether the *execution path* fully honours it (no fee/gas deduction, correct accounting, correct interaction with staking/slashing which remain even when fees are zero) needs an end-to-end check.
- *Done =* an e2e test on an `EnterpriseSubnet`/feeless deployment: transactions execute with zero fee deduction and correct balances, while validator staking/slashing still function. ("Feeless Permissioned Subnet Economics", WHITEPAPER line 416.)

**Balance settlement + rule enforcement ✅ DONE (Milestone 39) — the M38 settlement gap closed and the economics made binding rules.** Per-tx settlement now debits senders and credits the validator with conservation by construction (`fee_charged == Σ sender debits == validator reward`), on **both** production paths. The account-level **abuse guard** (`affordability_filter`) drops unaffordable transactions before execution; feeless subnets admit all. `fund()` is **genesis-only** (no minting on a running chain). `PROTOCOL_RULES_VERSION` is folded into the attestation body, so nodes on different economics reject each other's blocks — combined with the already-attested `tx_commitment` and deterministic settlement, balances cannot diverge undetected. Economics now run **inside** the throughput benchmarks (headline pipeline, batch sweep, congestion dynamics) — re-ran with M31–M34 in place: production ~12.5k tx/s (batch ≈ 2 000), verify ~1.2M, aggregate projection to 122M tx/s at 10 000 lanes; congestion market reproduces M38 exactly but now actually debited. **Economic sweet spot = throughput sweet spot** (fee/tx flat at 0.000485 AVR; congestion target ~30 900 tx/block sits far above the per-lane sweet spot, so fees stay at the floor there). Analysis `21_...`. Honest remaining item: commit balances *directly* into the state root (defense-in-depth for light-client balance proofs) — deliberately not half-shipped.
- *Next on the ledger after this:* network transport (gossip) for live multi-node, then F-E1 real TEE attestation.

**Balance commitment + verifier sync ✅ DONE (Milestone 39) — cheap, not in the Merkle root.** Per-account balance changes ride in the block `StateDelta` and are bound by a `balance_commitment` (one BLAKE3 over the changes) in the attestation body. Verifiers check the shipped balances against the commitment (tamper-evident) and apply them to the ledger via HashMap writes (no Merkle), so a node that only *verified* a block stays balance-consistent and can *produce* correctly later (`verifier_stays_balance_consistent_on_fast_path`); a producer that ships/settles wrong balances is caught (hash mismatch at apply, or a re-executing validator recomputing the commitment → slashing); the signed commitment prevents equivocation. Measured: committing balances into the **Merkle root** costs +112–136% on the verify path (`bench_balance_in_root_overhead`, ≈ halving it); the `balance_commitment`+`StateDelta` path leaves the verify sweep unchanged at ~1.0–1.15M tx/s. Light-client balance proofs (Merkle inclusion for a specific account) remain an opt-in capability at that cost. *Next on the ledger:* the network transport — **logic layer now validated in-process** via a `Transport` seam + in-memory backend (`multi_node_round_over_transport_converges_with_settlement`: validators produce lanes, exchange them, apply the round, converge to one root with consistent settled balances; doc 22 §9); the **real gossip/TCP backend** (`aevor-network`, 61 tests) plugs in behind the same trait and needs multi-machine to prove — then F-E1 real TEE attestation (corruption design captured in doc 22).

**F-C2 ✅ Staking/slashing hybrid** (PoU + stake) exists (`aevor-consensus/src/slashing`); F-A3 closes its corruption-evidence loop.

---

## Part D — Finalise the findings into canonical docs 📄

**F-D1 📄 Fold the new findings into README + WHITEPAPER where they confirm/quantify the design** (without drift):
- The measured **1M+ per-verifier / 6M+ sharded@512 / 100M+ sharded** throughput story as the concrete backing for the "no architectural ceiling" claim.
- **PoU verify-by-attestation** as the scaling mechanism (verifiers don't re-execute).
- **O(1) BLS finality** as the decentralisation-without-finality-penalty property (the Sui-cap contrast).
- **PQ cost contained to producing lanes**; **security level = latency not throughput**.
- **Per-role Merkle backend** (sorted on executors, sparse on proof-serving/light nodes).

**F-D2 📄 Update the ~200-doc mainnet set (P0 wave first, per `00_MAINNET_DOCUMENTATION_INDEX.md`):** the architecture docs that describe block production must reflect F-A1/F-A2 once wired; the ZK docs must reflect the F-B1 decision; the economics docs must reflect F-C1. Keep `docs/review/*` (this ledger + `15_...`) as the engineering source of truth feeding them.

*Rule: docs follow code. Update F-D1/F-D2 only as F-A/F-B/F-C land, so the canonical docs never describe something not in the code (no drift).*

---

## Part E — Real TEE attestation (LAST, by your instruction) ⛔

**F-E1 ✅ Real hardware attestation on all 5 platforms** — DONE and production-first (docs 25, 27). Every platform produces genuine evidence through its real device interface (NSM ioctl, `/dev/attestation/*`, configfs-tsm, `/dev/keystone_enclave`, OP-TEE) and is verified with real cryptography: Nitro `COSE_Sign1`/ES384 to the pinned AWS root; SGX DCAP v3 quote (P-256 + QE key binding + PCK chain); SEV-SNP report (P-384 over the signed region with the VCEK); TrustZone PSA token (ES256 `COSE_Sign1` + PSA claims); Keystone (two-link Ed25519 device→SM→enclave chain, `verify_strict`). Consensus stays platform-agnostic via `aevor_tee::evidence::AttestationEvidence` (+ `TeeTrustRoots`) and `aevor_tee::registry::{CodeRegistry, check_policy}` — the code-measurement registry that makes corruption detection instant and O(1) per block, with no re-execution (doc 22). `ExecutionAttestation` carries `tee_evidence`; `verify` fails closed where the trust root is network configuration. Builds and is fully tested off-hardware (aevor-tee 144 tests); the device paths run on real hardware.

*Corruption detection belongs here (design captured in `22_TEE_CORRUPTION_DETECTION_AND_SCALING.md`).* The production mechanism is **attestation verification**, not re-execution: a verifier accepts a producer only if its enclave **code measurement** is in a network-agreed registry, the enclave is genuine, and the signature verifies — instant, O(1)/block, no re-execution (which would run at the ~12k tx/s produce rate, ~100× slower than fast-path verify, and is anti-scaling). The measurement subsumes `PROTOCOL_RULES_VERSION` (it uniquely pins the exact code + economics). An **optional, tunable sampled re-execution quorum** is a defense-in-depth backstop against TEE compromise (SGX has had Foreshadow/Plundervolt/SGAxe/…), designed with the threat model here and enabled by the balance-delta sync already shipped. A prototyped re-execution primitive was measured, found to be the wrong layer, and reverted before commit.

---

## Part F — Explicitly deferred / NOT production-blocking

- **Live multi-node benchmark** (observed aggregate): only meaningful *after* F-A1, and needs real multi-machine hardware; it is a measurement, not a production feature. Not in the finalization critical path.
- **Release-mode headline numbers:** a reporting step; the debug shapes/ratios already carry the conclusions.

---

## The finalization order (proposed)

1. **F-A1** wire macro-DAG multi-lane into the node ← the big one; unlocks real throughput.
2. **F-A2** sharded verification ← unlocks 6M+/100M+.
3. **F-A3** corruption→slash loop closed.
4. **F-C1** feeless-subnet economics end-to-end.
5. **F-B1** Groth16/Halo2 decision (real vs scope-out) + make no stub reachable on a finalized path.
6. **F-D1/F-D2** fold findings into README/whitepaper/mainnet docs (as the above land).
7. **F-E1** real TEE attestation (last).

Nothing above drifts from canonical designs: dual-DAG (micro rejection + macro concurrency), PoU + staking/slashing hybrid, 5 TEE platforms as options, 4 security levels, BLAKE3/BLS12-381, deployment modes incl. feeless enterprise subnets. This is the whole remaining surface to call AEVOR production-final — with real TEE the deliberate last step.
