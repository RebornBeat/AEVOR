# AEVOR Crypto Agility & Post-Quantum Selection

Status: agility layer implemented (Milestone 6). Selection below is the recommended trajectory, not yet all wired.

## 1. The governing decision: agility over any single algorithm

The most important property is **not** which post-quantum scheme AEVOR picks — it is that the crypto layer can swap schemes (classical↔PQ, or PQ↔PQ) without touching anything that stores or moves a signature. A "best" PQC choice today can be broken tomorrow (SIKE and Rainbow both collapsed *during* NIST standardization), and better schemes keep arriving. So AEVOR commits to a **scheme-tagged envelope + dispatch**, and treats the algorithm list as data.

Implemented (Milestone 6):
- `aevor-core::crypto::SignatureSchemeId` — the wire tag. Additive; new schemes are new variants.
- `aevor-core::crypto::MultiSignature` / `MultiPublicKey` — variable-length tagged envelopes (one wire type for every scheme; PQ keys/sigs are large and variable-sized, so keys are enveloped too).
- `aevor-crypto::agility::{Signer, verify_multi, MultiVerify}` — sign/verify dispatch. Ed25519 is real; recognized-but-unimplemented PQ schemes return `Unsupported` (distinct from `Invalid`), so a verifier always knows the difference between "bad signature" and "this build can't check that scheme yet."

Design choice: the core fixed `Signature([u8;64])` was **kept unchanged** (Ed25519/BLS paths and ~1,600 tests depend on it); the envelope is **additive** alongside it. Widening the core type would ripple with no benefit.

## 2. What AEVOR actually needs, by role

AEVOR has three distinct signature roles with different constraints:

| Role | Frequency | Size sensitivity | Recommended |
|---|---|---|---|
| Transaction signing | every tx, over the wire | **very high** | Ed25519 now; **FN-DSA (Falcon)** as the PQ path (≈700 B vs ML-DSA's ≈2.4 KB) — smaller over the wire; or hybrid Ed25519+FN-DSA |
| Consensus / finality | every block | high; **must aggregate** | BLS12-381 today — **see the gap in §4** |
| Root of trust (genesis, validator identity, firmware) | rare, long-lived | low | **SLH-DSA (SPHINCS+)** — hash-based, most conservative math, size tolerable because infrequent |

The "true minimum" PQ posture: (a) the tagged envelope in place (done), (b) **ML-KEM (Kyber)** hybridized with X25519 for any key exchange/encryption, (c) a PQ signature on the *long-lived, high-value* items (SLH-DSA), and (d) transactions can stay Ed25519 / move to Falcon and be upgraded later precisely because the seam is clean. PQ does not need to be on every ephemeral signature on day one.

## 3. Scheme assessment (as of the current NIST state)

- **ML-DSA (Dilithium)** — FIPS 204, standardized, most vetted, broad libraries. The safe conservative default. Downside: 2.4–4.6 KB signatures. AEVOR's current `HybridEd25519Dilithium` targets this; it is a **stub** today (register B2) and should become real ML-DSA behind the `Signer` trait.
- **FN-DSA (Falcon)** — lattice, standardizing; **much smaller signatures** (~700 B L1). Best fit for AEVOR's over-the-wire priority on transactions. Cost: floating-point → implementation/side-channel care.
- **SLH-DSA (SPHINCS+)** — FIPS 205, hash-based, most conservative assumptions, no "new math" risk. Large signatures (8 KB+) → use for infrequent root-of-trust, not per-tx.
- **FAEST** — AES-based MPC-in-the-Head; the live survivor of the "symmetric-based / no-new-math" family (a source's headline pick, **AIM, was eliminated** in the NIST additional-signature process — do not select AIM). Still a *candidate*, not a standard; treat as an optional pluggable scheme, not the base.
- **SQIsign** — isogeny, tiny (241 B total), still a NIST candidate. Degrades under a hybrid quantum attack (sub-exponential, unlike lattices) and isogenies are young (SIKE broke in a weekend). Optional for bandwidth-critical niches only; never the base for long-lived value.
- **Classic McEliece** — code-based, very conservative, but ~1 MB public keys → impractical for on-chain keys.

Caveat on the framing that motivated this review: claims like "quantum computing is functionally impossible" and specific classical-speedup multipliers are stronger than the cryptographic consensus and are **not** baked into these choices. The robust, assumption-light takeaways — agility matters, symmetric/hash math is most conservative, size matters over the wire, store-now-decrypt-later is real — are what drive the design.

## 4. The unsolved gap: post-quantum finality aggregation

AEVOR's finality relies on **BLS12-381 signature aggregation** (`FinalityProof`). BLS is **not post-quantum**, and there is **no standardized post-quantum aggregate signature**. The very property AEVOR needs for scalable finality — aggregation — is the hardest thing to obtain post-quantum. This is a first-class open item, not a footnote. Options, all imperfect:
1. Keep BLS classical and accept that finality is not PQ (what most chains do today).
2. Replace aggregation with a SNARK that proves a batch of individual PQ signatures verified (compresses many PQ sigs to one proof; heavy prover).
3. Track PQ multi-signature research (e.g. lattice-based aggregation) as it matures.

Consequence: "PQ AEVOR" is **not** just "swap Ed25519→Dilithium on transactions." The transaction path is straightforward with the envelope; the consensus-aggregation path is a separate, harder decision that should be made deliberately.

## 5. Account continuity across the classical→post-quantum transition

Agility at the *signature* layer (§1) is not enough for real users; they also need their **wallet/identity to survive** the transition. AEVOR handles this at the account layer (`aevor-crypto::account`), and it rests on one enabling fact: **`Address` is a raw 32-byte identifier, not a hash of the public key**, so identity is decoupled from the key.

**A key can be created as any of three types** — Ed25519 (classical, smallest), ML-DSA-65 (post-quantum), or Hybrid (both). The choice is made at wallet creation and is not permanent.

**Switching keys never requires a new wallet.** An account has a stable `AccountId`; assets and identity bind to it. A signed **key rotation** (authorized by the current key) swaps the controlling key — e.g. Ed25519 → Hybrid — while the `AccountId` and everything under it stays put. This is safe as long as the current key's scheme is unbroken.

**A non-PQ wallet stays safe when quantum arrives — two independent guarantees:**

1. **Hybrid from the start (no action needed).** A Hybrid key requires forging *both* Ed25519 and ML-DSA-65. When Ed25519 falls, the ML-DSA half still protects every signature. A user who creates (or rotates into) a Hybrid key is simply safe, with the cost of larger signatures/keys.

2. **Quantum-safe migration pre-commitment (for a pure-classical wallet).** While Ed25519 is still secure, the account commits `hash(future_pq_key)` on-chain (authorized by the current key). Later — *even if Ed25519 has since been broken* — the user reveals the matching PQ key to take control. A quantum adversary who broke Ed25519 **still cannot forge this migration**, because they cannot find a key whose hash equals the commitment. Hash preimage resistance is only quadratically weakened by Grover, so a 256-bit hash gives 128-bit post-quantum security. This is the safety net for users who did not pre-emptively go hybrid: their classical wallet can still be rescued into PQ control after the classical break, without a signature from the (now-forgeable) classical key.

The distinction matters: rotation is authorized by the *current key* (fine pre-break); the pre-commitment's activation is authorized by the *commitment itself* (fine post-break). Together they cover both "upgrade early" and "the era arrived and my classical key is now weak."

All of this is implemented and tested (`AccountKeyRecord`: `open` / `rotate` / `set_pq_commitment` / `activate_pq_migration`), including the adversarial cases (unauthorized rotation, wrong-key reveal, unauthorized commitment).

## 6. Next steps (crypto)

1. ~~**B2**: implement real ML-DSA behind `Signer`/`verify_multi`.~~ **DONE (Milestone 9)** — ML-DSA-65 via the pure-Rust `fips204` crate is wired into the agility dispatch and proven end-to-end. The decision to use a vetted crate rather than roll our own followed the same overhead/performance lens as the storage decision (see the B2 entry in the register): pure-Rust expert implementations are faster than a bespoke NTT and avoid the silent side-channel risk of hand-rolled lattice code, and a pure-Rust option exists so the C++-avoidance motive that favored from-scratch for storage does not apply here.
2. Add **FN-DSA (Falcon)** as the size-optimized transaction PQ option, and **SLH-DSA** for root-of-trust — behind the same trait.
3. ~~Make the `HybridEd25519MlDsa65` path compose the real Ed25519 + real ML-DSA halves.~~ **DONE (Milestone 11)** — real hybrid + the full account-continuity/migration layer (§5).
4. Add **ML-KEM (Kyber)** hybrid X25519 for the KEM/encryption side.
5. Make an explicit decision on the **finality-aggregation PQ gap** (§4) before claiming end-to-end PQ.
