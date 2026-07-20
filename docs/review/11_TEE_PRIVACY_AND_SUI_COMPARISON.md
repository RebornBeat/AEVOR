# TEE Scope, Privacy Model, and Competitive Comparison (Sui)

Grounded in `WHITEPAPER.md` (§ TEE Attestation Framework, § TEE-as-a-Service,
§ Mixed Privacy Architecture). This note answers three questions: which TEE
hardware AEVOR targets, who uses TEE, and how AEVOR's privacy compares to Sui's.

## 1. TEE hardware platforms (confirmed: 5)

AEVOR's attestation framework targets five TEE platforms, normalized behind a
cross-platform attestation abstraction so applications get identical guarantees
regardless of hardware:

| Platform            | Environment kind                     |
|---------------------|--------------------------------------|
| Intel SGX           | User-mode secure enclaves            |
| AMD SEV             | Encrypted secure VMs                 |
| ARM TrustZone       | Secure-world execution               |
| RISC-V Keystone     | Configurable secure enclaves         |
| AWS Nitro Enclaves  | Cloud-based isolated enclaves        |

In the codebase these correspond to the platform backends under `aevor-tee`
(`sgx`, `sev`, `trustzone`, `keystone`, `nitro`). The attestation *verification*
logic is real; hardware quote *generation* is gated behind a feature flag on
platforms without the hardware present (tracked as B3).

## 2. Who uses TEE — validators AND applications

TEE is **not** validator-only. There are two distinct roles:

- **Validators PROVIDE and ATTEST.** Validators run TEE hardware and produce
  attestations that back Proof-of-Uncorruption consensus (mathematical
  verification that execution occurred correctly in verified hardware). This is
  the consensus-critical use.
- **Applications / dApps CONSUME (TEE-as-a-Service).** Validators also offer
  their TEE capacity as a *service*: dApps request confidential/verified
  execution through simple interfaces, getting "serverless Web3" compute with
  hardware anti-snooping — without running any hardware themselves. Service
  allocation, discovery, and geographic redundancy are provided by the validator
  network, not a central provider.
- **Users BENEFIT.** End users get private transactions and verified computation
  as a result, without interacting with TEE directly.

So: validators = providers + attesters; dApps/applications = consumers; users =
beneficiaries.

## 3. Private transactions — AEVOR's Mixed Privacy model

AEVOR's privacy is **object-level**: every object carries its own privacy policy
(Public / Protected / Private / Confidential), and privacy is **architecturally
enforced** — a privacy violation causes the operation to be *rejected*, never
silently downgraded. Key properties:

- **Granular:** different objects in the same transaction/app can have different
  privacy levels (not a single global "shielded pool").
- **General, not payments-only:** privacy applies to arbitrary object *state* and
  *computation*, not just token transfer amounts.
- **Hybrid mechanism:** confidential execution is backed by **TEE** (hardware
  anti-snooping protects data even from the node running it) **plus ZK** for
  mathematical privacy verification and selective disclosure.
- **Cross-privacy coordination:** objects of different privacy levels can
  interact through defined protocols.
- **Selective disclosure:** specific properties can be revealed to authorized
  parties while the rest stays confidential.

## 4. Honest comparison with Sui (as of mid-2026)

**What Sui shipped / announced** (from public reporting, mid-2026):
- **Confidential transfers (shipped ~June 2026):** hides transfer *amounts*
  using **range proofs**, while preserving supply integrity (proving no value is
  minted while amounts are hidden). Deliberately scoped: "range proofs on
  transfer amounts."
- **Confidential transactions (announced for 2026):** protocol-level, aims to
  hide amounts *and* addresses via **ZK-SNARKs**, framed as "compliant privacy"
  for payments and institutional adoption. Implementation details (which tx
  types, all tokens vs stablecoins) were still unspecified in the announcements.

**How this compares to AEVOR's design — evenhandedly:**

| Dimension            | Sui (2026)                                  | AEVOR (design)                                          |
|----------------------|---------------------------------------------|--------------------------------------------------------|
| Scope of privacy     | Payment **transfers** (amounts; later addresses) | **Arbitrary object state + computation**, object-level |
| Mechanism            | **ZK-only** (range proofs, ZK-SNARKs)       | **TEE + ZK hybrid** (hardware confidentiality + ZK)    |
| Granularity          | Transaction/transfer scoped                 | Per-object privacy policy                              |
| Trust assumption     | Cryptographic only (no hardware trust)      | Adds a **hardware-vendor / side-channel** trust surface via TEE |
| Maturity             | **Shipped** (transfers) / announced (full)  | Largely **design + partial implementation** (ZK provers B1, TEE B3 pending) |
| Philosophy           | "Compliant privacy" for payments            | "Compliant privacy" via selective disclosure           |

**Is AEVOR "more private"? — the honest answer is "broader in scope, different in trust model, and less mature."**
- **Broader in scope:** AEVOR's design covers confidential *computation and
  arbitrary state*, whereas Sui's confidential transfers are scoped to *payment
  amounts*. If the metric is "how much can be kept private," AEVOR's design aims
  wider.
- **Different trust model — not strictly "more" private:** AEVOR's TEE reliance
  buys cheap, general confidential computation but introduces a hardware-trust
  and side-channel surface that a pure-ZK approach like Sui's avoids. A purist
  would argue ZK-only is *more trust-minimized*. So "more private" depends on
  threat model; it is not unconditionally true.
- **Less mature:** Sui has **shipped** a narrow but real feature; AEVOR's privacy
  is still substantially in design/partial implementation. That is the most
  important honest caveat.

**Did Sui "copy" AEVOR? — no evidence, and the lineage runs the other way.**
Both are riding the same 2026 "compliant privacy for institutions" trend. The
**object-centric model itself originated with Sui/Move** (2022–2023); AEVOR's
object-*level privacy* is a natural extension of object-centric thinking that Sui
pioneered, combined with a TEE+ZK execution model that is genuinely distinct from
Sui's ZK-only transfers. So the accurate framing is: shared design space,
Sui-origin object model, AEVOR-distinct hybrid privacy mechanism — not
imitation in either direction.

**Takeaway for positioning:** AEVOR's defensible differentiators are (a)
general confidential *computation* (not just transfer amounts) and (b) the
TEE-as-a-Service model that lets dApps run private logic without their own
hardware. The honest liability is maturity: Sui shipped; AEVOR needs B1 (ZK) and
B3 (TEE) landed and a testnet privacy demo before the "more private" claim can be
made on anything other than paper.
