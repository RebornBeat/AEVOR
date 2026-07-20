# AEVOR — TEE Developer & Engineer Guide

Everything an engineer needs to understand AEVOR's TEE layer, work with the five supported platforms, and **extend it to new hardware** — new RISC-V chips, other secure enclaves, and open-source hardware roots of trust. This guide is anchored on the *actual* backend contract in `aevor-tee`, so the extension recipe is copy-adaptable, not aspirational.

> **Why TEEs are load-bearing in AEVOR.** Proof of Uncorruption derives *mathematical* certainty from hardware attestation rather than *probabilistic* certainty from economic assumptions. The TEE layer is therefore the root of the entire security model. Its abstraction is deliberately platform-agnostic so the network is never captive to a single vendor's silicon — multi-platform diversity is itself a security property (a single-platform vulnerability cannot compromise the network).

---

## 1. The TEE abstraction at a glance

`aevor-tee` is organized as: a **platform layer** (detection + dispatch), **five backend modules**, an **attestation layer** (report verification, cross-platform), and supporting modules (`isolation`, `service`, `acceleration`, `anti_snooping`, `multi_tee`, `runtime`).

```
aevor-tee
├── platform/       ── SupportedPlatforms::detect(), PlatformDetection dispatch, TeeBackend trait
├── sgx/            ┐
├── sev/            │
├── trustzone/      ├─ five backends: each exposes is_available / detect_capabilities / generate_report
├── keystone/       │
├── nitro/          ┘
├── attestation/    ── AttestationVerifier: verify(), verify_cross_platform(), per-platform verify_*
├── isolation/      ── isolated-execution boundaries
├── service/        ── TEE-as-a-Service allocation
├── acceleration/   ── platform crypto acceleration
├── anti_snooping/  ── cover traffic / surveillance resistance
├── multi_tee/      ── multi-instance coordination
└── runtime/        ── the TEE-secured execution runtime
```

The canonical platform identity lives in **`aevor-core::tee::TeePlatform`** (re-exported through `aevor-tee::platform`). The current variants are `IntelSgx`, `AmdSev`, `ArmTrustZone`, `RiscvKeystone`, `AwsNitro`.

### The three contracts every backend fulfills

Each backend module (`sgx`, `sev`, …) exposes three free functions with identical signatures:

```rust
pub fn is_available() -> bool;
pub fn detect_capabilities() -> TeeResult<PlatformCapabilities>;
pub fn generate_report(user_data: &[u8]) -> TeeResult<AttestationReport>;
```

And the attestation layer adds one verification function per platform:

```rust
// in aevor-tee/src/attestation/mod.rs
fn verify_sgx(report: &AttestationReport) -> bool;   // (and verify_sev, verify_trustzone, …)
```

Dispatch is centralized in `platform/mod.rs`:

```rust
SupportedPlatforms::detect()                         // probes all backends' is_available()
PlatformDetection::detect_capabilities(platform)     // routes to the platform's detect_capabilities()
PlatformDetection::generate_report(platform, data)   // routes to the platform's generate_report()
```

There is also an object-safe trait for backends that want to be handled polymorphically:

```rust
pub trait TeeBackend: Send + Sync {
    fn platform(&self) -> TeePlatform;
    fn generate_attestation(&self, user_data: &[u8]) -> TeeResult<AttestationReport>;
    fn verify_attestation(&self, report: &AttestationReport) -> TeeResult<bool>;
    fn is_available(&self) -> bool;
    fn capabilities(&self) -> TeeResult<PlatformCapabilities>;
    fn execute_isolated<F, R>(&self, f: F) -> TeeResult<R> where /* … */;
}
```

### The key types (all in `aevor-core::tee`)

- **`TeePlatform`** — the platform enum.
- **`PlatformCapabilities`** — `{ version, is_production, has_crypto_acceleration, available_memory_bytes, max_concurrent_instances, remote_attestation_available, sealing_available }`.
- **`TeeVersion`** — `{ platform, major, minor, patch, svn }`.
- **`AttestationReport`** — `{ platform, raw_report, code_measurement, signer_measurement, nonce, is_production, svn, user_data }`.
- **`CrossPlatformAttestation`** — a primary report plus secondaries, with a consistency check.

---

## 2. Detection vs. attestation — the current state (important)

The backends are split into two layers with **different maturity**, and understanding this split is essential:

| Layer | Function | Status today | Production requirement |
|-------|----------|--------------|------------------------|
| **Detection** | `is_available()` | **Real** — probes the real device path (e.g. `/dev/sgx_enclave`) | none — done |
| **Detection** | `detect_capabilities()` | **Real feature detection**, but sets `is_production: false` | set `is_production` from real TCB/attestation state |
| **Attestation** | `generate_report()` | **Simulation** — BLAKE3 measurement over a domain-separated tag | read the real hardware quote |
| **Attestation** | `verify_*()` | **Structural** — checks `raw_report` non-empty | validate the quote against the platform root of trust |

This is the correct posture for a pre-hardware codebase: the network can run, be tested (1,541 tests), and be developed against on machines with no secure hardware, while the attestation swap-in is a localized change per platform. **Keep the simulation path behind a feature flag** even after real backends land — it is how hardware-free CI runs.

> Register cross-reference: the attestation swap-in is **B3** in `01_STUB_AND_SIMULATION_REGISTER.md`. The client-side counterpart is **B11**.

---

## 3. The five platforms — engineer's reference

For each platform: what it is, how AEVOR detects it, and exactly what the production attestation swap-in is.

### 3.1 Intel SGX (`TeePlatform::IntelSgx`)
- **What:** hardware-enforced user-space enclaves on Intel CPUs; encrypted EPC memory (the backend advertises a 256 MB EPC, 64 concurrent instances).
- **Detection:** CPUID SGX bit + `/dev/sgx_enclave` present.
- **Report (production):** `sgx_create_report()` / DCAP quote-generation library produces a quote.
- **Verify (production):** DCAP quote verification + PCK certificate chain rooted at the Intel Provisioning Certification Service (PCS). Check MRENCLAVE (code measurement), MRSIGNER (signer), ISV SVN, and TCB status.
- **Gate the real path** behind `cfg(sgx)` and the Intel SGX SDK / DCAP libs.

### 3.2 AMD SEV-SNP (`TeePlatform::AmdSev`)
- **What:** VM-level memory encryption + integrity (SEV-SNP) for confidential VMs.
- **Detection:** `/dev/sev-guest` present (+ CPUID SEV bits).
- **Report (production):** `SNP_GET_REPORT` ioctl to `/dev/sev-guest` returns an attestation report bound to a report-data nonce.
- **Verify (production):** validate the report signature against the VCEK/VLEK certificate chain from the AMD Key Distribution Service (KDS); check measurement, TCB, and policy.

### 3.3 ARM TrustZone (`TeePlatform::ArmTrustZone`)
- **What:** secure-world/normal-world split on ARM; a trusted execution environment (OP-TEE-style).
- **Detection:** secure-world/TEE device presence (platform-specific).
- **Report (production):** PSA Attestation API from the secure world produces an Entity Attestation Token (EAT).
- **Verify (production):** validate the PSA/EAT token (COSE-signed) against the platform's provisioned root key; check the boot/software measurements.

### 3.4 RISC-V Keystone (`TeePlatform::RiscvKeystone`)
- **What:** open-source enclave framework for RISC-V; a Security Monitor (SM) runs in machine mode and isolates enclaves. **This is the reference open-hardware path** and the template for other open designs.
- **Detection:** Keystone SM / driver presence.
- **Report (production):** the Security Monitor produces an attestation over the enclave measurement, signed by the device root key.
- **Verify (production):** validate the SM report signature against the device root of trust (provisioned per-device or per-manufacturer); check enclave hash + SM version.

### 3.5 AWS Nitro Enclaves (`TeePlatform::AwsNitro`)
- **What:** isolated VMs with no persistent storage/interactive access; attestation via the Nitro Security Module (NSM). The backend simulates PCR0 (the enclave image measurement).
- **Detection:** NSM device (`/dev/nsm`) present.
- **Report (production):** NSM `GetAttestationDoc` returns a COSE_Sign1 attestation document containing PCRs and an optional nonce/public key.
- **Verify (production):** validate the COSE_Sign1 signature against the AWS Nitro Attestation PKI root; check PCR0 (and other PCRs) against expected measurements.

---

## 4. Extending to a new chip — step-by-step recipe

This is the core of the "leave the design extensible" requirement. Because dispatch is centralized and every backend fulfills the same three-function contract, adding a platform is a **mechanical, five-touch change**. Use RISC-V Keystone (§3.4) as your worked reference — it is the closest analogue for new RISC-V silicon and open-hardware roots of trust.

### Step 1 — Add the platform identity
In `aevor-core::tee`, add a variant to `TeePlatform` (e.g. `OpenTitan`, `Cca` for ARM CCA, `Tdx` for Intel TDX, or your new RISC-V core). This is the only change outside `aevor-tee`. Because `TeePlatform` is the canonical identity used everywhere, adding the variant makes the platform expressible throughout the system.

### Step 2 — Create the backend module
Add `aevor-tee/src/<platform>/mod.rs` implementing the three functions. Copy `sgx/mod.rs` or `keystone/mod.rs` as the template and adapt:

```rust
//! <Platform> TEE backend.

use aevor_core::tee::{PlatformCapabilities, TeeVersion, TeePlatform};
use crate::{AttestationReport, TeeError, TeeResult};

/// Real device probe — return true only when the hardware/driver is present.
pub fn is_available() -> bool {
    std::path::Path::new("/dev/<your-device>").exists()
    // + any CPUID / ISA / firmware capability check
}

pub fn detect_capabilities() -> TeeResult<PlatformCapabilities> {
    if !is_available() {
        return Err(TeeError::PlatformUnavailable { platform: "<platform>".into() });
    }
    Ok(PlatformCapabilities {
        version: TeeVersion { platform: TeePlatform::<Variant>, major: 1, minor: 0, patch: 0, svn: 0 },
        is_production: false, // flip to true once real attestation state is read
        has_crypto_acceleration: /* detect */ false,
        available_memory_bytes: /* enclave memory budget */ 0,
        max_concurrent_instances: /* platform limit */ 1,
        remote_attestation_available: true,
        sealing_available: /* does the platform seal? */ false,
    })
}

pub fn generate_report(user_data: &[u8]) -> TeeResult<AttestationReport> {
    // PRODUCTION: read the real hardware quote for `user_data` here.
    // SIMULATION (keep behind a feature flag): BLAKE3 over a domain-separated tag,
    // mirroring the existing backends so hardware-free CI still works.
    // Return an AttestationReport with the real platform, measurement, nonce, svn.
    todo!("real quote or feature-flagged simulation")
}
```

### Step 3 — Register in the dispatch (three edits in `platform/mod.rs`)
```rust
// SupportedPlatforms::detect()
if crate::<platform>::is_available() { available.push(TeePlatform::<Variant>); }

// PlatformDetection::detect_capabilities()
TeePlatform::<Variant> => crate::<platform>::detect_capabilities(),

// PlatformDetection::generate_report()
TeePlatform::<Variant> => crate::<platform>::generate_report(user_data),
```
And declare the module in `aevor-tee/src/lib.rs`: `pub mod <platform>;`

### Step 4 — Add verification in the attestation layer
In `aevor-tee/src/attestation/mod.rs`, add `verify_<platform>()` and route to it from the verifier's platform match. Production: validate the quote against the platform's root of trust (see the per-platform "Verify" notes in §3). Structural placeholder is acceptable only to bootstrap; do not ship it as the real security boundary.

### Step 5 — (Optional) implement `TeeBackend`
If the platform needs polymorphic handling (e.g. registered in a `multi_tee` set), implement the `TeeBackend` trait for a backend struct that forwards to your free functions and wires `execute_isolated`.

### Step 6 — Tests & feature flag
Mirror the existing backends' tests: `is_available_does_not_panic`, capability detection on the target arch, report generation shape. Gate the real hardware path behind a `cfg`/feature (as SGX uses `cfg(sgx)`), and keep the simulation path behind a `simulation` feature so CI without the hardware still exercises the interface.

### What you do **not** have to touch
Consensus, VM, execution, storage, client — none of them special-case platforms. They consume `TeePlatform`, `AttestationReport`, and the verifier. That is the whole point of the abstraction: **new silicon is additive**, never a cross-cutting change.

---

## 5. Guidance for open-source hardware roots of trust

For fully open designs (OpenTitan-style RoT, open RISC-V cores with custom SM, community secure elements), the same recipe applies, with two extra considerations:

1. **Root-of-trust provisioning.** DCAP/KDS/AWS-PKI assume a vendor PKI. Open hardware often has a *manufacturer-* or *deployment-provisioned* root key instead. Model this in your `verify_<platform>()`: accept a configured trust anchor (device root, batch key, or a transparency-log-published measurement) rather than a hardcoded vendor CA. Keep the trust anchor **configurable**, never hardcoded (consistent with AEVOR's no-hardcoded-ceilings philosophy — here, no-hardcoded-trust-root).
2. **Measurement transparency.** Where a vendor quote is replaced by an SM/boot measurement, publish expected measurements so verifiers can check them. Keystone (§3.4) is the in-tree reference for this shape.

Because platform diversity is a security property, **adding open-hardware backends strengthens the network** even if any single open platform is less battle-tested than SGX/SEV — an attacker must break *every* platform a validator set spans.

---

## 6. Operational notes

- **CI / no hardware:** `SupportedPlatforms::detect()` returns an empty set and every `is_available()` returns false — by design, without panicking. Select `TeeMode::Simulation` (in `aevor-config::tee`) to run against the simulation backends.
- **`is_production` flag:** today every backend reports `is_production: false`. Treat this as the single source of truth for "am I on real attested hardware" and gate security-sensitive behavior on it once real backends land.
- **Cross-platform attestation:** `AttestationVerifier::verify_cross_platform` already requires every platform in a bundle to verify individually *and* be mutually consistent — this is the mechanism behind multi-platform-diversity security.
- **Do not delete simulation code.** It is not a stub to be removed; it is the test harness that lets 1,541 tests run without secure silicon.

---

## 7. Checklist: adding a platform (tear-off)

- [ ] Add `TeePlatform::<Variant>` in `aevor-core::tee`.
- [ ] Create `aevor-tee/src/<platform>/mod.rs` with `is_available` / `detect_capabilities` / `generate_report`.
- [ ] `pub mod <platform>;` in `aevor-tee/src/lib.rs`.
- [ ] Register in `SupportedPlatforms::detect()`.
- [ ] Register in `PlatformDetection::detect_capabilities()` match.
- [ ] Register in `PlatformDetection::generate_report()` match.
- [ ] Add `verify_<platform>()` and route it in `attestation/mod.rs`.
- [ ] (Optional) `impl TeeBackend` for a backend struct.
- [ ] Real quote in `generate_report`; real root-of-trust validation in `verify_<platform>`.
- [ ] Simulation path behind a feature flag; tests mirroring existing backends.
- [ ] Confirm no consensus/VM/execution/storage/client changes were needed (they should not be).
