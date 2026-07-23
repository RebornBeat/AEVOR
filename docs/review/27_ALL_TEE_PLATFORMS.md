# 27 — All Five TEE Platforms: real attestation, production-first

Proof-of-Uncorruption is now real on **every** supported platform, not just AWS
Nitro (doc 25). Each platform's evidence is produced through its genuine device
interface and verified with real cryptography against the network's trust roots and
code registry. Everything builds and is tested off-hardware; the device paths
execute on the corresponding hardware.

## The shape

Two layers, so consensus never has per-platform branches:

- **`aevor_tee::registry`** — platform-agnostic *code identity*. Each verifier
  returns a `VerifiedEnclave { platform, measurements, user_data, nonce,
  timestamp }`; `CodeRegistry` holds the network-agreed builds permitted to produce
  blocks; `check_policy` enforces measurements + body binding + freshness. This is
  corruption detection: instant, O(1) per block, no re-execution (doc 22).
- **`aevor_tee::evidence`** — one `AttestationEvidence` enum consensus carries, one
  `produce()` that uses whichever TEE the machine has, one `verify(&TeeTrustRoots)`
  that dispatches to the right verifier. Trust roots are *network configuration*
  (an attacker supplying their own roots could forge anything); chip-specific
  certificates that legitimately vary per machine (the SEV-SNP VCEK) travel with
  the evidence and are checked against those roots.

## Per platform — what is actually implemented

| platform | evidence | verification | code identity |
|---|---|---|---|
| **AWS Nitro** | `COSE_Sign1` CBOR document | cert chain → pinned AWS root fingerprint; ES384 over the reconstructed `Sig_structure` | PCR0/1/2 (+PCR8) |
| **Intel SGX** | DCAP v3 quote | ECDSA P-256 over `header‖report_body` with the attestation key; QE report must bind that key via `SHA-256(att_key‖auth_data)`; PCK chain to a pinned Intel root when configured | MRENCLAVE, MRSIGNER |
| **AMD SEV-SNP** | 1184-byte report + VCEK cert | ECDSA P-384 over bytes `[0,672)` with the VCEK key (LE r‖s de-padded to P-384 width); VCEK chained to AMD root when configured | MEASUREMENT (48B) |
| **ARM TrustZone** | PSA attestation token | ES256 `COSE_Sign1` verified with the device IAK; PSA/EAT claims parsed (nonce, instance id, software components) | per-component measurements (+instance id) |
| **RISC-V Keystone** | 1352-byte report | two-link Ed25519 chain: device key signs the SM report, SM key signs the enclave report | enclave hash, SM hash |

Real binary/CBOR layouts throughout — offsets, endianness, and signature encodings
are the platforms' actual formats, not placeholders.

### Producer device interfaces (compile everywhere, run on hardware)

- **Nitro** — NSM ioctl via `aws-nitro-enclaves-nsm-api`.
- **SGX** — the standard attestation pseudo-files: write `REPORT_DATA` to
  `/dev/attestation/user_report_data`, read `/dev/attestation/quote`.
- **SEV-SNP** — Linux **configfs-tsm** (`/sys/kernel/config/tsm/report`): create a
  report directory, write `inblob`, read `outblob` (+ `auxblob` for the cert chain).
- **Keystone** — `/dev/keystone_enclave`.
- **TrustZone** — OP-TEE `/dev/tee0`.

`evidence::produce` probes these in order and returns `None` when no TEE is
present, so the same code path is correct in every environment.

## Wired into consensus

`ExecutionAttestation` carries `tee_evidence: Option<AttestationEvidence>` — no
longer Nitro-specific:

- **`seal`** binds the canonical body into real evidence on whichever TEE is
  present; `None` off-hardware (a few path checks) with the simulation signature.
- **`verify`** cryptographically verifies real evidence and confirms it binds
  exactly this transition; platforms whose root is network configuration
  (TrustZone, Keystone) **fail closed** here rather than accepting blindly.
- **`check_measurement(registry, roots, now_ms, max_age_ms)`** applies the full
  production policy: verified evidence + permitted code identity + freshness.

So the macro-DAG round paths (`apply_lane_round`, `apply_foreign_lanes`) verify real
attestations on any platform with no change to those paths.

## A real vulnerability caught in testing

The Keystone verifier initially used Ed25519 `verify`. A test asserting that an
all-zero report must never verify **failed** — because an all-zero public key is the
identity point and a zero signature satisfies the verification equation against it
(the classic small-order key attack). Switched to `verify_strict`, which rejects
small-order and non-canonical keys. The test now passes for the right reason. This
is exactly why the "must never verify" tests exist.

## Verification

- **aevor-tee: 144 tests**, clippy clean. Every verifier is tested for truncated /
  malformed / unsigned input rejection; Keystone and TrustZone additionally build
  **genuine signed evidence in-test** and verify the full chain end to end, plus
  tamper and wrong-key rejection. The registry is tested for platform scoping,
  prefix pinning, fail-closed on empty, and policy (binding, staleness, unregistered
  measurements).
- **node: 67 lib + 37 e2e**, clippy clean — the simulation fallback keeps every
  off-hardware test correct.
- **No degradation**, benchmarks ×3: PRODUCE 11,739 / 11,566 / 11,627 (±0.7%),
  VERIFY 1,095,138 / 1,049,263 / 995,187, economics byte-identical (base fee 990,
  fee/tx 485,000).

## Running on hardware

1. Build the block producer for your TEE (e.g. `nitro-cli build-enclave`, a Gramine
   manifest for SGX, an SNP guest image, an OP-TEE TA, or a Keystone enclave).
2. Record the resulting measurements and register them in the network's
   `CodeRegistry` (governance).
3. Distribute `TeeTrustRoots` (Intel root fingerprint, AMD root, Keystone device
   key, TrustZone IAK) as network configuration.
4. Run the validator on the hardware: `seal` produces real evidence, and peers'
   `verify` + `check_measurement` accept only blocks from a registered build.
