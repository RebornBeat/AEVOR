# 25 — Real TEE Attestation (AWS Nitro): production-ready, buildable, hardware-tested

This makes Proof-of-Uncorruption *real*. Until now attestation was a simulated
signature (`sim_sign`/`sim_verify`). AWS Nitro attestation is now implemented for
real — the producer requests a genuine hardware attestation document from the NSM
device, and every validator verifies it cryptographically. It builds and is tested
off-hardware (the verifier is pure Rust; the sim path is the off-enclave fallback);
the producer runs on Nitro hardware. Nitro is the recommended first platform; the
other four follow the same shape.

## The design (doc 22 realised)

The TEE proves *"this measured code ran in a genuine enclave and produced exactly
this transition"*; the network-agreed **measurement registry** proves *"that
measured code is the one we all agreed to run"*. Together they are corruption
detection — instant, O(1) per block, no re-execution:

1. **Producer** (`aevor_tee::nitro::attest`, in-enclave): issues the real NSM
   attestation request (`aws-nitro-enclaves-nsm-api`), binding the
   `ExecutionAttestation` body as `user_data` and a fresh nonce. Returns the
   `COSE_Sign1` document. Compiles everywhere; executes only on Nitro (`/dev/nsm`).
2. **Verifier** (`aevor_tee::nitro::verify::verify_document`, pure Rust — every
   validator): decode CBOR → `COSE_Sign1`; parse the attestation document; validate
   the certificate chain `leaf → cabundle → pinned AWS Nitro root` (SHA-256
   fingerprint `64:1A:03:…:5B`); verify the `COSE_Sign1` ES384 signature with the
   leaf's P-384 key over the reconstructed `Sig_structure`.
3. **Policy** (`check_policy` + `MeasurementRegistry`): the document must bind the
   expected body (`user_data`), be fresh, and its PCR0/1/2 (and PCR8 when a signing
   cert is enforced) must be in the accepted registry — i.e. an approved enclave
   image. Updating the registry is a governance action (a protocol upgrade); the
   measurement subsumes `PROTOCOL_RULES_VERSION` (it pins the exact code + rules).

## Wired into consensus (production-first)

`ExecutionAttestation` now carries an optional real `tee_document`:

- **`seal`** (producer): binds the body into a real Nitro attestation when in an
  enclave (guarded by a `/dev/nsm` check, so off-hardware it is a single stat and
  falls back to the simulation signature). Same call, correct in both environments.
- **`verify`** (every validator): when a real document is present, verifies it
  cryptographically (chain + ES384) and checks it binds this transition's body;
  otherwise checks the simulation signature. So on hardware the macro-DAG round
  applies (`apply_lane_round`, `apply_foreign_lanes`) verify *real* attestations
  with no code change to those paths.
- **`check_measurement(registry, now, max_age)`**: the code-identity step a
  production deployment calls to enforce *which* enclave image may produce — returns
  `true` for a simulated attestation so non-TEE tests are unaffected, and enforces
  the registry on hardware.

## Buildable and tested off-hardware

- Verifier crypto (CBOR/COSE/X.509/ES384) is pure Rust (`ciborium`, `p384`,
  `x509-parser`, `sha2`) — builds and runs with no enclave.
- Tests (13 in `aevor-tee::nitro`): malformed documents rejected; the pinned root
  fingerprint is AWS's published value; the registry accepts only registered
  measurements and enforces PCR8 when present; `check_policy` binds `user_data`,
  enforces freshness, and rejects unaccepted PCRs.
- The full node suite (58 lib + 34 e2e) is green with the integration in place —
  the simulation fallback keeps every off-enclave test correct. Benchmarks re-run
  2×: no throughput degradation (PRODUCE ~11.7–11.9k, VERIFY ~1.0–1.1M, economics
  byte-identical); the `is_available` guard keeps `seal` to one stat off-hardware.

## Testing on real hardware (what you run)

Build the block-producer as a Nitro enclave image; `nitro-cli build-enclave`
prints PCR0/1/2. Register those in the `MeasurementRegistry` the network agrees on.
Run the validator inside the enclave: `seal` now produces real attestations, peers'
`verify` + `check_measurement` accept only blocks from the approved image, and a
validator running unapproved code is rejected by every verifier.

## Remaining

- **Other four platforms** (SGX DCAP, SEV-SNP, TrustZone, Keystone): same shape —
  a per-platform `attest` (device) + `verify_document` (parse + chain + signature) +
  the shared `MeasurementRegistry`. Nitro is the recommended first bring-up.
- **Registry governance wiring**: distributing/updating the accepted measurement set
  through on-chain governance.
