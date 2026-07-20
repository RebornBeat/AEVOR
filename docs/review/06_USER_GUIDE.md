# AEVOR — User Guide (All User Types)

A user-facing orientation to AEVOR for the five audiences the platform serves: **validators**, **dApp / smart-contract developers**, **enterprises / subnet operators**, **end users**, and **node operators**. It explains what AEVOR gives each audience, the mental model they need, and where to go in the tooling.

> **One idea to carry throughout:** AEVOR gives *mathematical* certainty, not *probabilistic* certainty. When a transaction is finalized, it is **immutable** — it is never reversed or "rolled back." When something cannot be done safely (a conflict, a privacy-boundary violation, a failed verification), AEVOR **rejects** it rather than partially applying it. Rejection is not failure of the network; it is the network refusing to enter an unverified state. If a rejected transaction should be retried, that is the application's choice to resubmit — the infrastructure never silently retries.

> **On performance numbers:** every throughput/latency figure in AEVOR's docs (200,000+ TPS sustained, 1,000,000+ burst, ~20 ms–1 s confirmation) is a **measured baseline on reference hardware**. These are floors that improve with better hardware, not ceilings and not guarantees. AEVOR imposes no architectural throughput ceiling.

---

## 1. For everyone — the core concepts

**Proof of Uncorruption (PoU).** Validators run inside Trusted Execution Environments (secure hardware). The hardware cryptographically attests that execution was correct. Consensus is therefore about *verified correctness*, not *economic probability*. This is why finality is immutable.

**Dual-DAG.** Transactions that touch different objects run in parallel; transactions that would conflict are detected and rejected *before* they run, so the network never has to undo work. Blocks are produced by many validators at once (no single leader), and the throughput scales with participation.

**Four security levels.** You choose how much validator confirmation a transaction needs, trading latency for strength:

| Level | Confirmation (approx., hardware-dependent) | Use it for |
|-------|--------------------------------------------|------------|
| Minimal | ~20–50 ms | low-value, high-frequency actions |
| Basic | ~100–200 ms | everyday transactions |
| Strong | ~500–800 ms | high-value transfers |
| Full | <1 s | settlement, maximum assurance |

**Mixed privacy (per object).** Every object picks its own privacy level — `Public`, `Protected` (prove properties without revealing them), `Private` (encrypted, TEE-executed), or `Confidential` (adds metadata/correlation shielding). Privacy is *enforced*: a violation causes rejection, never a silent downgrade. AEVOR's privacy uses TEEs (~1.1–1.3× overhead), not homomorphic encryption (which would be 1000×+).

---

## 2. For validators

**What you provide and earn.** Validators secure consensus *and* can provide TEE-as-a-Service (compute, storage, edge delivery, analytics, deployment, multi-party computation). Rewards combine consensus participation and service provision, with quality- and geography-based multipliers (all reward figures are governance-configurable reference values that adapt with network economics).

**What you need.**
- TEE-capable hardware on one of the supported platforms: Intel SGX, AMD SEV-SNP, ARM TrustZone, RISC-V Keystone, or AWS Nitro Enclaves. (Supporting *multiple* platforms earns diversity incentives and strengthens the network.)
- The node software, run in validator mode.

**Getting started (shape of the flow — see the CLI reference in §7):**
1. Detect and verify your TEE platform (`aevor-cli` `tee` commands — capability detection and attestation self-check).
2. Generate keys (`keys`).
3. Configure the network to join (mainnet / testnet / a subnet) (`network`, `config`).
4. Register as a validator, declaring your TEE service capabilities (`validator`).
5. Start the node in validator mode and monitor service quality (`node`, `status`).

**What to expect operationally.** Your TEE attests each execution; the network verifies it. If your attestation ever fails to verify, your work is rejected (not silently accepted) — this is the security model protecting the network, and monitoring your attestation health is part of running a validator.

---

## 3. For dApp / smart-contract developers

**What you build on.** AevorVM executes contracts with automatic parallelism (based on which objects a transaction reads/writes) and cross-platform-consistent results across every TEE. AEVOR supports the **Move** language with AEVOR-specific extensions.

**Superpowers you don't get elsewhere:**
- **Declarative TEE execution.** A contract can request a secure execution environment declaratively — you get confidential compute without deploying any special infrastructure.
- **Object-level mixed privacy.** A single contract can hold public and private fields side by side. Example shape:
  ```
  MedicalRecord { patient_id: Private, diagnosis: Confidential,
                  treatment_date: Protected, insurance_status: Public }
  ```
  Each field's privacy is enforced by the platform; a violation rejects the operation.
- **AEVOR Move attributes.** `#[privacy]`, `#[tee_required]`, and `#[cross_chain]` let you express privacy, secure-execution, and cross-chain requirements directly on your Move code.
- **Automatic parallelization.** You don't manage locks; the micro-DAG derives dependencies from object access and rejects genuine conflicts pre-execution. Independent transactions simply run in parallel.

**Design implications to internalize:**
- Design for **rejection, not rollback.** If two transactions contend for the same object, one is rejected before execution; surface a resubmit path in your app rather than assuming a retry.
- **Choose a security level per action.** Use Minimal for cheap high-frequency actions and Strong/Full for value settlement.
- **Cross-privacy interactions are allowed but bounded.** Public and private objects can coordinate (selective disclosure, proof of private results for public verification), but boundary violations reject.

**The SDK.** `aevor-client` gives you query, transaction, and subscription clients plus response/attestation verification. You submit transactions, poll for finality at your chosen security level, and subscribe to real-time events. *(Transport wiring — HTTP/gRPC/WebSocket — is the one SDK piece still being connected; see the engineering register. The client interfaces themselves are complete.)*

---

## 4. For enterprises / subnet operators

**What AEVOR offers you.** Permissioned **subnets**: your own validator set and access controls, custom parameters and privacy defaults, optional **feeless** operation for internal use, and integration with existing compliance/identity systems — all while retaining AEVOR's mathematical security and the ability to interoperate with public networks through bridges.

**Deployment models:**
- **Permissioned enterprise subnet** — controlled access, tailored config, optional zero fees.
- **Hybrid** — applications that span your subnet and public networks; cross-network operations that can't complete with full verification are rejected (never partially settled).

**Configuration shape (illustrative):**
```yaml
network_config:
  type: "permissioned_subnet"
  organization: "your_org"
  compliance_framework: "SOX_compliance"
  data_residency: "jurisdiction_specific"
privacy_policy:
  default_level: "protected"
  selective_disclosure: "enabled"
economic_model:
  transaction_fees: "disabled"
```

**Compliance posture.** Object-level privacy supports selective disclosure for KYC/AML (prove compliance without exposing identity), and audit logging is built in. Privacy is architecturally enforced, so "confidential" fields cannot be silently exposed.

**TEE deployment patterns to choose between:**
- **Single TEE per application** — maximum isolation, atomic app logic, simplest security model.
- **Distributed TEE service mesh** — specialized instances, better utilization, granular fault tolerance. Failures reroute/reject; they don't degrade guarantees.
- **Hybrid** — start single, grow into distributed as you scale.

---

## 5. For end users

**What you get.** Fast confirmations (often well under a second), transaction finality that is *permanent* once reached, and genuine privacy options you control per asset/interaction.

**What "privacy" means for you.** You choose, per object, whether something is public, provable-but-hidden, private, or fully confidential. When you mark something private, the network *enforces* it — there is no path where it gets quietly revealed; an operation that would break your privacy is rejected instead.

**What "finality" means for you.** When your transaction reaches its security level, it is done — it will not be reversed later. If you need maximum assurance for a large transfer, choose a higher security level (a little more latency for maximum certainty).

**If a transaction is rejected.** That means the network declined to enter an unverified or conflicting state (for example, two actions raced for the same object). Your funds/state were not partially changed. You can resubmit.

---

## 6. For node operators (non-validating)

**Node modes.** Beyond validators, AEVOR supports **full nodes** (maintain and serve state) and **light nodes** (verify via proofs without storing everything). The node binary includes orchestration, health, archive, init, and graceful shutdown.

**What you do.**
- Initialize and configure the node for your target network (`init`, `config`).
- Choose full or light mode based on your resource budget and needs.
- Monitor health and metrics; nodes expose health endpoints and metrics.
- Keep durable storage healthy (state persistence) and stay connected to peers (topology-aware networking optimizes bandwidth — measured ~90–95% utilization on reference configs).

**What to expect.** A full node verifies attestations and serves data; a light node relies on Merkle proofs to verify responses without full state. *(Durable RocksDB storage and Merkle-proof export are being finalized in the engineering register; the node/storage interfaces are complete.)*

---

## 7. CLI quick reference (command groups)

`aevor-cli` is organized into these groups (run each with `--help` for specifics):

| Group | Purpose |
|-------|---------|
| `keys` | generate and manage keys |
| `network` | select/join a network (mainnet, testnet, subnet) |
| `node` | start/stop and control a node |
| `validator` | register and manage validator participation |
| `tee` | detect TEE capabilities and run attestation self-checks |
| `governance` | view/participate in on-chain governance |
| `config` | manage configuration |
| `status` | inspect node/network status |
| `output` | control output verbosity (supports a quiet mode) |

There is also a **testnet faucet** (`aevor-faucet`) with proof-of-work anti-abuse and cooldowns for obtaining test tokens.

---

## 8. Where things stand (honest status note)

AEVOR's architecture is fully present and its interfaces are complete and stable. A bounded set of implementations is still being finalized behind those interfaces — most relevantly for users: real TEE hardware attestation, durable storage, and the SDK/CLI network transport. None of these change how you *use* the platform or the concepts above; they are implementation swap-ins tracked in the engineering documents (`01_STUB_AND_SIMULATION_REGISTER.md`, `03_PRODUCTION_READINESS_CHECKLIST.md`). Until real TEE backends are enabled on your hardware, run against the explicit simulation mode for development.
