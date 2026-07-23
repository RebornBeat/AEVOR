# 30 — Node Operations Guide

What an operator needs to run AEVOR: node roles and what each is responsible for,
the validator lifecycle, TEE bring-up per platform, configuration, and what failure
looks like. This is written against the finalized implementation; where it states a
number, that number is measured (see doc 29 for provenance).

---

## 1. Node roles

A node's role determines its work profile and its resource ceiling.

### 1.1 Producer (block-producing validator)

Executes transactions, settles fees, and seals an attestation over the resulting
transition.

- **Work per round:** signature verification (parallel across cores), micro-DAG
  conflict rejection, VM execution, fee settlement, Merkle commit, attestation seal.
- **Measured rate:** ~11,400–11,900 tx/s per core. **This is the network's
  bottleneck** — aggregate throughput is `N_lanes × this`.
- **Scales with:** CPU cores (execution is parallel across the independent set).
- **Requires:** a TEE for real attestation; a funded validator identity; the
  network's protocol binary whose measurement is in the code registry.

### 1.2 Verifier (validating, non-producing)

Applies other validators' attested lanes **without re-executing**.

- **Work per round:** attestation verification per lane, cross-lane conflict checks,
  deterministic ordering, delta application (objects + balances), Merkle commit.
- **Measured rate:** ~1.0–1.1M tx/s — roughly 90× the producer rate, so verification
  is deliberately over-provisioned.
- **Dominant cost:** state insertion + Merkle root at **89.4%** of apply. Conflict
  checks are 7.8%, attestation verification 2.8%.
- **Does not require a TEE.** Verification is public-key cryptography; a validator
  with no TEE can verify any platform's evidence. Producing requires hardware,
  verifying does not.

### 1.3 Light client

Checks the object root and balance commitment without holding state.

- Balance consistency is available without Merkle inclusion proofs, because balance
  deltas ship explicitly and are committed in the attestation body.
- Per-account Merkle *proofs* remain an opt-in capability at the cost noted in
  doc 29 §1.2.

### 1.4 Sharded validator

Any of the above with `ShardingMode::Sharded`, holding one partition of state.

- **Stores** only its shard: at 16 shards, 6.2% of objects.
- **Executes** only the transactions it coordinates (the shard owning each
  transaction's lowest-ordered written object) — exactly one shard executes each
  transaction network-wide.
- **Apply cost** falls with shard count: 23.00 ms → 4.58 ms at 16 shards for the
  same round.
- **Important:** a sharded validator's Merkle root is a **per-shard root**. It
  converges with peers in its own shard, not with other shards; cross-shard state is
  reconciled through attested deltas. Monolithic deployments keep a single global
  root.

---

## 2. Validator lifecycle

1. **Identity.** Generate key material (`aevor keys`). The validator's consensus
   identity is bound into every attestation it seals, so it cannot be re-attributed.
2. **TEE bring-up.** Detect the platform and verify attestation locally
   (`aevor tee`) before joining. See §3.
3. **Registration and stake.** Register as a validator and stake (`aevor validator`).
4. **Configuration.** Set sharding mode, transport addresses, subnet policy
   (`aevor config`), then validate before starting.
5. **Produce and verify.** Start the node (`aevor node`); confirm participation
   (`aevor status`).
6. **Slashing exposure.** Evidence is emitted for an attestation that fails
   verification. Attribution is always to the **attested** producer, never to a
   claimed field — a forged lane cannot implicate another validator.
7. **Exit.** Unstake and withdraw per governance rules.

---

## 3. TEE operations, per platform

Common pattern for all five: build the enclave image → obtain its measurements →
register them in the network's code registry (a governance action) → distribute the
trust roots → run the validator inside the enclave.

| platform | build artefact | measurements to register | trust root the network configures |
|---|---|---|---|
| **AWS Nitro** | enclave image (EIF) | PCR0, PCR1, PCR2 (+PCR8 if signing enforced) | AWS Nitro root (pinned by fingerprint) |
| **Intel SGX** | signed enclave | MRENCLAVE, MRSIGNER | Intel SGX Root CA fingerprint |
| **AMD SEV-SNP** | guest image | launch MEASUREMENT (48 bytes) | AMD root (validates the chip's VCEK) |
| **ARM TrustZone** | trusted application | software-component measurements | device Initial Attestation Key |
| **RISC-V Keystone** | enclave binary | enclave hash, SM hash | device public key |

### 3.1 Device prerequisites

| platform | interface the node uses |
|---|---|
| AWS Nitro | NSM device (`/dev/nsm`) |
| Intel SGX | `/dev/attestation/user_report_data`, `/dev/attestation/quote` |
| AMD SEV-SNP | configfs-tsm (`/sys/kernel/config/tsm/report`, Linux 6.7+) |
| RISC-V Keystone | `/dev/keystone_enclave` |
| ARM TrustZone | OP-TEE (`/dev/tee0`) |

If none is present the node falls back to the simulation signature and produces no
hardware evidence. **That is correct for development and wrong for production** —
verify with `aevor tee` that real evidence is being produced before staking.

### 3.2 Trust roots are configuration, never evidence

Trust roots arrive as network configuration (genesis/governance). This matters: an
attacker who could supply their own root could forge anything. Consequently
**TrustZone and Keystone fail closed** when their root is absent — a node without
configured roots rejects that platform's evidence rather than accepting it.

### 3.3 Mixed-platform networks are a genesis decision

The code registry is platform-scoped, so a network chooses its exposure by which
identities it registers. **A network is only as strong as the weakest platform it
accepts.** Registering only SGX identities causes Nitro evidence to be rejected
regardless of validity. Decide this explicitly at genesis.

### 3.4 What failure looks like

| symptom | cause |
|---|---|
| attestation verification fails | wrong protocol binary, or evidence not binding this transition |
| measurement not in registry | validator running an unapproved build — the corruption-detection path working as intended |
| stale evidence rejected | clock skew beyond the freshness window |
| "no trust root configured" | TrustZone/Keystone without a distributed root (failing closed) |
| no hardware evidence produced | no TEE device present; node is in simulation |

---

## 4. Configuration reference

| setting | default | notes |
|---|---|---|
| sharding mode | **monolithic** | opt into `sharded { shard_id, total_shards }` for extreme scale |
| transport | **real TCP** (`ValidatorNetwork::bind`) | in-process transport is test-only |
| attestation | **real hardware when present** | simulation only off-hardware |
| pipeline depth | operator choice | rounds applied but not yet finalized; higher depth hides finality latency |
| subnet policy | per deployment | fee model, congestion targets, privacy floor |
| security level | per transaction | minimal → full, trading latency for confirmation breadth |

Every default is the production-safe choice; the alternative is always explicit.

---

## 5. Operating expectations

### 5.1 Throughput

- Aggregate = `N_lanes × per-lane production`. Adding *producers* adds throughput;
  adding verifiers adds resilience, not throughput.
- One verifier covers roughly 90–100 lanes before saturating. Past that, sharded
  verification bounds each validator's slice (measured 2–5 lanes as the network
  grows 8 → 128).
- Sharding does not increase production. It removes the **state ceiling** — without
  it, every validator must hold all state, so sustained high throughput eventually
  exceeds any single node.

### 5.2 What to alert on

- **Attestation verification failures** — either a misconfigured validator or an
  actual corruption attempt; both need investigation.
- **Rounds rejected for cross-lane conflicts** — indicates transaction routing is
  violating sender-sharding.
- **Incomplete shard certificate coverage** — a shard is silent; the round is
  correctly rejected rather than applied on a partial check.
- **`routed_to_other_shard` climbing** — a sharded producer receiving transactions it
  does not coordinate; a routing-layer problem, not a node fault.
- **`insufficient_funds` climbing** — the account-level abuse guard dropping
  unaffordable transactions, or genuine fee-market pressure.

### 5.3 Pre-promotion gate

Before promoting any build to devnet, testnet, or beta-mainnet:

```bash
bash test_aevor.sh          # non-zero exit blocks promotion
```

Gates: build → per-crate library tests → end-to-end consensus contract → named
security invariants → TEE attestation across all platforms → clippy. The security
invariants are listed individually so a regression in double-spend rejection or
attestation binding is unmissable in a CI log.

---

## 6. Known operational gaps

Deliberate, not oversights — each is scheduled:

1. **Registry governance distribution.** The code registry exists; distributing and
   updating it through on-chain governance is not wired. Today it is deployment
   configuration.
2. **Cross-shard transaction routing.** Classification and per-shard application are
   implemented; routing transactions to their coordinating shard across the network
   belongs to the mempool/routing layer.
3. **Sampled re-execution backstop.** Designed (doc 22 §5) as defence-in-depth
   against a *compromised* TEE; not built. The balance-delta sync it depends on is in
   place.
4. **Multi-machine orchestration.** Genesis tooling, peer discovery configuration,
   and topology management for devnet/testnet.
5. **Accelerator backends.** The `ComputeBackend` seam exists; concrete GPU/TPU/NPU
   backends are added per target hardware.
6. **Program deployment — the largest gap for dApps.** There is no `deploy` command
   or API endpoint. The execution engine runs programs and the transaction format
   carries bytecode, but nothing packages a program, submits it, and confirms its
   address. Until this exists, dApp development cannot begin. See §7.

---

## 7. CLI capability map (what exists, under which name)

An audit prompted by documentation that used older command names found that **most
capabilities exist** — under different, more conventional names — and that exactly
one is genuinely absent.

| capability | status | command |
|---|---|---|
| TEE platform detection / setup | ✅ | `aevor tee detect`, `aevor tee configure` |
| Attestation verification | ✅ | `aevor tee attest` |
| Key generation / management | ✅ | `aevor keys generate` / `import` / `export` / `list` |
| Subnet creation | ✅ | `aevor network subnet-create` |
| Bridges, peers | ✅ | `aevor network bridge`, `aevor network peers` |
| Node lifecycle | ✅ | `aevor node start` / `stop` / `restart` / `status` / `upgrade` |
| Validator registration and staking | ✅ | `aevor validator register` / `stake` / `unstake` |
| Slashing reports | ✅ | `aevor validator slash-report` |
| Governance | ✅ | `aevor governance propose` / `vote` / `delegate` |
| Configuration | ✅ | `aevor config show` / `validate` / `set` / `export` |
| Status queries | ✅ | `aevor status node` / `network` / `validators` / `consensus` |
| Test suite | ✅ | `bash test_aevor.sh` (correctly *not* a node command) |
| Benchmarking | ✅ | `bash test_aevor.sh --bench` |
| **Program deployment** | ⛔ **missing** | — |

### What deployment needs

The gap is narrow and well-defined, which is why it is worth stating precisely
rather than leaving as "dApp tooling":

1. **Packaging** — take compiled program bytecode and produce a deployment
   transaction with the correct read/write set (the program's own storage object).
2. **Submission** — a path from CLI/API into the node's transaction intake. The
   engine accepts `Vec<SignedTransaction>` today; what is missing is the
   externally-reachable submit endpoint plus mempool admission.
3. **Confirmation** — return the deployed program's object id once the transaction
   is included and the security level's confirmation threshold is met.
4. **Invocation** — a `call` path that constructs a transaction against a deployed
   program's object id.

Items 2 and 4 also unblock ordinary transaction submission, which no external
client can currently do. This is therefore the correct next *build* item after
devnet orchestration, and it is a prerequisite for the faucet and explorer to be
useful.
