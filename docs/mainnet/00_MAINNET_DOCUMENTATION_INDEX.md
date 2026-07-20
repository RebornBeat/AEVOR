# AEVOR Mainnet Documentation — Master Index & Production Plan

This is the catalog of the documentation set AEVOR needs for a mainnet launch, organized by audience and **prioritized** so it can be produced systematically rather than all at once. It is the roadmap for the "200+ docs" effort.

**Priorities**
- **P0 — Launch-blocking.** Without these a user/dev/validator literally cannot start. Produce first.
- **P1 — Launch-week.** Needed for a credible launch; can trail P0 by days.
- **P2 — Post-launch.** Depth, edge cases, advanced topics.

**Scale.** The parts below enumerate ~210 documents. That is the "200+" — and it is why this index exists: to make the set tractable and to avoid duplicating the substantial *engineering-review* docs already written (`aevor-review/00`–`12`), which are the source of truth these user-facing docs will distill.

**Status legend:** ☐ not started · ◐ drafted · ☑ done. Everything is ☐ today except where noted.

---

## Part 1 — Getting Started (end users) · ~14 docs
The absolute on-ramp. A newcomer goes from zero to a verified transaction.

- P0 · 1.01 What is AEVOR? (one-page orientation)
- P0 · 1.02 Install a wallet
- P0 · 1.03 Create and back up an account (seed, key rotation basics)
- P0 · 1.04 Get testnet tokens (faucet)
- P0 · 1.05 Send your first transaction
- P0 · 1.06 Check a transaction and its finality
- P1 · 1.07 Understanding security levels (Minimal→Full) as a user
- P1 · 1.08 Public vs private transactions (what others can see)
- P1 · 1.09 Fees: when you pay, when you don't (feeless subnets)
- P1 · 1.10 Wallet security best practices
- P1 · 1.11 Recovering / rotating a key without a new wallet
- P2 · 1.12 Hardware-wallet integration
- P2 · 1.13 Post-quantum migration for your account (what/when)
- P2 · 1.14 Troubleshooting common user errors

## Part 2 — Core Concepts (understanding AEVOR) · ~18 docs
The mental model. Distilled from `aevor-review/00`, `08`, `12`.

- P0 · 2.01 Proof of Uncorruption in plain terms
- P0 · 2.02 Why TEE attestation replaces re-execution (the speed story)
- P0 · 2.03 The dual-DAG: micro-DAG (conflicts) + macro-DAG (blocks)
- P0 · 2.04 Deterministic finality: "valid until proven corrupted"
- P1 · 2.05 Security Level Acceleration explained
- P1 · 2.06 Mixed privacy: the four object privacy levels
- P1 · 2.07 The five TEE platforms and cross-attestation
- P1 · 2.08 Uncorrupted frontier & real-time corruption detection
- P1 · 2.09 How AEVOR scales without a throughput ceiling
- P1 · 2.10 No-degradation-as-validators-join (BLS aggregate finality) — *distills review §5.4*
- P1 · 2.11 Hybrid trust: PoU + staking/slashing
- P2 · 2.12 AEVOR vs PoW/PoS (honest comparison)
- P2 · 2.13 AEVOR vs BFT chains and the decentralization trade (honest Sui framing)
- P2 · 2.14 Cryptography overview (BLAKE3, Ed25519, BLS12-381, ML-DSA, Bulletproofs)
- P2 · 2.15 Post-quantum readiness
- P2 · 2.16 The object model & ownership
- P2 · 2.17 Consensus time authority (logical ordering)
- P2 · 2.18 Glossary

## Part 3 — Developer Guides (building on AEVOR) · ~30 docs
Everything a dApp developer needs.

- P0 · 3.01 Developer quickstart (hello-world dApp)
- P0 · 3.02 Local devnet setup
- P0 · 3.03 The object model for developers
- P0 · 3.04 Writing a smart contract (AevorVM / Move) — intro
- P0 · 3.05 Building, testing, deploying a contract
- P0 · 3.06 Transaction structure & signing (any scheme)
- P1 · 3.07 Reading state with verified Merkle proofs
- P1 · 3.08 Privacy-aware programming (Public/Protected/Private/Confidential objects)
- P1 · 3.09 Confidential computation with TEE
- P1 · 3.10 Confidential amounts with range proofs (Bulletproofs)
- P1 · 3.11 Parallelism-friendly contract design (avoiding conflicts)
- P1 · 3.12 Events & subscriptions
- P1 · 3.13 Client SDKs overview (per language)
- P1 · 3.14 Error handling & transaction lifecycle for devs
- P2 · 3.15 Cross-object / multi-object transactions
- P2 · 3.16 Gas/fees model for developers (and feeless subnets)
- P2 · 3.17 Upgrading contracts
- P2 · 3.18 Formal verification & testing patterns
- P2 · 3.19 Oracles & external data
- P2 · 3.20 Bridges & cross-network calls
- P2 · 3.21 Indexing & querying at scale
- P2 · 3.22 Name service (NS) integration
- P2 · 3.23 Best practices & security checklist for dApps
- P2 · 3.24–3.30 Worked examples (DEX, NFT, payments, DAO, confidential voting, escrow, subscription)

## Part 4 — RPC & API Reference · ~28 docs
The interface contract. One doc per method family + transport.

- P0 · 4.01 RPC overview & endpoints
- P0 · 4.02 Authentication & rate limits
- P0 · 4.03 JSON-RPC: submit transaction
- P0 · 4.04 JSON-RPC: query object / account / state
- P0 · 4.05 JSON-RPC: get transaction & finality status
- P0 · 4.06 JSON-RPC: get block / frontier
- P1 · 4.07 JSON-RPC: Merkle proof retrieval & verification
- P1 · 4.08 WebSocket subscriptions: new blocks, finality
- P1 · 4.09 WebSocket subscriptions: object/account changes
- P1 · 4.10 WebSocket subscriptions: events
- P1 · 4.11 Attestation & security-level queries
- P1 · 4.12 NS (name service) RPC
- P1 · 4.13 Validator/committee/staking RPC
- P1 · 4.14 Error codes reference
- P1 · 4.15 Pagination, batching, and limits
- P2 · 4.16 Client library: (language A) reference
- P2 · 4.17 Client library: (language B) reference
- P2 · 4.18 Client library: (language C) reference
- P2 · 4.19 gRPC interface (if exposed)
- P2 · 4.20 Running your own RPC/archive node
- P2 · 4.21 Deprecation & versioning policy
- P2 · 4.22–4.28 Per-method deep dives / examples

## Part 5 — Running a Node · ~26 docs
Full node, light node, and **validator on TEE**. Distilled from `aevor-review/05` (TEE dev guide).

- P0 · 5.01 Node types overview (full / validator / light)
- P0 · 5.02 Hardware & OS requirements (incl. per-TEE-platform matrix)
- P0 · 5.03 Install the node software
- P0 · 5.04 Run a full node (sync, config, ports)
- P0 · 5.05 **Run a validator: overview & prerequisites**
- P0 · 5.06 **Provision a TEE for validation (platform-agnostic steps)**
- P0 · 5.07 **Generate consensus (BLS) & signing (Ed25519) keys**
- P0 · 5.08 **Stake, register, and join the validator set**
- P1 · 5.09 Validator configuration reference
- P1 · 5.10 Monitoring & metrics (health, attestation, finality participation)
- P1 · 5.11 Run a light node (proof verification, trusted root)
- P1 · 5.12 Upgrades & version management
- P1 · 5.13 Slashing: what triggers it and how to avoid it
- P1 · 5.14 Key management & rotation for validators
- P1 · 5.15 Backup, failover, and high availability
- P1 · 5.16 Networking & firewall setup
- P2 · 5.17 Performance tuning (distills review `Performance Tuning`)
- P2 · 5.18 Running an archive node
- P2 · 5.19 Running in a permissioned subnet
- P2 · 5.20 Disaster recovery
- P2 · 5.21 Validator economics & reward optimization
- P2 · 5.22 Decommissioning a validator
- P2 · 5.23–5.26 Per-cloud/bare-metal deployment recipes

## Part 6 — TEE & Attestation (per platform) · ~22 docs
The hardware-trust core. One setup + attestation guide per platform ×5, plus cross-cutting.

- P0 · 6.01 TEE & attestation overview (why, threat model)
- P0 · 6.02 Intel SGX: setup for validation
- P0 · 6.03 AMD SEV: setup for validation
- P0 · 6.04 ARM TrustZone: setup for validation
- P0 · 6.05 RISC-V Keystone: setup for validation
- P0 · 6.06 AWS Nitro Enclaves: setup for validation
- P1 · 6.07 Verifying an attestation (developer/operator)
- P1 · 6.08 Cross-platform attestation & why it matters
- P1 · 6.09 Measurement, SVN, and production vs debug enclaves
- P1 · 6.10 Attestation freshness & nonce handling
- P1 · 6.11 Handling TEE vulnerabilities & platform revocation
- P2 · 6.12–6.16 Per-platform troubleshooting (×5)
- P2 · 6.17 Remote attestation services & provisioning
- P2 · 6.18 TEE-as-a-Service overview
- P2 · 6.19 Sealing & secret management inside the enclave
- P2 · 6.20 Performance characteristics per platform
- P2 · 6.21 Migrating between TEE platforms
- P2 · 6.22 Security hardening checklist

## Part 7 — Deployment Models & Subnets · ~18 docs
Permissionless / permissioned / feeless / hybrid. Grounded in `aevor-config/src/deployment` + review §6.

- P0 · 7.01 Deployment models overview (public / enterprise subnet / hybrid)
- P0 · 7.02 The three independent axes: permission × fee × privacy
- P1 · 7.03 Deploy a permissioned subnet
- P1 · 7.04 Deploy a **feeless** permissioned subnet (resource-allocation economics)
- P1 · 7.05 Deploy a permissioned subnet **with fees**
- P1 · 7.06 Hybrid deployment (public + private)
- P1 · 7.07 Subnet governance & membership control
- P1 · 7.08 Cross-subnet interoperability & the frontier
- P2 · 7.09 Subnet resource allocation & quotas
- P2 · 7.10 Privacy policy per subnet
- P2 · 7.11 Bridging a subnet to public mainnet
- P2 · 7.12 Enterprise onboarding playbook
- P2 · 7.13 Compliance & data-residency options
- P2 · 7.14 Subnet monitoring & SLAs
- P2 · 7.15 Migrating a subnet between modes
- P2 · 7.16–7.18 Reference configs (public / feeless-subnet / hybrid)

## Part 8 — Economics & Governance · ~16 docs
Distilled from `Tokenomics.md`.

- P0 · 8.01 Token overview & utility
- P0 · 8.02 Fees vs feeless: how each works
- P1 · 8.03 Staking: delegators & validators
- P1 · 8.04 Rewards & inflation
- P1 · 8.05 Slashing policy (graduated)
- P1 · 8.06 Governance overview & proposal lifecycle
- P1 · 8.07 Voting & on-chain parameters
- P2 · 8.08 Treasury & funding
- P2 · 8.09 Feeless-subnet economics in depth
- P2 · 8.10 Fee markets & priority
- P2 · 8.11 Validator economics modeling
- P2 · 8.12 Token distribution & vesting
- P2 · 8.13 Governance security & timelocks
- P2 · 8.14 Emergency governance & upgrades
- P2 · 8.15 Cross-subnet economic coordination
- P2 · 8.16 Economic parameters reference

## Part 9 — Security & Operations · ~14 docs
- P0 · 9.01 Security model overview (what PoU guarantees, what it assumes)
- P1 · 9.02 Key management (users, devs, validators)
- P1 · 9.03 Incident response & the corruption-detection path
- P1 · 9.04 Upgrade & fork policy
- P1 · 9.05 Bug bounty & responsible disclosure
- P2 · 9.06 Auditing & formal methods
- P2 · 9.07 Threat model: TEE compromise scenarios & mitigations
- P2 · 9.08 Network attacks & defenses
- P2 · 9.09 Data privacy & confidentiality guarantees
- P2 · 9.10 Post-quantum transition operations
- P2 · 9.11 Monitoring & alerting reference
- P2 · 9.12 Backup & recovery reference
- P2 · 9.13 Compliance overview
- P2 · 9.14 Security FAQ

## Part 10 — Protocol Reference (spec-level) · ~24 docs
The authoritative reference; distills `WHITEPAPER.md` + `aevor-review/04`, `08`.

- P1 · 10.01 Transaction format & lifecycle
- P1 · 10.02 Block & frontier structure
- P1 · 10.03 Micro-DAG conflict model (pre-execution rejection)
- P1 · 10.04 Macro-DAG concurrent block production
- P1 · 10.05 Finality & BLS aggregate proofs
- P1 · 10.06 Attestation format (per platform)
- P1 · 10.07 Security-level state machine
- P2 · 10.08 State model & Merkle commitment (sparse Merkle)
- P2 · 10.09 Consensus messages & flow
- P2 · 10.10 Cryptographic primitives spec
- P2 · 10.11 AevorVM instruction set & execution
- P2 · 10.12 NS protocol & DNSSEC
- P2 · 10.13 Networking & gossip protocol
- P2 · 10.14 Wire formats & serialization
- P2 · 10.15 Privacy object model spec
- P2 · 10.16 Bridge protocol
- P2 · 10.17 Governance protocol
- P2 · 10.18 Economic protocol (fees/feeless/slashing)
- P2 · 10.19 Deployment/subnet protocol
- P2 · 10.20 Error & status codes (canonical)
- P2 · 10.21 Genesis & chain parameters
- P2 · 10.22 Versioning & upgrade protocol
- P2 · 10.23 Reference test vectors
- P2 · 10.24 Formal properties & invariants

---

## Production sequence (recommended)
1. **P0 wave (~40 docs):** Parts 1 (1.01–1.06), 2 (2.01–2.04), 3 (3.01–3.06), 4 (4.01–4.06), 5 (5.01–5.08), 6 (6.01–6.06), 7 (7.01–7.02), 8 (8.01–8.02), 9 (9.01), 10 (—). This is a launchable set: a user can transact, a dev can build, a validator can join on TEE, and the deployment axes are documented.
2. **P1 wave (~80 docs):** credible-launch depth across all parts.
3. **P2 wave (~90 docs):** advanced/reference/edge.

## Sourcing (avoid duplication)
Each user-facing doc **distills** an existing engineering-review doc rather than re-deriving it — the review set (`aevor-review/00`–`12`) and `WHITEPAPER.md`/`Tokenomics.md` are the source of truth. Single-source-of-truth discipline applies to docs too: concepts live in one canonical place (Part 2 / Part 10) and other docs link to them.

## What I'll do next
On your go, I produce the **P0 wave** first, in batches, starting with the launch-blocking on-ramp (Part 1 user quickstart) and the **validator-on-TEE** path (Part 5.05–5.08 + Part 6 platform setup) since those are the highest-leverage for a mainnet. Each batch ships as real Markdown files with the same integrity discipline as the code milestones.
