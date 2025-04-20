# Aevor Blockchain


**Aevor** is a next-generation Layer 1 blockchain platform built around a revolutionary **Dual-DAG Proof of Uncorruption (PoU)** consensus mechanism. Aevor combines parallelized execution, fine‑grained transaction superposition, and a tiered Security Level Accelerator to deliver exceptional throughput, near-instant finality, and strong privacy—without sacrificing decentralization.

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)  [![Docs](https://img.shields.io/badge/docs-latest-blue)](https://docs.aevor.io)

---
## 🌟 Overview
Aevor’s architecture evolves beyond traditional blockchain designs by integrating two complementary DAG layers and leveraging Trusted Execution Environments (TEEs) for execution integrity:

- **Micro-DAG**: Transaction-level dependencies based on object access enable maximal parallelism and precise conflict management.
- **Macro-DAG**: Block-level references replace linear chains, allowing concurrent block production without leader bottlenecks.
- **Proof of Uncorruption (PoU)**: TEEs guarantee code and state integrity; corrupted paths are detected and pruned in real time.
- **Security Level Accelerator**: Tiered validation phases (Minimal ▶ Basic ▶ Strong ▶ Full) optimized by network topology and validator reputation.

These innovations combine to deliver:

| Metric                         | Aevor V1 Value                   |
|--------------------------------|----------------------------------|
| **Standard TPS**               | 200 000 + transactions/s         |
| **Burst TPS**                  | 1 000 000 + transactions/s       |
| **Latency**                    | 20–50 ms (entry to micro-DAG)    |
| **Finality (Minimal)**         | 20–50 ms                          |
| **Finality (Basic)**           | 100–200 ms                        |
| **Finality (Strong)**          | 500–800 ms                        |
| **Finality (Full)**            | < 1 s                             |
| **Block Time**                 | Continuous (DAG-based)           |
| **Gas Efficiency**             | ~10× traditional L1s             |

---
## 🚀 Key Features

### 🛡️ Dual-DAG PoU Consensus
- **Micro-DAG Transaction Dependencies**: Object‑centric transaction DAG for parallel execution.
- **Macro-DAG Block Structure**: Blocks reference multiple parents; concurrent block creation.
- **TEE Integrity & Corruption Monitoring**: Hardware-backed attestations; real-time validation of execution environments.

### 🔒 Private & Confidential Execution
- **TEE-based Contract Execution**: Encrypted smart contracts with privacy preservation.
- **Optional ZK Proofs**: Zero-knowledge proofs for selective transparency.

### ⚡ Security Level Accelerator
- **Minimal Security**: Single validator confirmation (~20–50 ms)
- **Basic Security**: 10–20% validator confirmations (~100–200 ms)
- **Strong Security**: >1/3 validator confirmations (~500–800 ms)
- **Full Security**: >2/3 validator confirmations (< 1 s)
- **BLS Signature Aggregation**: Compact multi‑validator proofs reduce network overhead.
- **Topology-Aware Solicitation**: Prioritized requests to nearest validators for speed.

### 🌐 V1 Enhancements
The initial release (V1) further integrates:
- **Hybrid Topology Mesh**: RDMA‑style transports for sub‑5 ms propagation.
- **zk-SNARK Checkpoints**: Succinct proofs of macro‑DAG state for instant light‑client sync.
- **Predictive DAG Prefetching**: Warm micro-DAG caches based on incoming cluster forecasts.

These enhancements **reduce end-to-end latency by 10–20%** under load (e.g., micro-DAG inclusion and propagation) but do **not** increase peak throughput.

### 🏗️ V2 Roadmap (Experimental)
- **Dynamic Micro‑DAG Sharding**: Partition DAG by object neighborhoods for hotspot isolation.
- **Off‑Chain Channels**: Fast‑path state channels with on‑chain commits of final deltas.

> **Note:** V2 features are experimental; benchmarks to follow in Q3/Q4 2025.

---
## 🔬 Comparison with Alternatives

| Feature                  | Aevor V1                | Aevor V2 (Future) | Mysticeti v1       | Mysticeti v2            |
|--------------------------|-------------------------|-------------------|--------------------|-------------------------|
| **Standard TPS**         | 200 000 +               | TBD               | ~50 000            | ~200 000 sustained      |
| **Burst TPS**            | 1 000 000 +             | TBD               | ~50 000            | ~300 000 before 1 s      |
| **Latency**              | 20–50 ms                | TBD               | ~400 ms            | ~250 ms fast-path       |
| **Finality (Minimal)**   | 20–50 ms                | TBD               | N/A                | ~250 ms (50-validator P50 fast-path) |
| **Finality (Basic)**     | 100–200 ms              | TBD               | ~500 ms (50-validator WAN commit) | ~500 ms (3-message WAN) |
| **Finality (Strong)**    | 500–800 ms              | TBD               | N/A                | N/A                     |
| **Finality (Full)**      | < 1 s                   | TBD               | N/A                | N/A                     |
| **Privacy**              | Optional (TEE & ZK)     | Optional          | None               | Limited (planned)       |
| **Parallelism**          | Micro + Macro DAG       | Micro + Macro DAG | Block-level DAG    | Block-level + Sharding  |
| **Sharding**             | Natural via DAG         | Dynamic (future)  | None               | Horizontal via Remora   |
| **Decentralization**     | ✪ Full                  | ✪ Full            | ✪ Full             | ✪ Reduced               |

**Notes on Finality & Security:**  
- Mysticeti v1’s ~0.5 s WAN commit corresponds to a single-level confirmation similar to other DAG systems. It uses ~50 validators, offering no tiered security guarantees.  
- Mysticeti v2’s ~250 ms fast-path (P50) and ~500 ms WAN commit also rely on a fixed validator set without progressive thresholds.  
- Aevor’s multi‑level finality engages increasing validator subsets (from 1 to >2/3) to deliver clear security guarantees at each stage, resulting in both faster subjective finality and robust objective finality.

---
## 🏗️ Getting Started

### Prerequisites
- Rust 1.65+  
- Cargo  
- Docker (optional)

### Build & Run
```bash
git clone https://github.com/aevor/aevor.git
cd aevor
cargo build --release
./target/release/aevor start
```

_Or with Docker:_
```bash
docker pull aevor/node:latest
docker run -d -p 7777:7777 -p 8888:8888 -v aevor-data:/data aevor/node:latest
```

---
## 📚 Documentation
See [docs.aevor.io](https://docs.aevor.io) for detailed guides:
- Consensus & Dual-DAG
- Security Acceleration
- Transaction Superposition
- Smart Contracts (Move)
- Network Topology

---
## 🤝 Contributing
Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

---
## 📜 License
Aevor is open-source under the [MIT License](LICENSE).

---
*Built with ❤️ by the Aevor Team*

