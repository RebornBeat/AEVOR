# AEVOR Fee/Gas Analysis, Architecture Unification, and Sweet-Spot Confirmation

**Milestone 37.** This answers four questions directly: (1) is subnet handling a
clean branch off the *one* canonical mainnet flow, or a parallel process? (2) are
fees now single-source-of-truth with the original PoU/privacy/VM handling? (3) do
we have real gas/fee numbers to compare against other chains? (4) does the PoU
throughput sweet spot still hold once subnets are in the picture?

---

## 1. Architecture unification — one flow, branching only where it must

The concern was that `SubnetPolicy` / `open_on_subnet` / `new_simple` might have
created a *different* transaction pathway. They do not. The evidence:

**One transaction type.** `new_simple` is a convenience *builder* over the single
canonical `aevor_core::transaction::Transaction` (every field present:
`sender`, `sender_public_key`, `nonce`, `inputs`, `outputs`, `gas_limit`,
`max_gas_price`, …). It is the same constructor the real client path
(`aevor-client`) uses. There is no second transaction struct.

**One execution flow.** `open_on_subnet` does not fork execution — it calls the
same `open_with_backend` constructor and then sets the subnet policy. Every node,
mainnet or subnet, runs the *same* `process_block → verify_execute_commit →
ComposedExecutor::process_program_batch` pipeline: the same signature gate, the
same micro-DAG pre-execution conflict rejection, the same VM, the same PoU
attestation (`produce_attested_batch` / verify-by-attestation), the same
authenticated Merkle commitment.

**The subnet branches at exactly three points, and nowhere else:**

| Branch point | Where | What differs |
|---|---|---|
| Fee | `BlockOutcome.fee_charged = subnet.fee_for(gas_used)` | price sourced from the subnet's `FeeConfig` (feeless ⇒ 0) |
| Admission | `submit()` → `subnet.admits(sender)` | permissioned subnets reject non-permitted senders |
| Privacy baseline | `open_on_subnet` → `subnet.allows_privacy(dapp_privacy)` | below-baseline deployment rejected; objects stamped at level |

Mainnet is literally `SubnetPolicy::public_mainnet()`. So "mainnet" and "a subnet"
are the same code with a different policy value — update the mainnet flow and
every subnet inherits the change; a subnet is never pinned to a stale version.

---

## 2. Fees are now single-source-of-truth (the reconciliation)

**What was wrong:** the first cut of `SubnetPolicy` invented its own
`gas_price_nano`, disconnected from the canonical `FeeConfig` (base_fee 1000 nano,
min_gas_price 100) and from the VM's `GasMeter`. That was a real divergence.

**What is now true:** `SubnetPolicy` **carries the canonical `FeeConfig`** — the
same struct mainnet uses — and its fee is the **same formula** the VM's
`GasMeter::fee` uses:

```
fee = gas_used * gas_price          // identical to GasMeter::fee()
gas_price = FeeConfig.base_fee (floored at min_gas_price), or 0 when feeless
```

- `public_mainnet()` = `FeeConfig::default()` (price 1000 nano/gas).
- `feeless_permissioned(...)` = `FeeConfig::feeless()` (price 0).
- `fee_for_tx(gas, max_gas_price)` honors the **transaction's own** `max_gas_price`
  cap — the tx gas fields matter, exactly as on mainnet.

Because the fee model *is* the shared `FeeConfig`, any future change to mainnet
economics (base fee, EIP-1559-style adjustment via `fee_adjustment_bps` /
`target_utilization_bps`, min price) propagates to every subnet with no code
change. Gas metering itself is unchanged and already includes the VM gas
schedule's **TEE execution premium** — so these fees are the real
PoU-inclusive cost, not a figure that ignores attestation overhead.

---

## 3. Measured gas and fee — real numbers

Measured directly through the node (`bench_gas_and_fee_estimates`), at the
mainnet price of **1000 nano/gas** (1 nanoAVR = 1e-9 AVR):

| instructions/tx | gas/tx | mainnet fee (nanoAVR) | mainnet fee (AVR) |
|---:|---:|---:|---:|
| 3 (a trivial op) | 5 | 5,000 | 0.000005 |
| 30 | 50 | 50,000 | 0.00005 |
| 300 | 500 | 500,000 | 0.0005 |
| 3,000 (heavy contract) | 5,000 | 5,000,000 | 0.005 |

Gas is **instruction-and-argument based** (~1.67 gas per opcode here), so cost
scales with the actual work done — there is no inflated fixed floor. A **feeless
subnet charges 0** for any of these, by construction.

---

## 4. How cheap is it, vs other chains?

The honest comparison has two layers — **native-unit cost** (definite) and
**fiat cost** (depends on a token price that does not exist pre-mainnet).

**Native-unit magnitude.** A simple AEVOR tx costs **0.000005 AVR** at the
default price. Strikingly, that is the *same magnitude* as Solana's base fee of
0.000005 SOL per signature — both chains price a
simple transaction at 5e-6 of their native unit.

**Fiat, for context (early 2026, from public data):**
- **Solana**: averages around $0.017 per transaction as of early 2026, though they can spike during congestion; typical simple transfers are often approximately $0.00025 to $0.001 for standard transactions.
- **Ethereum L1**: a simple token transfer on Ethereum L1 can cost anywhere from a few dollars to over $20 USD, while more complex smart contract interactions for decentralised finance (DeFi) operations can exceed $100 USD during peak usage.

**Where AEVOR lands.** Because AEVOR's fee is `gas × price × (token price)` and the
token price is not yet set, the fiat cost is parametric: at a hypothetical
**$1/AVR** a simple tx is **$0.000005**; at a Solana-like **$150/AVR** it is
**~$0.00075** — i.e. in the same "small fraction of a cent" band as Solana and far
under Ethereum L1. And a **feeless subnet is exactly $0** regardless of token
price, which no fee-charging chain can match.

**The structural reason it stays cheap.** On Ethereum, fees spike because users
compete for a fixed block space. AEVOR removes that dynamic: throughput scales
horizontally with lanes and subnets (Section 5), so there is no congestion
auction forcing fees up. Low fees are a property of the architecture, not a
subsidy. Two honest caveats: the absolute fiat number depends on (a) the eventual
token price and (b) the `base_fee_nano` parameter, both TBD; and this compares
per-tx *fees*, not the different VMs' raw gas units.

---

## 5. PoU scaling with subnets, and the sweet spot

**Subnets do not change the PoU/throughput characteristics.** PoU attestation and
verify-by-attestation operate over *state transitions*, not fees or admission. A
subnet's blocks are produced, attested, and verified by the identical machinery.
The only per-block addition is computing `fee_for(gas_used)` — a single multiply,
negligible. So every PoU scaling result (M25–M33) applies **per subnet,
unchanged**:

- **Per-lane production** ≈ 10k tx/s single-core (the bottleneck), scaling with
  cores.
- **Verify-by-attestation** ≈ 973k tx/s single-core — ~95× over-provisioned
  vs production.
- **Finality** O(1) via BLS aggregate.
- **Aggregate = lanes × per-lane rate**: ~1M tx/s at 96 lanes, ~5.3M at 512,
  ~103M at 10,000 lanes.

**The sweet spot still holds** (from the combined study, M29/M33): the
verify-attest batch sweet spot is ~1k–10k tx (~1.1M tx/s peak), degrading past
~15k. That is a per-DAG property, so it holds **per subnet**. A multi-subnet
deployment's total throughput is the **sum** of its subnets' throughput — each
subnet is an independent Dual-DAG running at its own sweet spot. Subnets are thus
a second horizontal-scaling axis on top of lanes: `total ≈ Σ_subnets (lanes ×
per-lane)`.

**Formula confirmation.**
- Throughput: `aggregate = N_lanes × per_lane_rate`, per subnet; sum across subnets.
- Fee: `fee = gas_used × gas_price`, one formula, price from the shared `FeeConfig`
  (feeless ⇒ 0), tx capped by its `max_gas_price`.
- Both are unchanged by the subnet layer — subnets *reuse* them, they don't
  replace them.

---

## 6. Bottom line

- The subnet layer is a **clean branch** off one canonical flow (one tx type, one
  execution pipeline, one PoU path, one VM), diverging only at fee / admission /
  privacy-baseline. Update mainnet → subnets inherit it.
- Fees are **single-source-of-truth**: the shared `FeeConfig` + the VM's
  `gas × price` formula, with feeless as `FeeConfig::feeless()` and the tx's
  `max_gas_price` honored.
- A simple tx costs **0.000005 AVR** (~Solana's native-unit magnitude, far under
  Ethereum L1 in any plausible fiat mapping); feeless subnets cost **$0**; the
  cost is PoU-inclusive (TEE premium already in gas).
- The PoU **sweet spot is unchanged** by subnets and now composes across two
  horizontal axes (lanes within a subnet, subnets within a deployment).

**Not claimed:** a definitive USD/tx (needs a token price); full fee *settlement*
against account balances (fees are computed and reported, not yet debited from a
balance model — a separate, honestly-noted item). **Still open elsewhere:**
network transport, real TEE attestation (F-E1), and the docs fold (F-D).
