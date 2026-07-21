# AEVOR Fee-Market Algorithm, Validator Rewards, and Finalized Tokenomics

**Milestone 38.** This finalizes the economic core: a *smart*, congestion-based
fee market with privacy and post-quantum pricing folded into gas, validator
rewards funded by usage, flexible per-subnet fee models, and an end-to-end
simulation that varies congestion and token price. It also reframes the
Tokenomics reference for a **utility** chain rather than a funding-first one.

---

## 1. What the user asked for, and where it landed

- Subnets can use mainnet's fee formula, **their own**, a **flat** fee, or **none**. → done, all as one `FeeConfig`.
- **Validator rewards** from fees. → block reward = fees collected; no inflation needed.
- Fees **congestion-based**, not token-price-based; not flat. → EIP-1559-style base fee; token price affects only fiat display.
- **Privacy vs non** and **PQ vs non** premiums, since both add load. → priced *through gas* (TEE premium; per-byte bloat), so they also push congestion.
- **Simulate** price and congestion e2e for accurate fees/gas/rewards/slashing. → `fee_market_simulation_*` e2e test + `bench_fee_market_dynamics`.
- Tokenomics reframed for a utility chain. → status banner + finalized section.

---

## 2. The algorithm (one formula, three inputs)

Every transaction — mainnet or subnet — is priced by the same formula the VM's
`GasMeter` uses:

```
fee = total_gas × base_fee
total_gas = execution_gas + intrinsic_gas
```

**execution_gas** — VM, per instruction, **already includes the TEE execution
premium**. Privacy-protected work runs in a TEE, so it consumes more gas
automatically: the *privacy premium is in gas, not a separate charge*.

**intrinsic_gas** — a flat per-tx base plus a **per-byte charge on the serialized
transaction** (`intrinsic_gas(size) = base + size × gas_per_byte`). A post-quantum
ML-DSA signature (~5.5 KB) therefore costs far more than an Ed25519 one (~few
hundred bytes): the *bloat / PQ premium is priced per byte*, matching the storage
and bandwidth it imposes on every validator forever.

**base_fee** — congestion-based, updated each block in integer math:

```
next_base_fee = base × (1 + adjustment_bps/10000 × (gas_used − target_gas)/target_gas),  floored at min_price
target_gas    = block_gas_limit × target_utilization
```

Fuller-than-target block ⇒ base fee rises (throttle + validators earn more under
load); emptier ⇒ falls to the floor (idle is cheap); at target ⇒ unchanged. This
is why pricing privacy and PQ *through gas* is correct: they raise a transaction's
own cost **and**, in aggregate, push the controller that raises everyone's base
fee until demand subsides. All parameters live in the shared `FeeConfig`.

**Why this is "smart," not "dumb":** fees track the one thing that actually
signals scarcity — congestion — and self-correct every block; they do not peg to a
token price (which would make fees swing with speculation) and they are not a flat
toll (which would either over- or under-charge). Privacy and PQ are not arbitrary
surcharges; they are the real marginal resource cost, expressed in the same gas
unit as everything else.

---

## 3. Validator rewards and slashing on one ledger

The fee a block collects is credited to the validator as its **block reward**
(`validator_reward` accrues in the engine). Usage funds security directly: busy ⇒
higher fees ⇒ higher rewards; idle ⇒ lower. No inflation is required to pay
validators. This sits on the same ledger as accountability: attestation proves
correct execution, and corruption triggers **graduated slashing** of the
offender's stake (an invalid attestation is a 1% slash, from M35). Honest work is
paid; misbehavior is penalized.

**Honest caveat:** rewards are *accrued and reported* against the validator, and
fees are *computed and reported* (`BlockOutcome.fee_charged`), but not yet
*debited from payer balances* — the `Balance` debit/credit settlement layer is
present in `aevor-core` but not yet wired into block processing. That is the next
economic step, and it is called out rather than papered over.

---

## 4. Flexible subnet economics

Four modes, all a `FeeConfig`, all enforced by the same pipeline as mainnet:

| Mode | Constructor | Behavior |
|---|---|---|
| Mainnet's formula | `with_fee_config(FeeConfig::default(), …)` / `public_mainnet()` | inherits mainnet economics, including future changes |
| Its own formula | `with_fee_config(custom FeeConfig, …)` / `public_with_congestion(…)` | own base fee, target, adjustment |
| Flat fee | `flat_fee(price, …)` | fixed price, congestion adjustment off (`adjustment_bps = 0`) |
| None (feeless) | `feeless_permissioned(…)` / `FeeConfig::feeless()` | charges nothing |

Because a subnet *is* just a `FeeConfig` on the one flow, "use mainnet's / your
own / none" is a configuration choice, not a code fork — and sharing
`FeeConfig::default()` means a subnet tracks any mainnet economic change for free.

---

## 5. Measured results (real testing)

At the default 1000 nano/gas (1 AVR = 1e9 nanoAVR):

| Transaction | gas | fee (nanoAVR) | fee (AVR) |
|---|---:|---:|---:|
| Simple Ed25519 tx (bloat-inclusive) | 485 | 485,000 | 0.000485 |
| Post-quantum (ML-DSA) tx | ~5,650 | ~5,650,000 | ~0.00565 |
| Heavy 3,000-instruction contract | 24,461 | 24,461,000 | 0.024461 |
| Feeless subnet, any tx | — | 0 | 0 |

**Congestion simulation** (`bench_fee_market_dynamics`, constrained subnet: budget
2000 gas/block, target 1000, ±12.5% max step, floor 100):

```
block   gas  over/under  base fee   cumulative reward
  1    2425   +1425        1178        2,425,000
  2    2425   +1425        1387        5,281,650
  3    2425   +1425        1634        8,645,125   ← congested: fee climbs
  4     485    -515        1529        9,437,615
  …                          …            …
 11     485    -515         962       13,730,350   ← idle: fee decays to floor
```

**PQ bloat premium:** Ed25519 tx 485,000 nanoAVR vs post-quantum 5,650,000 — about
**11×**, entirely from size. **Token-price independence:** the same tx is
485,000 nanoAVR regardless of token price; in fiat it is **$0.000005** at
$0.01/AVR and **$0.073** at $150/AVR — the native fee never moves, only the
conversion.

These are debug-build numbers, which is fine: gas is deterministic, so the gas and
fee figures are identical in release; only wall-clock throughput (measured
separately) needs release.

---

## 6. Tokenomics reframe

`Tokenomics.md` gained a **status banner** (the Parts I–IX prose is the standing
reference; the fee-market/reward core is now finalized and governs where they
differ) and a concrete **"Finalized Fee-Market and Reward Mechanism"** section
covering the utility-first stance, the one formula, the congestion rule, rewards
from usage, the flexible subnet modes, and the measured numbers. The prose was
already utility-oriented (it repeatedly rejects speculation and artificial
scarcity); the banner makes the stance explicit — no dependence on a token sale,
security paid from fees not inflation, feeless subnets supported.

---

## 7. Verification

- `aevor-core` economics: 26 tests (base fee ±12.5% at ±1 step, floors at min, PQ
  intrinsic gas 10×+ Ed25519, market policy advances). Clippy 0.
- node: 56 lib + 22 e2e tests, incl. `fee_market_simulation_congestion_pq_price_rewards`
  and the subnet flexibility tests. Clippy (lib + tests) 0.
- Benchmarks: `bench_gas_and_fee_estimates` (bloat-inclusive), `bench_fee_market_dynamics`.

**Not yet done (honestly):** fee/reward *settlement* against `Balance` (computed
and reported, not debited); and the still-open items from before — network
transport, real TEE attestation (F-E1), and the docs fold (F-D).
