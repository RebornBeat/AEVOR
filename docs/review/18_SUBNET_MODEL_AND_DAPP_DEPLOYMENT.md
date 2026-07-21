# AEVOR Subnet Model & dApp Deployment — Whitepaper Review + Enforcement

**Status:** F-C1 finalized (Milestone 36). This document reviews the subnet model
as the whitepaper specifies it, then maps each property to the code that now
enforces it end-to-end, and shows how a dApp deploys onto a subnet with settings.

---

## 1. The core idea: subnets carry policy, just as objects carry privacy

AEVOR already lets an **individual object** declare its own privacy level
(`Public` / `Protected` / `Private`), and that level is *architecturally
enforced* — a privacy violation is a rejection, never a silent downgrade
(whitepaper line 63). A **subnet** is the same idea one level up: a subnet
launches with a policy it enforces on *every* transaction and object it holds.

The whitepaper describes subnets differing along three **independent** axes:

| Axis | Whitepaper | Values |
|------|-----------|--------|
| **Economics** | "Feeless Permissioned Subnet Economics" (line 416) | feeless · fee-charging |
| **Participation** | "permissionless public networks … permissioned enterprise subnets … hybrid" (line 75) | permissionless · permissioned |
| **Privacy baseline** | "Permissioned Subnet Capabilities and Custom Privacy Policies" (lines 348, 408) | `Public` · `Protected` · `Private` minimum |

These are independent: a subnet can be *feeless + permissioned + Private-baseline*
(the classic enterprise subnet), or *fee + permissionless + Public-baseline*
(public mainnet), or any other combination. Multiple subnets with **different
baselines coexist** and interoperate — "privacy models that span multiple subnet
deployments with different privacy baselines" (line 1245).

---

## 2. Configuration → policy → enforcement

There are two layers, and they are now connected:

**Layer 1 — declarative config an operator writes** (`aevor-config`,
`SubnetDeploymentConfig`):

```rust
SubnetDeploymentConfig {
    subnet_id, name,
    permissioned: bool,                    // participation axis
    permitted_participants: Vec<String>,   // who may transact (hex addresses)
    fees_enabled: bool,                    // economics axis (false = feeless)
    fee_policy: Option<String>,
    enforced_privacy_level: Option<String>,// privacy baseline ("public"/"protected"/"private")
}
```

**Layer 2 — typed, enforced policy in the node** (`node::subnet::SubnetPolicy`):

```rust
SubnetPolicy {
    feeless: bool,
    gas_price_nano: u64,
    min_privacy_level: PrivacyLevel,   // the enforced baseline
    permissioned: bool,
    permitted: Vec<Address>,
}
```

`SubnetPolicy::from_deployment_config(&cfg)` bridges the two — parsing
`enforced_privacy_level` into a real `PrivacyLevel`, `fees_enabled = false` into
`feeless`, and the permitted addresses from hex. The config is the source of
truth; the policy is what the running node enforces.

The policy answers three questions, and the engine calls them at the right points:

- `fee_for(gas_used) -> Amount` — **zero on a feeless subnet**, else `gas_used * gas_price`.
- `admits(sender) -> bool` — permissionless admits everyone; permissioned admits only its list.
- `allows_privacy(level) -> bool` — is `level` at or above the baseline? (levels are ordered `Public < Protected < Private`).

---

## 3. How the three properties are enforced end-to-end

All three are covered by integration tests that drive a real `NodeEngine`
(`node/tests/end_to_end.rs`).

### 3.1 Feeless vs fee (the F-C1 core)

Every block records a `fee_charged: Amount` derived from the gas it consumed via
the subnet's `fee_for`. On a **feeless** subnet the fee is always zero even
though gas is really consumed; on a **fee** subnet it is `gas_used * price`.

> `feeless_subnet_charges_no_fee_fee_subnet_charges_gas`: the *same* batch pays
> `0` on a feeless subnet and `gas_used * 2` on a 2-nano/gas subnet.

This is the honest shape of "feeless": gas is still metered (it bounds work), but
the **fee** attached to that gas is zero. Metering and pricing are separate.

### 3.2 Enforced privacy baseline

A dApp deploys with a chosen object-privacy level via
`NodeEngine::open_on_subnet(dir, owner, subnet, dapp_privacy, security)`. If the
dApp's level is **below** the subnet baseline, deployment is **rejected outright**
— privacy is architecturally enforced, so you cannot run a `Public` dApp on a
`Private` subnet. At or above the baseline is accepted, and the node stamps the
objects it writes at the dApp's level.

> `subnet_privacy_baseline_rejects_below_and_stamps_at_level`: `Public` dApp on a
> `Private` subnet → error; `Private` dApp → accepted and stamped `Private`;
> `Private` dApp on a `Protected` subnet (above baseline) → accepted.

### 3.3 Permissioned admission

On a permissioned subnet, a transaction whose sender is not on the permitted list
is rejected before it can enter the mempool (`submit` returns `false`); a
permitted sender is admitted. A permissionless subnet admits everyone.

> `permissioned_subnet_admits_only_permitted_senders`: a tx from the permitted
> address is admitted; a tx from any other address is rejected.

---

## 4. How dApps work, by subnet setting

A dApp is deployed onto a subnet and inherits that subnet's rules. What changes
for the dApp, axis by axis:

**On a feeless subnet** the dApp's users pay nothing; the subnet operator absorbs
the (metered but unpriced) compute. Typical for an enterprise or civic deployment
where a sponsor runs the validators. **On a fee subnet** users pay `gas * price`
in the fee token; this is public mainnet's default.

**On a permissionless subnet** anyone can call the dApp. **On a permissioned
subnet** only permitted addresses can — the same dApp code, a closed audience.
Enterprise subnets layer additional organizational config on top
(`EnterpriseSubnetConfig`: compliance requirements, permitted jurisdictions, KYC'd
validators, audit logging, data-retention) without changing the dApp itself.

**Privacy baseline** sets the floor for the dApp's objects. A dApp can always be
*more* private than the subnet floor (a `Private` object on a `Protected` subnet
is fine), but never less. A dApp that needs public transparency simply cannot
deploy on a `Private`-baseline subnet — the mismatch is caught at deployment, not
discovered at runtime.

Because the axes are independent, the same dApp binary can be deployed onto very
different subnets — a public fee subnet for retail users and a feeless
permissioned `Private` subnet for an enterprise — and the platform enforces the
right rules in each, without the dApp having to special-case them.

---

## 5. Cross-subnet coordination

Subnets with **different** economics, participation, and privacy baselines
interoperate. The whitepaper's frontier/coordination layer maintains consistency
"regardless of subnet configuration differences, economic model variations, or
governance policy diversity" (line 1235), and cross-network conflicts are
**rejected before execution** rather than rolled back afterward (line 1251) —
the same pre-execution rejection discipline the micro-DAG uses within a subnet,
applied across subnet boundaries. Multi-subnet privacy coordination lets an
application span deployments with different baselines while keeping mathematical
guarantees about confidentiality (line 1245).

The multi-lane / cross-subnet *transport* that carries these operations between
live nodes is the remaining networking item (tracked separately); the subnet
**policy model** and its enforcement within a node are finalized here.

---

## 6. What is finalized vs what remains

**Finalized (Milestone 36):**
- `SubnetPolicy` with the three axes, typed, plus a `from_deployment_config` bridge.
- Feeless vs fee enforced end-to-end (`fee_charged` on every block).
- Privacy-baseline enforced at dApp deployment (below-baseline rejected; objects stamped at level).
- Permissioned admission enforced at `submit`.
- Five unit tests + three end-to-end tests.

**Remaining (tracked elsewhere, not part of F-C1):**
- Live multi-node / cross-subnet **transport** (gossip) — a networking property.
- Real **TEE attestation** (F-E1) — the biggest item, hardware-bound to test.
- Folding all of this into the README / whitepaper / mainnet docs (F-D, last).
