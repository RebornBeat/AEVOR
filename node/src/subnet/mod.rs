//! Subnet deployment policy — the on-chain enforcement of the settings a subnet
//! launches with, built as a thin branch off the **one** canonical mainnet flow
//! rather than a parallel process.
//!
//! A subnet differs from mainnet only along three axes, and only where it must:
//! **economics** (feeless vs fee), **participation** (permissioned vs
//! permissionless), and an **enforced privacy baseline** (a minimum
//! [`PrivacyLevel`], exactly as an individual object carries its own). Everything
//! else — the transaction type, the VM, gas metering, PoU attestation, the
//! micro-DAG conflict rejection, privacy-boundary enforcement — is shared,
//! unchanged, with mainnet. Mainnet is simply [`SubnetPolicy::public_mainnet`].
//!
//! **Fees are single-source-of-truth.** A subnet carries the same
//! [`FeeConfig`](aevor_config::economics::FeeConfig) mainnet uses, and the fee it
//! charges is the *same* formula the VM's canonical `GasMeter` uses —
//! `fee = gas_used * gas_price` — with the price sourced from that `FeeConfig`.
//! A feeless subnet is just `FeeConfig::feeless()` (fees disabled), so its price
//! is zero. Because the fee model is the shared `FeeConfig`, any change to the
//! mainnet fee model is inherited by every subnet automatically — a subnet is
//! never pinned to a stale fee notion.

use aevor_config::deployment::SubnetDeploymentConfig;
use aevor_config::economics::FeeConfig;
use aevor_core::primitives::{Address, Amount, GasPrice};
use aevor_core::privacy::PrivacyLevel;

/// The policy a subnet enforces on every transaction and object it processes.
#[derive(Clone, Debug)]
pub struct SubnetPolicy {
    /// The canonical fee model — the **same** `FeeConfig` mainnet uses. Feeless
    /// subnets use [`FeeConfig::feeless`]. Sharing this struct means a subnet
    /// inherits any change to the mainnet fee model automatically.
    pub fee: FeeConfig,
    /// The minimum privacy level the subnet enforces. A dApp cannot deploy — and
    /// objects cannot be written — below this baseline.
    pub min_privacy_level: PrivacyLevel,
    /// When true, only `permitted` addresses may transact.
    pub permissioned: bool,
    /// Permitted participant addresses. Enforced only when `permissioned`.
    pub permitted: Vec<Address>,
}

impl Default for SubnetPolicy {
    fn default() -> Self {
        Self::public_mainnet()
    }
}

impl SubnetPolicy {
    /// Public mainnet: the default `FeeConfig` (fees on), fully open, `Public`
    /// baseline. This is the canonical flow every other subnet branches from.
    #[must_use]
    pub fn public_mainnet() -> Self {
        Self {
            fee: FeeConfig::default(),
            min_privacy_level: PrivacyLevel::Public,
            permissioned: false,
            permitted: Vec::new(),
        }
    }

    /// A feeless permissioned subnet with a chosen privacy baseline — the
    /// enterprise pattern: no fees ([`FeeConfig::feeless`]), closed participation,
    /// mandated privacy.
    #[must_use]
    pub fn feeless_permissioned(permitted: Vec<Address>, min_privacy_level: PrivacyLevel) -> Self {
        Self {
            fee: FeeConfig::feeless(),
            min_privacy_level,
            permissioned: true,
            permitted,
        }
    }

    /// A fee-charging public subnet at a fixed effective gas price (nano/gas),
    /// with a chosen privacy baseline. The price is pinned by setting both the
    /// base fee and the floor to `gas_price_nano`.
    #[must_use]
    pub fn fee_public(gas_price_nano: u64, min_privacy_level: PrivacyLevel) -> Self {
        Self {
            fee: FeeConfig {
                enabled: true,
                base_fee_nano: gas_price_nano,
                min_gas_price_nano: gas_price_nano,
                ..FeeConfig::default()
            },
            min_privacy_level,
            permissioned: false,
            permitted: Vec::new(),
        }
    }

    /// A public subnet with explicit congestion parameters — for tuning and
    /// simulation. `block_gas_limit` is the per-block gas budget, `target_bps`
    /// the utilization the controller steers toward, and `adjustment_bps` the max
    /// per-block base-fee change. Smaller budgets make congestion reachable in a
    /// test; production uses the large `FeeConfig::default` budget.
    #[must_use]
    pub fn public_with_congestion(
        base_fee_nano: u64,
        block_gas_limit: u64,
        target_bps: u32,
        adjustment_bps: u32,
        min_price: u64,
    ) -> Self {
        Self {
            fee: FeeConfig {
                enabled: true,
                base_fee_nano,
                min_gas_price_nano: min_price,
                block_gas_limit,
                target_utilization_bps: target_bps,
                fee_adjustment_bps: adjustment_bps,
            },
            min_privacy_level: PrivacyLevel::Public,
            permissioned: false,
            permitted: Vec::new(),
        }
    }

    /// The fully general constructor: a subnet supplies **its own** fee model.
    /// This is how a subnet uses a fee formula different from mainnet's — pass any
    /// `FeeConfig` (custom base fee, target utilization, adjustment rate), or
    /// `FeeConfig::default()` to share mainnet's exact model, or
    /// `FeeConfig::feeless()` for no fees at all. The three modes the operator can
    /// pick — mainnet's formula / their own / none — are all just a `FeeConfig`.
    #[must_use]
    pub fn with_fee_config(
        fee: FeeConfig,
        min_privacy_level: PrivacyLevel,
        permissioned: bool,
        permitted: Vec<Address>,
    ) -> Self {
        Self {
            fee,
            min_privacy_level,
            permissioned,
            permitted,
        }
    }

    /// A subnet with a **flat** fee that does not float with congestion — a fixed
    /// price per gas unit (`fee_adjustment_bps = 0`, so the base fee never moves).
    /// Useful for an enterprise subnet that wants perfectly predictable costs.
    /// Mainnet and the default subnet remain congestion-based; this is opt-in.
    #[must_use]
    pub fn flat_fee(gas_price_nano: u64, min_privacy_level: PrivacyLevel) -> Self {
        Self {
            fee: FeeConfig {
                enabled: true,
                base_fee_nano: gas_price_nano,
                min_gas_price_nano: gas_price_nano,
                fee_adjustment_bps: 0,
                ..FeeConfig::default()
            },
            min_privacy_level,
            permissioned: false,
            permitted: Vec::new(),
        }
    }

    /// Whether this subnet charges fees. Feeless subnets return `true` here.
    #[must_use]
    pub fn feeless(&self) -> bool {
        !self.fee.enabled
    }

    /// The effective gas price under this subnet's fee model, in nano/gas. Zero
    /// when feeless; otherwise the base fee floored at the minimum gas price.
    /// This is the network price a block's fee is computed at.
    #[must_use]
    pub fn effective_gas_price(&self) -> GasPrice {
        if self.fee.enabled {
            GasPrice(self.fee.base_fee_nano.max(self.fee.min_gas_price_nano))
        } else {
            GasPrice(0)
        }
    }

    /// The fee for gas consumed at the subnet's effective price. This is the
    /// **same formula** the VM's canonical `GasMeter::fee` uses —
    /// `fee = gas_used * gas_price` — so mainnet and subnets price gas
    /// identically, differing only in the price the shared `FeeConfig` yields.
    #[must_use]
    pub fn fee_for(&self, gas_used: u64) -> Amount {
        Amount::from_nano(u128::from(gas_used) * u128::from(self.effective_gas_price().0))
    }

    /// The per-transaction fee, capped by the sender's own `max_gas_price` (a
    /// field on the canonical transaction). The price a tx pays is
    /// `min(network price, its cap)` — the tx's gas fields are honored, exactly
    /// as on mainnet.
    #[must_use]
    pub fn fee_for_tx(&self, gas_used: u64, max_gas_price: GasPrice) -> Amount {
        let price = self.effective_gas_price().0.min(max_gas_price.0);
        Amount::from_nano(u128::from(gas_used) * u128::from(price))
    }

    /// Whether `participant` may transact on this subnet. A permissionless subnet
    /// admits everyone; a permissioned subnet admits only its permitted set.
    #[must_use]
    pub fn admits(&self, participant: Address) -> bool {
        !self.permissioned || self.permitted.contains(&participant)
    }

    /// Whether an object/dApp at `level` satisfies the subnet's privacy baseline.
    /// Privacy levels are ordered (`Public` < `Protected` < `Private`), so the
    /// object must be at least as private as the baseline.
    #[must_use]
    pub fn allows_privacy(&self, level: PrivacyLevel) -> bool {
        level >= self.min_privacy_level
    }

    /// Build a policy from the declarative subnet deployment config an operator
    /// writes. `fees_enabled` selects the shared mainnet `FeeConfig` or the
    /// feeless one; `enforced_privacy_level` names the baseline;
    /// `permitted_participants` are parsed as 32-byte hex addresses.
    ///
    /// # Errors
    /// Returns an error string if `enforced_privacy_level` is not a known level
    /// name (`public` / `protected` / `private`).
    pub fn from_deployment_config(cfg: &SubnetDeploymentConfig) -> Result<Self, String> {
        let min_privacy_level = match cfg.enforced_privacy_level.as_deref() {
            None | Some("public" | "Public") => PrivacyLevel::Public,
            Some("protected" | "Protected") => PrivacyLevel::Protected,
            Some("private" | "Private") => PrivacyLevel::Private,
            Some(other) => return Err(format!("unknown enforced privacy level: {other}")),
        };
        let fee = if cfg.fees_enabled {
            FeeConfig::default()
        } else {
            FeeConfig::feeless()
        };
        let permitted = cfg
            .permitted_participants
            .iter()
            .filter_map(|s| parse_hex_address(s))
            .collect();
        Ok(Self {
            fee,
            min_privacy_level,
            permissioned: cfg.permissioned,
            permitted,
        })
    }
}

/// Parse a 32-byte address from a hex string (with or without a `0x` prefix).
/// Returns `None` if the string is not exactly 64 hex characters.
fn parse_hex_address(s: &str) -> Option<Address> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Address(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_prices_gas_at_the_canonical_fee_config() {
        let m = SubnetPolicy::public_mainnet();
        assert!(!m.feeless());
        assert_eq!(m.effective_gas_price().0, 1_000);
        assert_eq!(m.fee_for(50).as_nano(), 50 * 1_000);
    }

    #[test]
    fn feeless_charges_nothing() {
        let feeless = SubnetPolicy::feeless_permissioned(vec![], PrivacyLevel::Private);
        assert!(feeless.feeless());
        assert_eq!(feeless.effective_gas_price().0, 0);
        assert_eq!(feeless.fee_for(1_000_000).as_nano(), 0);
    }

    #[test]
    fn fee_public_pins_the_price() {
        let s = SubnetPolicy::fee_public(2, PrivacyLevel::Public);
        assert_eq!(s.effective_gas_price().0, 2);
        assert_eq!(s.fee_for(1_000_000).as_nano(), 2_000_000);
    }

    #[test]
    fn with_fee_config_shares_mainnet_or_brings_its_own_or_none() {
        // Share mainnet's exact model.
        let same =
            SubnetPolicy::with_fee_config(FeeConfig::default(), PrivacyLevel::Public, false, vec![]);
        assert_eq!(same.effective_gas_price().0, 1_000);
        // Bring its own model (different base fee).
        let own = SubnetPolicy::with_fee_config(
            FeeConfig { base_fee_nano: 50, min_gas_price_nano: 50, ..FeeConfig::default() },
            PrivacyLevel::Public,
            false,
            vec![],
        );
        assert_eq!(own.effective_gas_price().0, 50);
        // None at all.
        let none =
            SubnetPolicy::with_fee_config(FeeConfig::feeless(), PrivacyLevel::Private, true, vec![]);
        assert!(none.feeless());
    }

    #[test]
    fn flat_fee_pins_price_and_disables_adjustment() {
        let flat = SubnetPolicy::flat_fee(500, PrivacyLevel::Public);
        assert_eq!(flat.effective_gas_price().0, 500);
        assert_eq!(flat.fee.fee_adjustment_bps, 0, "flat fee never floats with congestion");
    }

    #[test]
    fn per_tx_fee_is_capped_by_the_transactions_max_gas_price() {
        let m = SubnetPolicy::public_mainnet();
        assert_eq!(m.fee_for_tx(100, GasPrice(10)).as_nano(), 100 * 10);
        assert_eq!(m.fee_for_tx(100, GasPrice(100_000)).as_nano(), 100 * 1_000);
        let f = SubnetPolicy::feeless_permissioned(vec![], PrivacyLevel::Public);
        assert_eq!(f.fee_for_tx(100, GasPrice(100_000)).as_nano(), 0);
    }

    #[test]
    fn permissioned_admits_only_permitted() {
        let a = Address([1u8; 32]);
        let b = Address([2u8; 32]);
        let subnet = SubnetPolicy::feeless_permissioned(vec![a], PrivacyLevel::Public);
        assert!(subnet.admits(a));
        assert!(!subnet.admits(b));
        assert!(SubnetPolicy::public_mainnet().admits(b));
    }

    #[test]
    fn privacy_baseline_is_a_minimum() {
        let private_subnet = SubnetPolicy::feeless_permissioned(vec![], PrivacyLevel::Private);
        assert!(private_subnet.allows_privacy(PrivacyLevel::Private));
        assert!(!private_subnet.allows_privacy(PrivacyLevel::Protected));
        assert!(!private_subnet.allows_privacy(PrivacyLevel::Public));
        let public_subnet = SubnetPolicy::public_mainnet();
        assert!(public_subnet.allows_privacy(PrivacyLevel::Public));
        assert!(public_subnet.allows_privacy(PrivacyLevel::Private));
    }

    #[test]
    fn from_config_maps_feeless_permissioned_and_privacy() {
        let cfg = SubnetDeploymentConfig {
            subnet_id: "s1".into(),
            name: "enterprise".into(),
            permissioned: true,
            permitted_participants: vec![format!("0x{}", "11".repeat(32))],
            fees_enabled: false,
            fee_policy: None,
            enforced_privacy_level: Some("private".into()),
        };
        let policy = SubnetPolicy::from_deployment_config(&cfg).unwrap();
        assert!(policy.feeless());
        assert!(policy.permissioned);
        assert_eq!(policy.min_privacy_level, PrivacyLevel::Private);
        assert_eq!(policy.permitted, vec![Address([0x11; 32])]);
        assert_eq!(policy.fee_for(500).as_nano(), 0);
    }

    #[test]
    fn from_config_enables_mainnet_fee_model_when_fees_on() {
        let cfg = SubnetDeploymentConfig {
            subnet_id: "s3".into(),
            name: "public-subnet".into(),
            permissioned: false,
            permitted_participants: vec![],
            fees_enabled: true,
            fee_policy: None,
            enforced_privacy_level: None,
        };
        let policy = SubnetPolicy::from_deployment_config(&cfg).unwrap();
        assert!(!policy.feeless());
        assert_eq!(policy.effective_gas_price().0, 1_000);
    }

    #[test]
    fn from_config_rejects_unknown_privacy_level() {
        let cfg = SubnetDeploymentConfig {
            subnet_id: "s2".into(),
            name: "bad".into(),
            permissioned: false,
            permitted_participants: vec![],
            fees_enabled: true,
            fee_policy: None,
            enforced_privacy_level: Some("ultra".into()),
        };
        assert!(SubnetPolicy::from_deployment_config(&cfg).is_err());
    }
}
