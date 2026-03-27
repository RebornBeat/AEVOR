//! Network-level security: DDoS, Sybil, Eclipse protection.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkSecurityStatus { pub ddos_active: bool, pub sybil_score: u32, pub eclipse_risk: u8 }

pub struct DdosProtection { rate_limit_rps: u32 }
impl DdosProtection {
    pub fn new(rate_limit_rps: u32) -> Self { Self { rate_limit_rps } }
    pub fn is_rate_limited(&self, rps: u32) -> bool { rps > self.rate_limit_rps }
}

pub struct SybilResistance { min_stake: aevor_core::primitives::Amount }
impl SybilResistance {
    pub fn new(min_stake: aevor_core::primitives::Amount) -> Self { Self { min_stake } }
    pub fn passes(&self, stake: aevor_core::primitives::Amount) -> bool { stake >= self.min_stake }
}

pub struct EclipseAttackPrevention { min_diverse_peers: usize }
impl EclipseAttackPrevention {
    pub fn new(min_diverse_peers: usize) -> Self { Self { min_diverse_peers } }
    pub fn is_protected(&self, peer_count: usize) -> bool { peer_count >= self.min_diverse_peers }
}

pub struct NetworkSecurityMonitor {
    ddos: DdosProtection,
    sybil: SybilResistance,
    eclipse: EclipseAttackPrevention,
}
impl NetworkSecurityMonitor {
    pub fn new(rate_limit_rps: u32, min_stake: aevor_core::primitives::Amount, min_peers: usize) -> Self {
        Self {
            ddos: DdosProtection::new(rate_limit_rps),
            sybil: SybilResistance::new(min_stake),
            eclipse: EclipseAttackPrevention::new(min_peers),
        }
    }

    /// The `DDoS` protection component (rate limiting).
    pub fn ddos(&self) -> &DdosProtection { &self.ddos }

    /// The Sybil resistance component (minimum stake enforcement).
    ///
    /// Validators without sufficient stake are considered potential Sybil identities.
    pub fn sybil(&self) -> &SybilResistance { &self.sybil }

    /// The Eclipse attack prevention component (peer diversity).
    pub fn eclipse(&self) -> &EclipseAttackPrevention { &self.eclipse }

    /// Check whether a peer with `stake` passes Sybil resistance.
    pub fn passes_sybil_check(&self, stake: aevor_core::primitives::Amount) -> bool {
        self.sybil.passes(stake)
    }

    pub fn status(&self, rps: u32, peer_count: usize) -> NetworkSecurityStatus {
        NetworkSecurityStatus {
            ddos_active: self.ddos.is_rate_limited(rps),
            sybil_score: 0,
            eclipse_risk: if self.eclipse.is_protected(peer_count) { 0 } else { 100 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Amount;

    fn nano(n: u128) -> Amount { Amount::from_nano(n) }

    #[test]
    fn ddos_protection_rate_limited_above_threshold() {
        let prot = DdosProtection::new(100);
        assert!(prot.is_rate_limited(101));
        assert!(!prot.is_rate_limited(100));
        assert!(!prot.is_rate_limited(50));
    }

    #[test]
    fn sybil_resistance_passes_sufficient_stake() {
        let sr = SybilResistance::new(nano(1_000_000));
        assert!(sr.passes(nano(1_000_000)));
        assert!(sr.passes(nano(2_000_000)));
        assert!(!sr.passes(nano(999_999)));
    }

    #[test]
    fn eclipse_prevention_protected_when_enough_peers() {
        let ep = EclipseAttackPrevention::new(8);
        assert!(ep.is_protected(8));
        assert!(ep.is_protected(20));
        assert!(!ep.is_protected(7));
    }

    #[test]
    fn monitor_status_ddos_active_when_over_limit() {
        let mon = NetworkSecurityMonitor::new(100, nano(1_000), 4);
        let status = mon.status(200, 10);
        assert!(status.ddos_active);
    }

    #[test]
    fn monitor_status_no_ddos_under_limit() {
        let mon = NetworkSecurityMonitor::new(100, nano(1_000), 4);
        let status = mon.status(50, 10);
        assert!(!status.ddos_active);
    }

    #[test]
    fn monitor_status_eclipse_risk_100_below_min_peers() {
        let mon = NetworkSecurityMonitor::new(100, nano(1_000), 8);
        let status = mon.status(10, 5); // only 5 peers, need 8
        assert_eq!(status.eclipse_risk, 100);
    }

    #[test]
    fn monitor_status_eclipse_risk_zero_with_enough_peers() {
        let mon = NetworkSecurityMonitor::new(100, nano(1_000), 4);
        let status = mon.status(10, 10);
        assert_eq!(status.eclipse_risk, 0);
    }

    #[test]
    fn monitor_passes_sybil_check() {
        let mon = NetworkSecurityMonitor::new(100, nano(5_000), 4);
        assert!(mon.passes_sybil_check(nano(10_000)));
        assert!(!mon.passes_sybil_check(nano(1_000)));
    }
}
