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
    pub fn status(&self, rps: u32, peer_count: usize) -> NetworkSecurityStatus {
        NetworkSecurityStatus {
            ddos_active: self.ddos.is_rate_limited(rps),
            sybil_score: 0,
            eclipse_risk: if self.eclipse.is_protected(peer_count) { 0 } else { 100 },
        }
    }
}
