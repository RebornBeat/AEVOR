//! Deterministic finality: proofs, gadgets, immediate confirmation.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::{
    FinalityProof, MathematicalCertainty, DeterministicFinality,
};
use aevor_core::consensus::SecurityLevel;
use aevor_core::primitives::Hash256;

/// The finality gadget: determines when a block has achieved finality.
pub struct FinalityGadget {
    required_level: SecurityLevel,
}

impl FinalityGadget {
    pub fn new(required_level: SecurityLevel) -> Self {
        Self { required_level }
    }

    pub fn is_final(&self, proof: &FinalityProof) -> bool {
        proof.security_level >= self.required_level
    }
}

/// Immediate finality confirmation for Minimal security.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImmediateFinalityConfirmation {
    pub item_hash: Hash256,
    pub confirmed_at_ms: u64,
    pub security_level: SecurityLevel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, ValidatorWeight};
    use aevor_core::consensus::{
        ConsensusTimestamp, FinalityProof, MathematicalCertainty, SecurityLevel,
    };

    fn proof(level: SecurityLevel) -> FinalityProof {
        FinalityProof {
            signatures: vec![],
            aggregate_signature: vec![],
            participant_bitmap: vec![],
            total_weight: ValidatorWeight::from_u64(100),
            security_level: level,
        }
    }

    fn certainty(level: SecurityLevel) -> MathematicalCertainty {
        MathematicalCertainty {
            item_hash: Hash256([0xAB; 32]),
            finality_proof: proof(level),
            security_level: level,
            timestamp: ConsensusTimestamp::new(1, 0, 100),
        }
    }

    // ── FinalityGadget — progressive security ─────────────────────────────
    // Whitepaper: "Applications that require minimal confirmation times for
    // low-value transactions can operate with basic security levels that
    // provide immediate mathematical verification, while applications that
    // require maximum security for high-value operations can utilize enhanced
    // security levels."

    #[test]
    fn gadget_accepts_exact_security_level() {
        let g = FinalityGadget::new(SecurityLevel::Basic);
        assert!(g.is_final(&proof(SecurityLevel::Basic)));
    }

    #[test]
    fn gadget_accepts_higher_than_required() {
        let g = FinalityGadget::new(SecurityLevel::Basic);
        assert!(g.is_final(&proof(SecurityLevel::Full)));
    }

    #[test]
    fn gadget_rejects_lower_than_required() {
        let g = FinalityGadget::new(SecurityLevel::Strong);
        assert!(!g.is_final(&proof(SecurityLevel::Basic)));
    }

    #[test]
    fn gadget_full_security_rejects_all_lower() {
        let g = FinalityGadget::new(SecurityLevel::Full);
        assert!(!g.is_final(&proof(SecurityLevel::Minimal)));
        assert!(!g.is_final(&proof(SecurityLevel::Basic)));
        assert!(!g.is_final(&proof(SecurityLevel::Strong)));
        assert!(g.is_final(&proof(SecurityLevel::Full)));
    }

    #[test]
    fn gadget_minimal_accepts_all_levels() {
        let g = FinalityGadget::new(SecurityLevel::Minimal);
        for level in [SecurityLevel::Minimal, SecurityLevel::Basic,
                      SecurityLevel::Strong, SecurityLevel::Full] {
            assert!(g.is_final(&proof(level)));
        }
    }

    // ── ImmediateFinalityConfirmation ─────────────────────────────────────
    // Whitepaper: "AEVOR's immediate finality through mathematical verification
    // enables application design patterns that weren't previously practical."

    #[test]
    fn immediate_confirmation_stores_hash_and_level() {
        let conf = ImmediateFinalityConfirmation {
            item_hash: Hash256([0x77; 32]),
            confirmed_at_ms: 42,
            security_level: SecurityLevel::Minimal,
        };
        assert_eq!(conf.item_hash, Hash256([0x77; 32]));
        assert_eq!(conf.confirmed_at_ms, 42);
        assert_eq!(conf.security_level, SecurityLevel::Minimal);
    }

    // ── MathematicalCertainty (DeterministicFinality) ─────────────────────
    // Whitepaper: "mathematical proof that doesn't require ongoing resource
    // expenditure to maintain validity."

    #[test]
    fn mathematical_certainty_stores_all_fields() {
        let mc = certainty(SecurityLevel::Full);
        assert_eq!(mc.item_hash, Hash256([0xAB; 32]));
        assert_eq!(mc.security_level, SecurityLevel::Full);
        assert_eq!(mc.finality_proof.security_level, SecurityLevel::Full);
    }

    #[test]
    fn deterministic_finality_is_alias_for_mathematical_certainty() {
        // DeterministicFinality = MathematicalCertainty — same type
        let df: DeterministicFinality = certainty(SecurityLevel::Strong);
        assert_eq!(df.security_level, SecurityLevel::Strong);
    }
}
