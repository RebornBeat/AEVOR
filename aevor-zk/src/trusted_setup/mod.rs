//! Trusted setup coordination for Groth16 and PLONK circuits.
//!
//! Trusted setup ceremonies produce the structured reference strings (SRS)
//! required by systems like Groth16 and PLONK. The setup must be performed
//! before any proving can occur, and requires at least one honest participant.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

/// Status of a trusted setup ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyStatus {
    /// Ceremony is accepting contributions.
    Open,
    /// Ceremony is finalizing the SRS.
    Finalizing,
    /// Ceremony completed — SRS is ready.
    Complete,
    /// Ceremony was aborted (too few participants).
    Aborted,
}

/// A single participant's contribution to a setup ceremony.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyContribution {
    /// Hash identifying this participant.
    pub contributor: Hash256,
    /// Their contribution to the SRS.
    pub contribution_hash: Hash256,
    /// Proof that the contribution is well-formed.
    pub proof_of_knowledge: Vec<u8>,
}

/// A trusted setup ceremony producing a circuit-specific SRS.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedSetupCeremony {
    /// Identifier for this ceremony.
    pub circuit_hash: Hash256,
    /// Current ceremony status.
    pub status: CeremonyStatus,
    /// Contributions received so far.
    pub contributions: Vec<CeremonyContribution>,
    /// Minimum number of contributions required.
    pub min_contributions: usize,
}

impl TrustedSetupCeremony {
    /// Create a new ceremony for the given circuit.
    pub fn new(circuit_hash: Hash256, min_contributions: usize) -> Self {
        Self {
            circuit_hash,
            status: CeremonyStatus::Open,
            contributions: Vec::new(),
            min_contributions,
        }
    }

    /// Add a contribution to the ceremony.
    pub fn contribute(&mut self, contribution: CeremonyContribution) -> bool {
        if self.status != CeremonyStatus::Open {
            return false;
        }
        self.contributions.push(contribution);
        if self.contributions.len() >= self.min_contributions {
            self.status = CeremonyStatus::Finalizing;
        }
        true
    }

    /// Number of contributions received.
    pub fn contribution_count(&self) -> usize { self.contributions.len() }

    /// Returns `true` if the ceremony has sufficient contributions.
    pub fn is_ready(&self) -> bool {
        self.contributions.len() >= self.min_contributions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn hash(n: u8) -> Hash256 { Hash256([n; 32]) }

    fn contribution(contributor: u8) -> CeremonyContribution {
        CeremonyContribution {
            contributor: hash(contributor),
            contribution_hash: hash(contributor + 100),
            proof_of_knowledge: vec![contributor],
        }
    }

    #[test]
    fn ceremony_starts_open() {
        let c = TrustedSetupCeremony::new(hash(1), 3);
        assert_eq!(c.status, CeremonyStatus::Open);
        assert_eq!(c.contribution_count(), 0);
        assert!(!c.is_ready());
    }

    #[test]
    fn contribute_adds_until_min_then_finalizes() {
        let mut c = TrustedSetupCeremony::new(hash(1), 2);
        assert!(c.contribute(contribution(1)));
        assert_eq!(c.status, CeremonyStatus::Open);
        assert!(!c.is_ready());
        assert!(c.contribute(contribution(2)));
        assert_eq!(c.status, CeremonyStatus::Finalizing);
        assert!(c.is_ready());
        assert_eq!(c.contribution_count(), 2);
    }

    #[test]
    fn contribute_rejected_when_not_open() {
        let mut c = TrustedSetupCeremony::new(hash(1), 1);
        c.contribute(contribution(1)); // transitions to Finalizing
        // Further contributions should be rejected
        let accepted = c.contribute(contribution(2));
        assert!(!accepted);
        assert_eq!(c.contribution_count(), 1);
    }

    #[test]
    fn ceremony_status_variants_distinct() {
        assert_ne!(CeremonyStatus::Open, CeremonyStatus::Complete);
        assert_ne!(CeremonyStatus::Finalizing, CeremonyStatus::Aborted);
    }

    #[test]
    fn contribution_stores_all_fields() {
        let c = contribution(5);
        assert_eq!(c.contributor, hash(5));
        assert_eq!(c.contribution_hash, hash(105));
        assert_eq!(c.proof_of_knowledge, vec![5]);
    }
}
