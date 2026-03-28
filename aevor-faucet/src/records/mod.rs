//! Distribution record tracking.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Amount, Hash256};
use aevor_core::consensus::ConsensusTimestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributionRecord {
    pub tx_hash: Hash256,
    pub recipient: Address,
    pub amount: Amount,
    pub timestamp: ConsensusTimestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressRecord {
    pub address: Address,
    pub total_received: Amount,
    pub request_count: u64,
    pub last_request: ConsensusTimestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributionHistory { pub records: Vec<DistributionRecord>, pub total_distributed: Amount }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordQuery { pub address: Option<Address>, pub limit: usize }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordVerification { pub record_hash: Hash256, pub valid: bool }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Amount, Hash256};
    use aevor_core::consensus::ConsensusTimestamp;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    #[test]
    fn distribution_history_total_distributed() {
        let h = DistributionHistory { records: vec![], total_distributed: Amount::from_nano(5_000) };
        assert_eq!(h.total_distributed.as_nano(), 5_000u128);
    }

    #[test]
    fn address_record_tracks_requests() {
        let r = AddressRecord { address: addr(1), total_received: Amount::from_nano(1_000), request_count: 3, last_request: ConsensusTimestamp::GENESIS };
        assert_eq!(r.request_count, 3);
    }

    #[test]
    fn record_query_optional_address() {
        let q = RecordQuery { address: None, limit: 50 };
        assert!(q.address.is_none());
        let q2 = RecordQuery { address: Some(addr(1)), limit: 10 };
        assert!(q2.address.is_some());
    }

    #[test]
    fn record_verification_valid_flag() {
        let v = RecordVerification { record_hash: Hash256::ZERO, valid: true };
        assert!(v.valid);
    }
}
