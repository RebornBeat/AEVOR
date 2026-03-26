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
