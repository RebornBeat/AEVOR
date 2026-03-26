//! VM execution context types.

use serde::{Deserialize, Serialize};
pub use aevor_core::execution::ExecutionContext;
use aevor_core::primitives::{Address, BlockHeight, ChainId};
use aevor_core::consensus::ConsensusTimestamp;
use aevor_core::privacy::PrivacyContext;
use aevor_core::tee::TeePlatform;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionContext {
    pub sender: Address,
    pub nonce: aevor_core::primitives::Nonce,
    pub gas_limit: aevor_core::primitives::GasAmount,
    pub value: aevor_core::primitives::Amount,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockContext {
    pub height: BlockHeight,
    pub timestamp: ConsensusTimestamp,
    pub chain_id: ChainId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeContext {
    pub platform: TeePlatform,
    pub nonce: [u8; 32],
    pub is_active: bool,
}

pub type VmPrivacyContext = PrivacyContext;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmExecutionContext {
    pub transaction: TransactionContext,
    pub block: BlockContext,
    pub tee: Option<TeeContext>,
    pub privacy: VmPrivacyContext,
}
