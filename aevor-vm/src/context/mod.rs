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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Amount, ChainId, BlockHeight, GasAmount, Nonce};
    use aevor_core::consensus::ConsensusTimestamp;
    use aevor_core::tee::TeePlatform;

    fn tx_ctx() -> TransactionContext {
        TransactionContext {
            sender: Address([1u8; 32]),
            nonce: Nonce(0),
            gas_limit: GasAmount::from_u64(21_000),
            value: Amount::ZERO,
        }
    }

    fn block_ctx() -> BlockContext {
        BlockContext {
            height: BlockHeight(100),
            timestamp: ConsensusTimestamp::new(1, 0, 100),
            chain_id: ChainId::MAINNET,
        }
    }

    #[test]
    fn transaction_context_stores_sender_and_gas() {
        let ctx = tx_ctx();
        assert_eq!(ctx.sender, Address([1u8; 32]));
        assert_eq!(ctx.gas_limit.as_u64(), 21_000);
    }

    #[test]
    fn block_context_stores_height_and_timestamp() {
        let ctx = block_ctx();
        assert_eq!(ctx.height.as_u64(), 100);
        assert_eq!(ctx.chain_id, ChainId::MAINNET);
    }

    #[test]
    fn tee_context_all_five_platforms() {
        for platform in [
            TeePlatform::IntelSgx, TeePlatform::AmdSev, TeePlatform::ArmTrustZone,
            TeePlatform::RiscvKeystone, TeePlatform::AwsNitro,
        ] {
            let tee = TeeContext { platform, nonce: [0u8; 32], is_active: true };
            assert_eq!(tee.platform, platform);
            assert!(tee.is_active);
        }
    }

    #[test]
    fn vm_execution_context_with_tee() {
        let ctx = VmExecutionContext {
            transaction: tx_ctx(),
            block: block_ctx(),
            tee: Some(TeeContext { platform: TeePlatform::IntelSgx, nonce: [1u8; 32], is_active: true }),
            privacy: aevor_core::privacy::PrivacyContext::default(),
        };
        assert!(ctx.tee.is_some());
        assert!(ctx.tee.unwrap().is_active);
    }

    #[test]
    fn vm_execution_context_without_tee() {
        let ctx = VmExecutionContext {
            transaction: tx_ctx(),
            block: block_ctx(),
            tee: None,
            privacy: aevor_core::privacy::PrivacyContext::default(),
        };
        assert!(ctx.tee.is_none());
    }
}
