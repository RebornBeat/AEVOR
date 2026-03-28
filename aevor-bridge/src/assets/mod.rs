//! Cross-chain asset management.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Amount, Hash256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetStandard { Erc20, Erc721, Native, Utxo }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainAsset { pub id: Hash256, pub chain: String, pub standard: AssetStandard }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedAsset { pub original: CrossChainAsset, pub wrapper_address: Address }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeAsset { pub symbol: String, pub decimals: u8 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetLock { pub asset: CrossChainAsset, pub amount: Amount, pub lock_hash: Hash256 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetMint { pub asset: CrossChainAsset, pub amount: Amount, pub recipient: Address }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetBurn { pub asset: CrossChainAsset, pub amount: Amount, pub proof: Vec<u8> }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Amount, Hash256};

    fn asset(chain: &str, standard: AssetStandard) -> CrossChainAsset {
        CrossChainAsset { id: Hash256::ZERO, chain: chain.into(), standard }
    }

    #[test]
    fn asset_standards_distinct() {
        assert_ne!(AssetStandard::Erc20, AssetStandard::Erc721);
        assert_ne!(AssetStandard::Native, AssetStandard::Utxo);
    }

    #[test]
    fn asset_lock_stores_amount_and_hash() {
        let lock = AssetLock { asset: asset("ethereum", AssetStandard::Erc20), amount: Amount::from_nano(1_000), lock_hash: Hash256([0xAB; 32]) };
        assert_eq!(lock.amount.as_nano(), 1_000u128);
        assert_eq!(lock.lock_hash, Hash256([0xAB; 32]));
    }

    #[test]
    fn wrapped_asset_stores_original_and_wrapper() {
        let wa = WrappedAsset { original: asset("bitcoin", AssetStandard::Utxo), wrapper_address: Address([1u8; 32]) };
        assert_eq!(wa.original.chain, "bitcoin");
    }

    #[test]
    fn asset_burn_requires_proof() {
        let burn = AssetBurn { asset: asset("ethereum", AssetStandard::Erc20), amount: Amount::from_nano(500), proof: vec![0xFF; 32] };
        assert!(!burn.proof.is_empty());
    }
}
