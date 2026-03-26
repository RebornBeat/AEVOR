//! Cross-chain asset management.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Amount, Hash256};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
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
