//! API request/response types.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, BlockHeight, Hash256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTransaction { pub hash: Hash256, pub sender: Address, pub status: String, pub gas_used: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBlock { pub hash: Hash256, pub height: BlockHeight, pub transaction_count: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiObject { pub id: Hash256, pub owner: Address, pub privacy_level: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiValidator { pub id: Hash256, pub status: String, pub stake: u128 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiQuery { pub filter: Option<String>, pub limit: usize, pub offset: usize }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiReceipt { pub transaction_hash: Hash256, pub success: bool, pub gas_consumed: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError { pub code: u32, pub message: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pagination { pub page: usize, pub per_page: usize, pub total: usize }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub enum SortOrder { #[default] Asc, Desc }
