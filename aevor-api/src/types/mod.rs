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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, BlockHeight, Hash256};

    #[test]
    fn api_transaction_stores_fields() {
        let tx = ApiTransaction { hash: Hash256::ZERO, sender: Address([1u8;32]), status: "finalized".into(), gas_used: 21_000 };
        assert_eq!(tx.status, "finalized");
        assert_eq!(tx.gas_used, 21_000);
    }

    #[test]
    fn api_block_stores_height_and_count() {
        let b = ApiBlock { hash: Hash256::ZERO, height: BlockHeight(100), transaction_count: 42 };
        assert_eq!(b.height.as_u64(), 100);
        assert_eq!(b.transaction_count, 42);
    }

    #[test]
    fn api_error_stores_code_and_message() {
        let e = ApiError { code: 404, message: "not found".into() };
        assert_eq!(e.code, 404);
    }

    #[test]
    fn pagination_stores_all_fields() {
        let p = Pagination { page: 2, per_page: 20, total: 500 };
        assert_eq!(p.total, 500);
    }
}
