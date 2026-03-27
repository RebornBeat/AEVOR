//! Blockchain state queries: objects, blocks, validators, transactions.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, BlockHeight, Hash256};
use crate::ClientResult;

/// Query for blockchain objects (smart contract state).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ObjectQuery {
    /// Filter by specific object ID.
    pub id: Option<Hash256>,
    /// Filter by owner address.
    pub owner: Option<Address>,
    /// Maximum number of results to return.
    pub limit: usize,
}

impl ObjectQuery {
    /// Query for a single object by ID.
    pub fn by_id(id: Hash256) -> Self {
        Self { id: Some(id), owner: None, limit: 1 }
    }
    /// Query all objects owned by an address.
    pub fn by_owner(owner: Address, limit: usize) -> Self {
        Self { id: None, owner: Some(owner), limit }
    }
}

/// Query for a block by height or hash.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlockQuery {
    /// Filter by block height.
    pub height: Option<BlockHeight>,
    /// Filter by block hash.
    pub hash: Option<Hash256>,
}

impl BlockQuery {
    /// Query for the block at a specific height.
    pub fn at_height(height: BlockHeight) -> Self {
        Self { height: Some(height), hash: None }
    }
    /// Query for a block by its hash.
    pub fn by_hash(hash: Hash256) -> Self {
        Self { height: None, hash: Some(hash) }
    }
}

/// Query for validators.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorQuery {
    /// If `true`, only return currently active validators.
    pub active_only: bool,
    /// Maximum number of validators to return.
    pub limit: usize,
}

impl ValidatorQuery {
    /// Query all active validators (up to `limit`).
    pub fn active(limit: usize) -> Self { Self { active_only: true, limit } }
    /// Query all validators including inactive ones.
    pub fn all(limit: usize) -> Self { Self { active_only: false, limit } }
}

/// Paginated result set from a query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryResult<T> {
    /// Items in this page.
    pub items: Vec<T>,
    /// Total number of items matching the query (across all pages).
    pub total: usize,
}

impl<T> QueryResult<T> {
    /// Create a result with a single page of items.
    pub fn new(items: Vec<T>, total: usize) -> Self { Self { items, total } }
    /// Returns `true` if there are no results.
    pub fn is_empty(&self) -> bool { self.items.is_empty() }
    /// Number of items in this page.
    pub fn len(&self) -> usize { self.items.len() }
}

/// Pagination parameters for query requests.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryPagination {
    /// Page number (0-indexed).
    pub page: usize,
    /// Number of results per page.
    pub per_page: usize,
}

impl QueryPagination {
    /// Create pagination parameters.
    pub fn new(page: usize, per_page: usize) -> Self { Self { page, per_page } }
    /// Offset into the full result set.
    pub fn offset(&self) -> usize { self.page * self.per_page }
}

impl Default for QueryPagination {
    fn default() -> Self { Self { page: 0, per_page: 20 } }
}

/// Client for querying blockchain state (objects, blocks, validators).
pub struct QueryClient {
    endpoint: String,
}

impl QueryClient {
    /// Create a query client pointing at the given endpoint.
    pub fn new(endpoint: String) -> Self { Self { endpoint } }

    /// The endpoint this client connects to.
    pub fn endpoint(&self) -> &str { &self.endpoint }

    /// Query blockchain objects matching the given filter.
    ///
    /// # Errors
    /// Returns an error if the transport is not yet connected or the request fails.
    pub fn query_objects<T: serde::de::DeserializeOwned>(
        &self,
        query: &ObjectQuery,
        _pagination: &QueryPagination,
    ) -> ClientResult<QueryResult<T>> {
        let _ = query;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "not yet connected".into(),
        })
    }

    /// Query a block by height or hash.
    ///
    /// # Errors
    /// Returns an error if the transport is not yet connected or the request fails.
    pub fn query_block(
        &self,
        query: &BlockQuery,
    ) -> ClientResult<Option<aevor_core::block::BlockHeader>> {
        let _ = query;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "not yet connected".into(),
        })
    }

    /// Query validators matching the given filter.
    ///
    /// # Errors
    /// Returns an error if the transport is not yet connected or the request fails.
    pub fn query_validators(
        &self,
        query: &ValidatorQuery,
    ) -> ClientResult<QueryResult<aevor_core::primitives::ValidatorId>> {
        let _ = query;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "not yet connected".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, BlockHeight, Hash256};

    fn addr(n: u8) -> Address { Address([n; 32]) }
    fn hash(n: u8) -> Hash256 { Hash256([n; 32]) }

    #[test]
    fn object_query_by_id_sets_id_and_limit_one() {
        let q = ObjectQuery::by_id(hash(5));
        assert_eq!(q.id, Some(hash(5)));
        assert!(q.owner.is_none());
        assert_eq!(q.limit, 1);
    }

    #[test]
    fn object_query_by_owner_sets_owner() {
        let q = ObjectQuery::by_owner(addr(3), 50);
        assert_eq!(q.owner, Some(addr(3)));
        assert!(q.id.is_none());
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn object_query_default_is_empty() {
        let q = ObjectQuery::default();
        assert!(q.id.is_none());
        assert!(q.owner.is_none());
    }

    #[test]
    fn block_query_at_height() {
        let q = BlockQuery::at_height(BlockHeight(42));
        assert_eq!(q.height, Some(BlockHeight(42)));
        assert!(q.hash.is_none());
    }

    #[test]
    fn block_query_by_hash() {
        let q = BlockQuery::by_hash(hash(7));
        assert_eq!(q.hash, Some(hash(7)));
        assert!(q.height.is_none());
    }

    #[test]
    fn validator_query_active_sets_active_only() {
        let q = ValidatorQuery::active(100);
        assert!(q.active_only);
        assert_eq!(q.limit, 100);
    }

    #[test]
    fn validator_query_all_includes_inactive() {
        let q = ValidatorQuery::all(50);
        assert!(!q.active_only);
    }

    #[test]
    fn query_result_is_empty_when_no_items() {
        let r: QueryResult<u32> = QueryResult::new(vec![], 0);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn query_result_len_and_total_are_independent() {
        let r = QueryResult::new(vec![1u32, 2, 3], 100);
        assert_eq!(r.len(), 3);
        assert_eq!(r.total, 100);
        assert!(!r.is_empty());
    }

    #[test]
    fn pagination_offset_is_page_times_per_page() {
        let p = QueryPagination::new(3, 20);
        assert_eq!(p.offset(), 60);
    }

    #[test]
    fn pagination_default_is_first_page_twenty() {
        let p = QueryPagination::default();
        assert_eq!(p.page, 0);
        assert_eq!(p.per_page, 20);
        assert_eq!(p.offset(), 0);
    }

    #[test]
    fn query_client_returns_error_when_disconnected() {
        let client = QueryClient::new("http://localhost:8731".into());
        assert_eq!(client.endpoint(), "http://localhost:8731");
        let q = ObjectQuery::by_id(hash(1));
        let p = QueryPagination::default();
        let result: ClientResult<QueryResult<u32>> = client.query_objects(&q, &p);
        assert!(result.is_err());
    }
}
