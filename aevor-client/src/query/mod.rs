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
    pub async fn query_objects<T: serde::de::DeserializeOwned>(
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
    pub async fn query_block(
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
    pub async fn query_validators(
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
