//! Real socket transport for [`NodeConnection`].
//!
//! [`TcpNodeConnection`] is a request/response client that talks to a node over
//! TCP, implementing the *same* [`NodeConnection`] trait as the in-process
//! `EngineConnection` — so client code is identical whether the node is
//! in-process or across a socket. The wire is length-prefixed bincode frames;
//! the request/response envelopes ([`NodeRequest`] / [`NodeResponse`]) are
//! shared with the node-side server.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use serde::{Deserialize, Serialize};

use aevor_core::primitives::ObjectId;
use aevor_core::storage::MerkleProof;
use aevor_core::transaction::SignedTransaction;

use crate::exec::{NodeConnection, SubmitResponse};
use crate::{ClientError, ClientResult};

/// Maximum frame size accepted on the wire (guards against absurd allocations).
const MAX_FRAME: usize = 64 * 1024 * 1024;

/// A request from a client to a node.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum NodeRequest {
    /// Submit a signed transaction to the node's mempool.
    Submit(SignedTransaction),
    /// Query for an object's inclusion proof.
    Query(ObjectId),
}

/// A node's response to a [`NodeRequest`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeResponse {
    /// Result of a submit.
    Submit(SubmitResponse),
    /// Result of a query (inclusion proof, or `None` if absent).
    Query(Option<MerkleProof>),
    /// The node failed to process the request.
    Error(String),
}

/// Write a length-prefixed frame (4-byte little-endian length + payload).
///
/// # Errors
/// Returns an I/O error if the write fails.
pub fn write_frame<W: Write>(w: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes();
    w.write_all(&len)?;
    w.write_all(bytes)?;
    w.flush()
}

/// Read a length-prefixed frame written by [`write_frame`].
///
/// # Errors
/// Returns an I/O error if the read fails or the frame is oversized.
pub fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds maximum size",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// A `NodeConnection` that talks to a node over TCP.
///
/// Each call opens a short connection, sends one request frame, and reads one
/// response frame (HTTP/1.0-style). Persistent connections are a refinement.
pub struct TcpNodeConnection {
    addr: SocketAddr,
}

impl TcpNodeConnection {
    /// Create a connection targeting a node's request/response address.
    #[must_use]
    pub fn connect(addr: SocketAddr) -> Self {
        Self { addr }
    }

    fn round_trip(&self, request: &NodeRequest) -> ClientResult<NodeResponse> {
        let bytes = bincode::serialize(request)
            .map_err(|e| ClientError::InvalidResponse { reason: e.to_string() })?;
        let mut stream = TcpStream::connect(self.addr)
            .map_err(|e| ClientError::InvalidResponse { reason: e.to_string() })?;
        write_frame(&mut stream, &bytes)
            .map_err(|e| ClientError::InvalidResponse { reason: e.to_string() })?;
        let response_bytes = read_frame(&mut stream)
            .map_err(|e| ClientError::InvalidResponse { reason: e.to_string() })?;
        bincode::deserialize(&response_bytes)
            .map_err(|e| ClientError::InvalidResponse { reason: e.to_string() })
    }
}

impl NodeConnection for TcpNodeConnection {
    fn submit_transaction(&mut self, tx: &SignedTransaction) -> ClientResult<SubmitResponse> {
        match self.round_trip(&NodeRequest::Submit(tx.clone()))? {
            NodeResponse::Submit(r) => Ok(r),
            NodeResponse::Error(reason) => Err(ClientError::InvalidResponse { reason }),
            NodeResponse::Query(_) => Err(ClientError::InvalidResponse {
                reason: "unexpected query response to submit".to_string(),
            }),
        }
    }

    fn query_object(&self, id: ObjectId) -> ClientResult<Option<MerkleProof>> {
        match self.round_trip(&NodeRequest::Query(id))? {
            NodeResponse::Query(p) => Ok(p),
            NodeResponse::Error(reason) => Err(ClientError::InvalidResponse { reason }),
            NodeResponse::Submit(_) => Err(ClientError::InvalidResponse {
                reason: "unexpected submit response to query".to_string(),
            }),
        }
    }
}
