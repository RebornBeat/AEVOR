//! DNS wire protocol: message parsing and serialization.

use serde::{Deserialize, Serialize};

/// Opcode for a DNS message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsOpcode {
    /// Standard query.
    Query,
    /// Inverse query (deprecated).
    IQuery,
    /// Server status request.
    Status,
}

/// Response code (RCODE) in a DNS message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRcode {
    /// No error.
    NoError,
    /// Format error — query could not be interpreted.
    FormatError,
    /// Server failure.
    ServerFailure,
    /// Name does not exist.
    NxDomain,
    /// Query type not implemented.
    NotImplemented,
    /// Query refused by policy.
    Refused,
}

/// A DNS wire-format message (query or response).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsMessage {
    /// 16-bit message identifier (matched query to response).
    pub id: u16,
    /// Whether this is a response (`true`) or query (`false`).
    pub is_response: bool,
    /// Opcode for this message.
    pub opcode: DnsOpcode,
    /// Question names in this message.
    pub questions: Vec<String>,
    /// Response code (meaningful only in responses).
    pub rcode: DnsRcode,
    /// Whether the answer is authoritative.
    pub authoritative: bool,
    /// Whether this response was truncated.
    pub truncated: bool,
}

impl DnsMessage {
    /// Create a new query message.
    pub fn query(id: u16, names: Vec<String>) -> Self {
        Self {
            id,
            is_response: false,
            opcode: DnsOpcode::Query,
            questions: names,
            rcode: DnsRcode::NoError,
            authoritative: false,
            truncated: false,
        }
    }

    /// Create a NXDOMAIN response.
    pub fn nxdomain(query: &Self) -> Self {
        Self {
            id: query.id,
            is_response: true,
            opcode: query.opcode,
            questions: query.questions.clone(),
            rcode: DnsRcode::NxDomain,
            authoritative: true,
            truncated: false,
        }
    }

    /// Returns `true` if this is a successful response.
    pub fn is_success(&self) -> bool {
        self.is_response && matches!(self.rcode, DnsRcode::NoError)
    }
}
