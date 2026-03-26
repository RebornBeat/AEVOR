//! Immutable security audit trail.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_core::consensus::ConsensusTimestamp;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum AuditPrivacyLevel { Public, Redacted, Private }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Hash256,
    pub event_type: String,
    pub description: String,
    pub timestamp: ConsensusTimestamp,
    pub privacy: AuditPrivacyLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditQuery { pub event_type: Option<String>, pub since_round: Option<u64>, pub limit: usize }

pub struct ImmutableAuditTrail { entries: Vec<AuditEntry> }
impl ImmutableAuditTrail {
    pub fn new() -> Self { Self { entries: Vec::new() } }
    pub fn append(&mut self, entry: AuditEntry) { self.entries.push(entry); }
    pub fn entry_count(&self) -> usize { self.entries.len() }
    pub fn query(&self, q: &AuditQuery) -> Vec<&AuditEntry> {
        self.entries.iter()
            .filter(|e| q.event_type.as_deref().map(|t| e.event_type == t).unwrap_or(true))
            .take(q.limit)
            .collect()
    }
}
impl Default for ImmutableAuditTrail { fn default() -> Self { Self::new() } }

pub struct SecurityAuditLog { trail: ImmutableAuditTrail }
impl SecurityAuditLog {
    pub fn new() -> Self { Self { trail: ImmutableAuditTrail::new() } }
    pub fn log(&mut self, entry: AuditEntry) { self.trail.append(entry); }
    pub fn count(&self) -> usize { self.trail.entry_count() }
}
impl Default for SecurityAuditLog { fn default() -> Self { Self::new() } }
