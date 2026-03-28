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
            .filter(|e| q.event_type.as_deref().is_none_or(|t| e.event_type == t))
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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::consensus::ConsensusTimestamp;

    fn entry(event: &str, privacy: AuditPrivacyLevel) -> AuditEntry {
        AuditEntry {
            id: Hash256::ZERO,
            event_type: event.into(),
            description: format!("{event} occurred"),
            timestamp: ConsensusTimestamp::new(1, 0, 1),
            privacy,
        }
    }

    #[test]
    fn immutable_audit_trail_append_and_count() {
        let mut trail = ImmutableAuditTrail::new();
        trail.append(entry("ValidatorSlash", AuditPrivacyLevel::Public));
        trail.append(entry("KeyRotation", AuditPrivacyLevel::Redacted));
        assert_eq!(trail.entry_count(), 2);
    }

    #[test]
    fn audit_query_filters_by_event_type() {
        let mut trail = ImmutableAuditTrail::new();
        trail.append(entry("ValidatorSlash", AuditPrivacyLevel::Public));
        trail.append(entry("KeyRotation", AuditPrivacyLevel::Public));
        trail.append(entry("ValidatorSlash", AuditPrivacyLevel::Redacted));

        let q = AuditQuery { event_type: Some("ValidatorSlash".into()), since_round: None, limit: 10 };
        let results = trail.query(&q);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.event_type == "ValidatorSlash"));
    }

    #[test]
    fn audit_query_no_filter_returns_up_to_limit() {
        let mut trail = ImmutableAuditTrail::new();
        for i in 0..5 { trail.append(entry(&format!("event-{i}"), AuditPrivacyLevel::Public)); }

        let q = AuditQuery { event_type: None, since_round: None, limit: 3 };
        assert_eq!(trail.query(&q).len(), 3);
    }

    #[test]
    fn security_audit_log_delegates_to_trail() {
        let mut log = SecurityAuditLog::new();
        log.log(entry("TeeAttestation", AuditPrivacyLevel::Private));
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn audit_privacy_levels_distinct() {
        assert!(matches!(AuditPrivacyLevel::Public, AuditPrivacyLevel::Public));
        assert!(!matches!(AuditPrivacyLevel::Private, AuditPrivacyLevel::Public));
        assert!(!matches!(AuditPrivacyLevel::Redacted, AuditPrivacyLevel::Private));
    }
}
