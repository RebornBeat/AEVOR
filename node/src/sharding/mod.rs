//! State sharding: partitioned state ownership as an opt-in engine mode.
//!
//! **Merged, not replacing.** The engine defaults to [`ShardingMode::Monolithic`]
//! — every validator holds the full state, the proven production mode. Extreme
//! scale (sustained tens–hundreds of millions of tx/s) needs the total state
//! partitioned across validators so no single node holds it all; that is
//! [`ShardingMode::Sharded`], which the same engine interchanges into. Choosing a
//! mode is a startup decision; monolithic remains the default so nothing that
//! works today changes.
//!
//! A shard owns a deterministic slice of the object *and* account space
//! ([`ShardAssignment`]), so every validator agrees on which shard owns which
//! state with no coordination. In sharded mode a validator stores and applies only
//! the state it owns; the cross-lane double-spend defenses still run over the whole
//! round (they are global), only the *storage* is partitioned. Transactions that
//! touch state in more than one shard are cross-shard and use the protocol in
//! [`CrossShard`] (single-shard transactions need none).

use aevor_core::primitives::{Address, ObjectId};

/// Deterministic partition of the object/account space into `total_shards` shards.
/// An id maps to a shard by its leading bytes, so the mapping is stable and
/// coordination-free across all validators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardAssignment {
    total_shards: u32,
}

impl ShardAssignment {
    /// A partition into `total_shards` (clamped to at least 1).
    #[must_use]
    pub fn new(total_shards: u32) -> Self {
        Self { total_shards: total_shards.max(1) }
    }

    /// The number of shards.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.total_shards
    }

    fn shard_of_bytes(&self, b: &[u8; 32]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]) % self.total_shards
    }

    /// The shard that owns `object`.
    #[must_use]
    pub fn shard_of_object(&self, object: &ObjectId) -> u32 {
        self.shard_of_bytes(&object.0 .0)
    }

    /// The shard that owns `account`.
    #[must_use]
    pub fn shard_of_account(&self, account: &Address) -> u32 {
        self.shard_of_bytes(&account.0)
    }
}

/// How this validator's state is partitioned. Defaults to [`Self::Monolithic`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ShardingMode {
    /// Every validator holds the full state (the default — proven, production).
    #[default]
    Monolithic,
    /// This validator owns exactly `shard_id` of a partitioned state.
    Sharded {
        /// Which shard this validator owns.
        shard_id: u32,
        /// The global partition.
        assignment: ShardAssignment,
    },
}

impl ShardingMode {
    /// A sharded mode owning `shard_id` of `total_shards`.
    #[must_use]
    pub fn sharded(shard_id: u32, total_shards: u32) -> Self {
        let assignment = ShardAssignment::new(total_shards);
        Self::Sharded { shard_id: shard_id % assignment.total(), assignment }
    }

    /// Whether this validator stores `object` (always true when monolithic).
    #[must_use]
    pub fn owns_object(&self, object: &ObjectId) -> bool {
        match self {
            Self::Monolithic => true,
            Self::Sharded { shard_id, assignment } => {
                assignment.shard_of_object(object) == *shard_id
            }
        }
    }

    /// Whether this validator stores `account` (always true when monolithic).
    #[must_use]
    pub fn owns_account(&self, account: &Address) -> bool {
        match self {
            Self::Monolithic => true,
            Self::Sharded { shard_id, assignment } => {
                assignment.shard_of_account(account) == *shard_id
            }
        }
    }

    /// Whether state is partitioned (i.e. not monolithic).
    #[must_use]
    pub fn is_sharded(&self) -> bool {
        matches!(self, Self::Sharded { .. })
    }

    /// Whether **this** validator executes a transaction with the given write set.
    ///
    /// Monolithic validators execute everything. A sharded validator executes only
    /// the transactions it coordinates ([`CrossShard::coordinator`] — the shard
    /// owning the lowest written object), so across the network exactly one shard
    /// executes each transaction: no duplicate execution, no dropped transactions,
    /// and no coordination needed to agree on who runs what. A transaction with an
    /// empty write set is assigned to shard 0 so it still has exactly one executor.
    #[must_use]
    pub fn is_responsible_for(&self, writes: &[ObjectId]) -> bool {
        match self {
            Self::Monolithic => true,
            Self::Sharded { shard_id, assignment } => {
                CrossShard::coordinator(assignment, writes).map_or(*shard_id == 0, |c| c == *shard_id)
            }
        }
    }
}

/// Cross-shard transaction classification and protocol.
///
/// A transaction is **single-shard** when every object it writes falls in one
/// shard — the owning validator processes it with no coordination. It is
/// **cross-shard** when its writes span shards; then each participating shard
/// applies the part it owns, and the parts commit together. The commitment is the
/// per-shard attestation set for the round: because each shard's writes are bound
/// by its own attestation (and the balance commitment), a cross-shard transaction
/// is applied atomically across shards exactly when every touched shard's
/// attestation for the round verifies — no shard can apply its half while another
/// rejects, because a verifier requires the full set. This reuses the existing
/// per-lane attestation + commitment machinery rather than adding a new 2-phase
/// lock.
pub struct CrossShard;

impl CrossShard {
    /// The distinct shards a set of written objects touches.
    #[must_use]
    pub fn shards_touched(assignment: &ShardAssignment, writes: &[ObjectId]) -> Vec<u32> {
        let mut shards: Vec<u32> = writes.iter().map(|o| assignment.shard_of_object(o)).collect();
        shards.sort_unstable();
        shards.dedup();
        shards
    }

    /// Whether the write set is confined to a single shard.
    #[must_use]
    pub fn is_single_shard(assignment: &ShardAssignment, writes: &[ObjectId]) -> bool {
        Self::shards_touched(assignment, writes).len() <= 1
    }

    /// The shard responsible for **executing** a transaction: the shard owning the
    /// lowest-ordered written object. This is deterministic and derived purely from
    /// the transaction, so every validator agrees on the executor with zero
    /// coordination — exactly one shard executes each transaction, and no
    /// transaction is executed twice or dropped.
    ///
    /// For a single-shard transaction this is simply its own shard. For a
    /// cross-shard transaction the coordinating shard executes it once and emits a
    /// delta containing writes to every touched shard; each shard then applies only
    /// the writes it owns, and atomicity holds because the whole delta is bound by
    /// one attestation (a verifier accepts all of it or none).
    ///
    /// Returns `None` for an empty write set (nothing to own).
    #[must_use]
    pub fn coordinator(assignment: &ShardAssignment, writes: &[ObjectId]) -> Option<u32> {
        writes
            .iter()
            .min_by(|a, b| a.0 .0.cmp(&b.0 .0))
            .map(|lowest| assignment.shard_of_object(lowest))
    }
}

/// A shard's attestation that **its slice** of a round's object/account space is
/// conflict-free.
///
/// Cross-lane conflict checking is the one per-round cost that scales with object
/// count (measured: ~77% of the non-storage floor). It partitions *perfectly*,
/// because a conflict is defined on a single object: object X's conflicts can only
/// be detected by whoever owns X, so if every shard checks its own slice, every
/// possible conflict is checked exactly once — complete coverage at 1/N the cost.
///
/// The catch, and why this type exists: a validator that checks only its own slice
/// knows only that *its* slice is clean. Committing a round requires knowing it is
/// **globally** clean. So shard-local checking is sound only when the round carries
/// a certificate from every shard. Applying without full coverage would silently
/// downgrade the double-spend guarantee, so the engine requires the complete set
/// and rejects the round otherwise.
///
/// Security model: identical in kind to sharded *verification* — each shard needs
/// an honest quorum. A fully byzantine shard could falsely certify its slice, so
/// per-shard quorum size is the security floor. It is a tradeoff, not a new class
/// of risk.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShardConflictCertificate {
    /// The shard whose slice was checked.
    pub shard_id: u32,
    /// The partition this certificate was produced under.
    pub total_shards: u32,
    /// Commitment to the exact lane set checked, so a certificate cannot be
    /// replayed against a different round.
    pub lane_set_commitment: [u8; 32],
}

impl ShardConflictCertificate {
    /// Whether `certificates` cover every shard of `total_shards` for this exact
    /// lane set — the completeness requirement that keeps shard-local conflict
    /// checking as strong as the monolithic check.
    #[must_use]
    pub fn covers_all_shards(
        certificates: &[Self],
        total_shards: u32,
        lane_set_commitment: [u8; 32],
    ) -> bool {
        if total_shards == 0 {
            return false;
        }
        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for c in certificates {
            if c.total_shards == total_shards && c.lane_set_commitment == lane_set_commitment {
                seen.insert(c.shard_id);
            }
        }
        (0..total_shards).all(|s| seen.contains(&s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn obj(n: u8) -> ObjectId {
        ObjectId(Hash256([n; 32]))
    }
    fn acct(n: u8) -> Address {
        Address::from_bytes([n; 32])
    }

    #[test]
    fn monolithic_owns_everything() {
        let m = ShardingMode::Monolithic;
        assert!(m.owns_object(&obj(0)));
        assert!(m.owns_object(&obj(255)));
        assert!(m.owns_account(&acct(7)));
        assert!(!m.is_sharded());
    }

    #[test]
    fn assignment_is_deterministic_and_bounded() {
        let a = ShardAssignment::new(4);
        assert_eq!(a.total(), 4);
        for n in 0..=255u8 {
            let s = a.shard_of_object(&obj(n));
            assert!(s < 4);
            assert_eq!(s, a.shard_of_object(&obj(n)), "stable");
        }
        // total 0 clamps to 1 (single shard owns all).
        assert_eq!(ShardAssignment::new(0).total(), 1);
    }

    #[test]
    fn shards_partition_the_space_disjointly() {
        // Every object is owned by exactly one shard across the full set.
        let total = 4u32;
        for n in 0..=255u8 {
            let owners: Vec<u32> = (0..total)
                .filter(|&sid| ShardingMode::sharded(sid, total).owns_object(&obj(n)))
                .collect();
            assert_eq!(owners.len(), 1, "object {n} owned by exactly one shard");
        }
    }

    #[test]
    fn exactly_one_shard_is_responsible_for_any_transaction() {
        // The coordination-free executor rule: for ANY write set, exactly one shard
        // is responsible — no duplicate execution, no dropped transactions.
        let total = 4u32;
        let modes: Vec<ShardingMode> =
            (0..total).map(|s| ShardingMode::sharded(s, total)).collect();
        // Single-object write sets.
        for n in 0..=255u8 {
            let writes = vec![obj(n)];
            let responsible = modes.iter().filter(|m| m.is_responsible_for(&writes)).count();
            assert_eq!(responsible, 1, "single-shard tx {n}: exactly one executor");
        }
        // Cross-shard write sets (spanning several shards).
        for start in 0..32u8 {
            let writes: Vec<ObjectId> = (start..start.saturating_add(5)).map(obj).collect();
            let responsible = modes.iter().filter(|m| m.is_responsible_for(&writes)).count();
            assert_eq!(responsible, 1, "cross-shard tx at {start}: exactly one coordinator");
        }
        // Empty write set still has exactly one executor (shard 0 by rule).
        let responsible = modes.iter().filter(|m| m.is_responsible_for(&[])).count();
        assert_eq!(responsible, 1, "empty write set: exactly one executor");
        // Monolithic always executes.
        assert!(ShardingMode::Monolithic.is_responsible_for(&[obj(9)]));
    }

    #[test]
    fn coordinator_is_the_shard_of_the_lowest_written_object() {
        let a = ShardAssignment::new(4);
        let writes = vec![obj(200), obj(3), obj(77)];
        let expected = a.shard_of_object(&obj(3)); // lowest id
        assert_eq!(CrossShard::coordinator(&a, &writes), Some(expected));
        // Order of the write set does not change the coordinator (determinism).
        let reordered = vec![obj(77), obj(200), obj(3)];
        assert_eq!(CrossShard::coordinator(&a, &reordered), Some(expected));
        assert_eq!(CrossShard::coordinator(&a, &[]), None);
    }

    #[test]
    fn cross_shard_classification() {
        let a = ShardAssignment::new(8);
        // A single object is trivially single-shard.
        assert!(CrossShard::is_single_shard(&a, &[obj(1)]));
        // Objects that happen to land in different shards are cross-shard.
        let writes: Vec<ObjectId> = (0..16u8).map(obj).collect();
        let touched = CrossShard::shards_touched(&a, &writes);
        assert!(touched.iter().all(|&s| s < 8));
        assert_eq!(CrossShard::is_single_shard(&a, &writes), touched.len() <= 1);
    }
}
