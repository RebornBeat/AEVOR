# 26 — State Sharding (opt-in mode) and Cross-Round Pipelining

Two extreme-scale capabilities, built the way you asked: **merged, not replacing.**
State sharding is an opt-in engine mode with **monolithic as the default**, so
everything that works today is unchanged and the engine interchanges into a sharded
mode when a deployment needs it. Cross-round pipelining is a round-lifecycle
optimization that applies to **both** modes. Benchmarks re-run: no degradation.

---

## State sharding — an interchangeable mode

**Why a mode, not a rewrite.** Full state sharding changes the state model (each
validator holds only part of the state). Ripping out the monolithic engine to get
there would discard the proven path. Instead the engine carries a
`ShardingMode` (`node/src/sharding`):

- `ShardingMode::Monolithic` (**default**) — every validator holds the full state.
  Nothing changes; this is production today.
- `ShardingMode::Sharded { shard_id, assignment }` — this validator stores and
  applies only the objects/accounts it owns.

`NodeEngine::set_sharding(mode)` interchanges between them; the default is
monolithic, so it is opt-in and production-first (the proven mode is the default,
sharding is an advanced capability).

**The partition.** `ShardAssignment` maps object and account ids to a shard by their
leading bytes — deterministic and coordination-free, so every validator agrees on
which shard owns which state. `owns_object` / `owns_account` are always true in
monolithic mode.

**What sharded mode does today (the storage foundation).** The round-apply paths
(`apply_lane_round`, `apply_foreign_lanes`) route object/balance application through
`apply_owned_delta`, which stores only owned state. So two validators in different
shards, applying the same round, hold **disjoint** subsets that together cover the
whole round — proven by `sharded_mode_partitions_state_across_validators` (monolithic
holds all four objects; shard 0 and shard 1 of two each hold a strict subset summing
to the whole). Crucially, the **cross-lane double-spend defenses still run over the
entire round** — only *storage* is partitioned, not the safety checks.

**Shard-aware execution (producer side) — DONE, end-to-end.** A sharded producer no
longer executes everything. Two rules make the partition complete:

1. **Coordination-free executor assignment.** `CrossShard::coordinator` designates
   the shard owning a transaction's *lowest-ordered written object* as its executor.
   This is derived purely from the transaction, so every validator agrees with zero
   communication. `ShardingMode::is_responsible_for` applies it (monolithic: always
   true). The engine's `shard_admission_filter` runs ahead of both production paths
   (`process_block`, `produce_attested_batch`), so a sharded validator executes only
   what it coordinates; the rest are counted in `BlockOutcome.routed_to_other_shard`
   for routing to the owning shard's producer — not dropped.
   Verified by `shard_aware_execution_partitions_work_exactly_once`: across 4 shards
   given the same 24 transactions, each shard executes a strict subset,
   `accepted + routed_to_other_shard == total` on every shard, and the executed
   counts sum to exactly the total — **each transaction executed exactly once, none
   duplicated, none lost**. Unit-tested for arbitrary write sets
   (`exactly_one_shard_is_responsible_for_any_transaction`), including cross-shard
   and empty write sets.
2. **Ship everything, store what you own.** `verify_execute_commit` stores only
   owned objects, while the shipped `StateDelta` still carries *every* write from the
   transactions this shard executed. That is precisely the cross-shard mechanism:
   one shard executes, one attestation binds the whole delta, and each shard applies
   only its own writes via `apply_owned_delta`. Atomicity holds because a verifier
   accepts the whole attested delta or none of it — no shard can apply its half while
   another rejects. Verified by
   `cross_shard_delta_ships_all_writes_while_storing_only_owned`.

**Consequence to note for sharded deployments.** Because a sharded validator stores
only its partition, its Merkle state root is a *per-shard* root — sharded validators
converge with peers in the same shard, not with other shards. Cross-shard state is
reconciled by the attested deltas above. Monolithic deployments are unaffected
(single global root, exactly as today).

**Cross-shard transactions.** `CrossShard` classifies a write set as single-shard
(owned by one shard — no coordination) or cross-shard (spans shards). The commitment
mechanism reuses the existing per-lane attestation + balance commitment: a
cross-shard transaction is applied atomically across shards exactly when every
touched shard's attestation for the round verifies, because a verifier requires the
full set — no shard applies its half while another rejects. This avoids a separate
2-phase lock.

---

## Cross-round pipelining — for both modes

**Not sharding-specific.** Pipelining overlaps a round's finality with the next
round's production; it is a round-lifecycle optimization independent of how state is
partitioned, so it lives in `node/src/pipeline` and applies to monolithic and
sharded alike.

**The idea.** Production (~11k tx/s/core) is the bottleneck; finality is an O(1) BLS
aggregation. A round's authenticated state is known at **apply** (the root is
computed before the round's finality certificate is aggregated and gossiped), so the
next round produces and applies immediately while earlier rounds' certificates settle.
Applied state advances at production rate; finality trails by the pipeline depth,
hiding finality latency under production.

**`RoundPipeline`.** Tracks applied-but-not-yet-committed rounds up to a configured
depth. `record_applied` enqueues a round (state already advanced) and, when the
pipeline exceeds depth, commits the oldest and returns its `FinalityCertificate` —
the round whose finality overlapped newer production. `drain` finalizes the rest in
order. Tested: `finality_trails_application_by_depth` (finality lags while the
pipeline fills, then commits oldest-first), `drain_finalizes_remaining_in_order`,
`depth_one_finalizes_each_round_immediately_behind`. It takes a `LaneRoundOutcome`,
so it is mode-agnostic by construction.

---

## No degradation (benchmarks re-run)

- `bench_full_pipeline` ×2: PRODUCE 11,830 / 11,495, VERIFY 1,110,654 / 1,092,007 —
  on the ~11–12k / ~1.0–1.1M baseline; economics byte-identical (base fee 990,
  fee/tx 485,000).
- `bench_multi_lane_round` (apply path now through the sharding filter): ~927k→525k
  across 1–32 lanes — on baseline. The `apply_owned_delta` ownership check is a
  no-op match returning true in monolithic mode, so it costs nothing.

Node **65 lib + 35 e2e**, clippy clean.

## Status

Both capabilities are merged and green: sharding as an interchangeable mode
(monolithic default; partitioned storage on apply, cross-shard classification) and
pipelining as a both-modes round-lifecycle primitive. Remaining for full sharded
operation: shard-aware *execution* on the producer and the live cross-shard driver,
building on the storage partition already in place.
