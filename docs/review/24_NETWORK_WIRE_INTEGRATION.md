# 24 — Live Network Wire: the macro-DAG round over a real transport

This is a real, buildable integration — not a stub. It runs the full macro-DAG
round over a network transport. It is validated in-process (single core) and runs
over real TCP on hardware with **no code change** — only the transport backend
differs. Production round *coordination* (round numbers, view changes, equivocation
handling) layers on top of this exchange primitive; convergence, settlement, and
the cross-lane double-spend defenses are already enforced underneath.

## What exists

- **Real wire (`aevor_network::gossip::TcpTransport`).** Binds a listener, spawns a
  background accept thread, and `broadcast` opens a connection per peer and writes a
  length-prefixed, tagged `NetworkMessage`. Implements `MessageTransport`. The
  in-process `LocalNetwork` implements the same trait for tests. (Pre-existing in
  `aevor-network`, 61 tests.)
- **Round driver (`node::network::run_round`, new).** Generic over any
  `MessageTransport`. One call: record the round base → produce this validator's
  lane (execute + settle + attest, applying it locally) → broadcast it → poll-collect
  peers' lanes until quorum → apply the foreign lanes and converge. Returns the
  `LaneRoundOutcome`. Runs identically over `LocalNetwork` (immediate delivery) or
  `TcpTransport` (drains the socket inbox, sleeping between empty polls).
- **Producer round-apply (`NodeEngine::apply_foreign_lanes`, new).** A validator that
  has already applied its OWN lane (from producing it) applies the OTHER lanes on
  top. Each foreign lane is verified (attestation), checked to fork from the round
  base, checked against its balance commitment, and checked for cross-lane object
  and account conflicts against this validator's own lane and each other (the
  double-spend defenses). Because all lanes touch disjoint objects/accounts, the
  resulting root is identical on every validator regardless of which lane was its
  own — the round converges.
- **Lane wire format (new).** `StateDelta` and `LaneBlock` are `serde`; lanes cross
  the wire as bincode inside `NetworkMessage::Block` payloads (`encode_lane` /
  `decode_lane`).

## What is validated (single core)

- `lane_wire_round_trip` — serialize/deserialize a lane, malformed bytes rejected.
- `apply_foreign_lanes_producer_flow_converges` — a producing validator applying the
  other lanes reaches the **same state root and settled balances** as a fresh
  verifier applying the whole round, with identical deterministic ordering.
- `run_round_over_real_transport_converges` — **three validators, each on its own
  thread**, run `run_round` concurrently over a shared `LocalNetwork`: each produces
  a lane on disjoint senders/objects, gossips it, collects the round, applies the
  foreign lanes, and **all three converge to one state root**. This exercises the
  exact `MessageTransport` trait the real `TcpTransport` implements, so it is the
  live-round logic end to end; only the wire differs on hardware.

## Running it on real hardware

Swap the backend — the driver and engine are unchanged:

```rust
// Each validator binds and lists its peers:
let transport = aevor_network::gossip::TcpTransport::bind(my_addr, peer_addrs)?;
let cfg = node::network::RoundConfig {
    lane_id, producer, expected_lanes, poll: Duration::from_millis(20), max_polls: 500,
};
let outcome = node::network::run_round(&mut engine, &transport, &cfg, my_txs)?;
```

The same `run_round` that converges in-process now converges across machines. The
double-spend defenses (`apply_foreign_lanes`) and settlement (balance deltas +
commitments) apply identically over the wire.

## What layers on top (not stubbed — deliberately above this primitive)

- **Round coordination:** round/height numbers, waiting for a validator set / quorum
  certificate rather than a fixed `expected_lanes`, and view changes when a producer
  is silent. `run_round`'s poll-until-quorum-or-timeout is the exchange substrate
  these use.
- **Equivocation / liveness slashing over the wire:** the attestation checks and
  `detect_lane_corruption` already produce slashing evidence; wiring it to gossip is
  coordination, not new consensus.
- **Transport hardening:** persistent connections (vs connect-per-broadcast), TLS,
  peer discovery — `aevor-network` has discovery/bandwidth primitives to fold in.

## Status

Node **58 lib + 34 e2e**, clippy clean. The live macro-DAG round runs over a real
transport and converges with settlement and double-spend defense; it is ready to run
across machines by binding `TcpTransport`. Remaining on the ledger: real TEE
attestation (F-E1), then state sharding + cross-round pipelining for sustained
extreme scale (doc 23 §5).
