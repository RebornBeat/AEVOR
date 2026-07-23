//! Live macro-DAG round over the network.
//!
//! **Production is the default.** A live validator runs
//! [`ValidatorNetwork::bind`], which binds a real `TcpTransport` and gossips with
//! peers across machines — this is the norm. [`run_round`] is the generic engine
//! underneath (it works over any [`aevor_network::gossip::MessageTransport`]); the
//! in-process [`aevor_network::gossip::LocalNetwork`] is a **test-only** injection
//! used to exercise the round logic on one machine. The flow is identical whether
//! a message crosses a process (tests) or the globe (production):
//!
//! 1. produce this validator's lane from its transactions (execute + settle +
//!    attest) — this applies the lane to the validator's own state;
//! 2. broadcast the lane to peers;
//! 3. collect the round's other lanes until quorum (or the poll budget elapses);
//! 4. apply the collected foreign lanes on top of our own
//!    ([`NodeEngine::apply_foreign_lanes`]) — verified, conflict-checked
//!    (double-spend defenses), and settled — and converge.
//!
//! Lanes cross the wire as bincode-serialized [`LaneBlock`]s inside
//! `NetworkMessage::Block` payloads (transport-agnostic bytes). Production round
//! coordination (round numbers, equivocation handling, view changes) layers on
//! top of this exchange primitive; convergence, settlement, and the cross-lane
//! double-spend defenses are already enforced by `apply_foreign_lanes`.

use aevor_core::primitives::ValidatorId;
use aevor_core::transaction::SignedTransaction;
use aevor_network::gossip::{MessageTransport, NetworkMessage};

use crate::engine::{LaneBlock, LaneRoundOutcome, NodeEngine};
use crate::{NodeError, NodeResult};

/// Serialize a lane for the wire.
#[must_use]
pub fn encode_lane(lane: &LaneBlock) -> Vec<u8> {
    bincode::serialize(lane).unwrap_or_default()
}

/// Deserialize a lane from the wire, or `None` if the bytes are malformed.
#[must_use]
pub fn decode_lane(bytes: &[u8]) -> Option<LaneBlock> {
    bincode::deserialize(bytes).ok()
}

/// How this validator participates in one macro-DAG round.
pub struct RoundConfig {
    /// This validator's lane id for the round.
    pub lane_id: u32,
    /// This validator's identity (producer of its lane).
    pub producer: ValidatorId,
    /// Total lanes expected in the round (this validator + peers).
    pub expected_lanes: usize,
    /// Delay between empty inbox polls while waiting for peers' lanes.
    pub poll: std::time::Duration,
    /// Maximum number of empty polls before the round is abandoned.
    pub max_polls: usize,
}

/// Run one macro-DAG round over `transport`. See the module docs for the flow.
///
/// # Errors
/// Propagates production/apply errors, and returns an error if fewer than
/// `cfg.expected_lanes` lanes are gathered within the poll budget (no quorum).
pub fn run_round<T: MessageTransport>(
    engine: &mut NodeEngine,
    transport: &T,
    cfg: &RoundConfig,
    my_txs: Vec<SignedTransaction>,
) -> NodeResult<LaneRoundOutcome> {
    // Record the round base BEFORE producing — the common fork point every lane
    // in the round shares.
    let round_base = engine.state_root().0 .0;

    // 1. Produce our lane (applies it to our own state) and 2. broadcast it.
    //    The configured identity is what this validator ATTESTS as, so the lane's
    //    producer comes from the signed attestation rather than being carried
    //    alongside it as mutable metadata.
    engine.set_validator_id(cfg.producer);
    let (_out, attestation, delta) = engine.produce_attested_batch(my_txs)?;
    let own = LaneBlock { lane_id: cfg.lane_id, producer: attestation.producer, attestation, delta };
    transport.broadcast(NetworkMessage::Block(encode_lane(&own)));

    // 3. Collect foreign lanes until quorum (dedup by tx_commitment; ignore echoes
    //    of our own lane).
    let mut foreign: std::collections::HashMap<[u8; 32], LaneBlock> =
        std::collections::HashMap::new();
    let mut polls = 0usize;
    while foreign.len() + 1 < cfg.expected_lanes && polls < cfg.max_polls {
        let mut progressed = false;
        for msg in transport.drain_inbound() {
            let NetworkMessage::Block(bytes) = msg else { continue };
            let Some(lane) = decode_lane(&bytes) else { continue };
            if lane.attestation.tx_commitment != own.attestation.tx_commitment
                && foreign.insert(lane.attestation.tx_commitment, lane).is_none()
            {
                progressed = true;
            }
        }
        if !progressed {
            std::thread::sleep(cfg.poll);
            polls += 1;
        }
    }
    if foreign.len() + 1 < cfg.expected_lanes {
        return Err(NodeError::SubsystemCrash {
            subsystem: "macro_dag".to_string(),
            reason: format!(
                "round gathered {} of {} expected lanes before timeout",
                foreign.len() + 1,
                cfg.expected_lanes
            ),
        });
    }

    // 4. Apply the foreign lanes on top of our own and converge.
    let foreign_vec: Vec<LaneBlock> = foreign.into_values().collect();
    engine.apply_foreign_lanes(round_base, &own, &foreign_vec)
}

/// Production validator networking: bind real TCP transport and run rounds.
///
/// This is the default path for a live validator — it owns a real
/// [`aevor_network::gossip::TcpTransport`] bound to this validator's address and
/// connected to the peer set. Tests that run on one machine construct a
/// [`aevor_network::gossip::LocalNetwork`] and call [`run_round`] directly with an
/// endpoint instead; production uses this.
pub struct ValidatorNetwork {
    transport: aevor_network::gossip::TcpTransport,
}

impl ValidatorNetwork {
    /// Bind this validator's listener at `bind_addr` and target `peers` — the
    /// production entry point for live multi-machine operation.
    ///
    /// # Errors
    /// Returns an error if the listener cannot bind.
    pub fn bind(
        bind_addr: std::net::SocketAddr,
        peers: Vec<std::net::SocketAddr>,
    ) -> NodeResult<Self> {
        let transport = aevor_network::gossip::TcpTransport::bind(bind_addr, peers).map_err(|e| {
            NodeError::SubsystemCrash {
                subsystem: "network".to_string(),
                reason: format!("failed to bind transport: {e}"),
            }
        })?;
        Ok(Self { transport })
    }

    /// The bound local address (useful when binding to port 0).
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.transport.local_addr()
    }

    /// Run one macro-DAG round over the real network.
    ///
    /// # Errors
    /// Propagates production/apply errors and quorum-timeout from [`run_round`].
    pub fn run_round(
        &self,
        engine: &mut NodeEngine,
        cfg: &RoundConfig,
        my_txs: Vec<SignedTransaction>,
    ) -> NodeResult<LaneRoundOutcome> {
        run_round(engine, &self.transport, cfg, my_txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{ExecutionAttestation, StateDelta};

    #[test]
    fn lane_wire_round_trip() {
        let lane = LaneBlock {
            lane_id: 7,
            producer: aevor_core::primitives::Hash256([9u8; 32]),
            attestation: ExecutionAttestation::seal(
                aevor_core::primitives::Hash256([9u8; 32]),
                [1u8; 32],
                [2u8; 32],
                [3u8; 32],
                [4u8; 32],
            ),
            delta: StateDelta::default(),
        };
        let bytes = encode_lane(&lane);
        let back = decode_lane(&bytes).expect("decodes");
        assert_eq!(back.lane_id, lane.lane_id);
        assert_eq!(back.attestation, lane.attestation);
        assert_eq!(back.delta, lane.delta);
        assert!(decode_lane(&[0xFF, 0x00, 0x01]).is_none() || decode_lane(&[]).is_none());
    }
}
