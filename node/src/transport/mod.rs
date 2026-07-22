//! Transport seam — how a validator exchanges consensus messages with peers.
//!
//! This defines the message set and the [`Transport`] abstraction, plus an
//! in-memory backend for exercising multi-node logic in a single process
//! (single-core, no real network). The production backend — real gossip /
//! propagation over the network — is provided by `aevor-network` and plugs in
//! behind the same trait, so the consensus flow is identical whether a message
//! travels across a process or the globe:
//!
//! 1. each validator produces its lane ([`crate::engine::NodeEngine::produce_attested_batch`]),
//! 2. broadcasts it as a [`NetworkMessage::Lane`],
//! 3. every validator collects the round's lanes and applies them
//!    ([`crate::engine::NodeEngine::apply_lane_round`]) — object writes reproduce
//!    the round root, per-lane balance deltas settle against each account,
//! 4. all validators converge to the identical state.
//!
//! The in-memory backend delivers synchronously and losslessly: it models the
//! *logic* of exchange and convergence, not the wire (latency, loss, ordering,
//! peer discovery, and bandwidth shaping are `aevor-network`'s concern).

use crate::engine::LaneBlock;
use std::cell::RefCell;
use std::rc::Rc;

/// A consensus message exchanged between validators in a macro-DAG round.
#[derive(Clone)]
pub enum NetworkMessage {
    /// One validator's produced lane: its Proof-of-Uncorruption attestation plus
    /// the state delta (object writes + per-account balance deltas). A verifier
    /// feeds this into [`crate::engine::NodeEngine::apply_lane_round`].
    Lane(Box<LaneBlock>),
}

/// How a node sends to, and receives from, its peers. A real backend gossips over
/// the network; the in-memory backend delivers within one process. Keeping the
/// consensus code behind this trait means the node is agnostic to the wire.
pub trait Transport {
    /// Broadcast a message to every peer.
    fn broadcast(&mut self, message: NetworkMessage);
    /// Take everything delivered to this node since the last call.
    fn drain(&mut self) -> Vec<NetworkMessage>;
}

type Inboxes = Rc<RefCell<Vec<Vec<NetworkMessage>>>>;

/// An in-memory broadcast network connecting `n` in-process nodes. Delivery is
/// synchronous and lossless — it models the logic of exchange, not the wire.
/// Obtain each node's [`Transport`] via [`InMemoryNet::handle`].
pub struct InMemoryNet {
    inboxes: Inboxes,
}

impl InMemoryNet {
    /// A network of `nodes` in-process participants.
    #[must_use]
    pub fn new(nodes: usize) -> Self {
        Self { inboxes: Rc::new(RefCell::new(vec![Vec::new(); nodes])) }
    }

    /// A transport handle for node `index`.
    #[must_use]
    pub fn handle(&self, index: usize) -> InMemoryHandle {
        InMemoryHandle { index, inboxes: Rc::clone(&self.inboxes) }
    }
}

/// One node's handle onto an [`InMemoryNet`].
pub struct InMemoryHandle {
    index: usize,
    inboxes: Inboxes,
}

impl Transport for InMemoryHandle {
    fn broadcast(&mut self, message: NetworkMessage) {
        let mut boxes = self.inboxes.borrow_mut();
        let n = boxes.len();
        for (i, inbox) in boxes.iter_mut().enumerate().take(n) {
            if i != self.index {
                inbox.push(message.clone());
            }
        }
    }

    fn drain(&mut self) -> Vec<NetworkMessage> {
        std::mem::take(&mut self.inboxes.borrow_mut()[self.index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_reaches_every_peer_but_not_the_sender() {
        let net = InMemoryNet::new(3);
        let mut a = net.handle(0);
        let mut b = net.handle(1);
        let mut c = net.handle(2);
        // Node 0 broadcasts; 1 and 2 receive, 0 does not.
        a.broadcast(NetworkMessage::Lane(Box::new(sample_lane(7))));
        assert_eq!(a.drain().len(), 0, "sender does not receive its own broadcast");
        assert_eq!(b.drain().len(), 1, "peer receives");
        assert_eq!(c.drain().len(), 1, "peer receives");
        // Draining is consuming.
        assert_eq!(b.drain().len(), 0, "inbox emptied on drain");
    }

    fn sample_lane(id: u8) -> LaneBlock {
        use aevor_core::primitives::Hash256;
        LaneBlock {
            lane_id: u32::from(id),
            producer: Hash256([id; 32]),
            attestation: crate::engine::ExecutionAttestation::seal(
                [0u8; 32],
                [1u8; 32],
                [2u8; 32],
                [3u8; 32],
            ),
            delta: crate::engine::StateDelta::default(),
        }
    }
}
