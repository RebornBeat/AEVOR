//! Message transport for propagation logic.
//!
//! [`MessageTransport`] is the abstraction a node uses to broadcast to peers and
//! receive inbound messages. [`LocalNetwork`] is an in-process implementation
//! that connects multiple nodes via shared queues — it exercises the real
//! gossip/propagation and convergence logic with wire-serialized messages,
//! while a socket-backed transport (QUIC/TCP) implements the same trait for
//! production. Keeping the seam here means the node logic never depends on the
//! concrete transport.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// A message exchanged between nodes. Payloads are already-serialized bytes, so
/// the type is transport-agnostic (the same bytes cross an in-process queue or a
/// real socket).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkMessage {
    /// A serialized signed transaction for mempool propagation.
    Transaction(Vec<u8>),
    /// A serialized block announcement.
    Block(Vec<u8>),
}

/// The transport a node uses to gossip with peers.
pub trait MessageTransport {
    /// Broadcast a message to all connected peers (not to self).
    fn broadcast(&self, message: NetworkMessage);
    /// Take all messages received since the last drain.
    fn drain_inbound(&self) -> Vec<NetworkMessage>;
}

type Inbox = Arc<Mutex<VecDeque<NetworkMessage>>>;

/// A shared in-process network. Each connected endpoint gets its own inbox;
/// broadcasting from one endpoint enqueues the message to every *other*
/// endpoint's inbox.
#[derive(Clone, Default)]
pub struct LocalNetwork {
    inboxes: Arc<Mutex<Vec<Inbox>>>,
}

impl LocalNetwork {
    /// Create an empty network.
    #[must_use]
    pub fn new() -> Self {
        Self { inboxes: Arc::new(Mutex::new(Vec::new())) }
    }

    /// Connect a new node, returning its endpoint handle.
    #[must_use]
    pub fn connect(&self) -> LocalEndpoint {
        let inbox: Inbox = Arc::new(Mutex::new(VecDeque::new()));
        let mut inboxes = self.inboxes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = inboxes.len();
        inboxes.push(Arc::clone(&inbox));
        LocalEndpoint {
            index,
            inboxes: Arc::clone(&self.inboxes),
            own_inbox: inbox,
        }
    }

    /// Number of connected endpoints.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.inboxes.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }
}

/// One node's handle to a [`LocalNetwork`].
pub struct LocalEndpoint {
    index: usize,
    inboxes: Arc<Mutex<Vec<Inbox>>>,
    own_inbox: Inbox,
}

impl MessageTransport for LocalEndpoint {
    fn broadcast(&self, message: NetworkMessage) {
        let inboxes = self.inboxes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (i, inbox) in inboxes.iter().enumerate() {
            if i != self.index {
                inbox.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push_back(message.clone());
            }
        }
    }

    fn drain_inbound(&self) -> Vec<NetworkMessage> {
        let mut queue = self.own_inbox.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.drain(..).collect()
    }
}

/// A real TCP-backed [`MessageTransport`].
///
/// Each node binds a listener and knows its peers' addresses. `broadcast`
/// opens a short connection to each peer and writes a length-prefixed,
/// JSON-serialized [`NetworkMessage`]; a background thread accepts inbound
/// connections and enqueues received messages. This implements the *same* trait
/// as [`LocalEndpoint`], so node logic is identical over an in-process bus or a
/// real socket. (Graceful listener shutdown is a refinement; the accept loop is
/// a detached thread.)
pub struct TcpTransport {
    peers: Vec<std::net::SocketAddr>,
    inbox: Inbox,
    local_addr: std::net::SocketAddr,
}

impl TcpTransport {
    /// Bind to `bind_addr` (use port 0 to let the OS choose) and target `peers`.
    ///
    /// # Errors
    /// Returns an I/O error if the listener cannot bind.
    pub fn bind(
        bind_addr: std::net::SocketAddr,
        peers: Vec<std::net::SocketAddr>,
    ) -> std::io::Result<Self> {
        let listener = std::net::TcpListener::bind(bind_addr)?;
        let local_addr = listener.local_addr()?;
        let inbox: Inbox = Arc::new(Mutex::new(VecDeque::new()));
        let inbox_bg = Arc::clone(&inbox);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                if let Some(msg) = Self::read_message(&mut stream) {
                    inbox_bg
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push_back(msg);
                }
            }
        });
        Ok(Self { peers, inbox, local_addr })
    }

    /// The actual bound address (useful when binding to port 0).
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    fn read_message(stream: &mut std::net::TcpStream) -> Option<NetworkMessage> {
        use std::io::Read as _;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).ok()?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 64 * 1024 * 1024 {
            return None; // guard against absurd frames
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).ok()?;
        decode_message(&buf)
    }
}

/// Wire encoding for a [`NetworkMessage`]: a 1-byte tag then the raw payload.
/// Dependency-free so the transport needs no serialization crate.
fn encode_message(message: &NetworkMessage) -> Vec<u8> {
    let (tag, payload): (u8, &[u8]) = match message {
        NetworkMessage::Transaction(b) => (0, b),
        NetworkMessage::Block(b) => (1, b),
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(tag);
    out.extend_from_slice(payload);
    out
}

fn decode_message(bytes: &[u8]) -> Option<NetworkMessage> {
    let (tag, payload) = bytes.split_first()?;
    match tag {
        0 => Some(NetworkMessage::Transaction(payload.to_vec())),
        1 => Some(NetworkMessage::Block(payload.to_vec())),
        _ => None,
    }
}

impl MessageTransport for TcpTransport {
    fn broadcast(&self, message: NetworkMessage) {
        use std::io::Write as _;
        let bytes = encode_message(&message);
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes();
        for peer in &self.peers {
            if let Ok(mut stream) = std::net::TcpStream::connect(peer) {
                let _ = stream.write_all(&len);
                let _ = stream.write_all(&bytes);
                let _ = stream.flush();
            }
        }
    }

    fn drain_inbound(&self) -> Vec<NetworkMessage> {
        let mut queue = self.inbox.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_reaches_peers_not_self() {
        let net = LocalNetwork::new();
        let a = net.connect();
        let b = net.connect();
        let c = net.connect();
        assert_eq!(net.peer_count(), 3);

        a.broadcast(NetworkMessage::Transaction(vec![1, 2, 3]));

        // A does not receive its own broadcast; B and C do.
        assert!(a.drain_inbound().is_empty());
        assert_eq!(b.drain_inbound(), vec![NetworkMessage::Transaction(vec![1, 2, 3])]);
        assert_eq!(c.drain_inbound(), vec![NetworkMessage::Transaction(vec![1, 2, 3])]);
    }

    #[test]
    fn drain_is_idempotent() {
        let net = LocalNetwork::new();
        let a = net.connect();
        let b = net.connect();
        a.broadcast(NetworkMessage::Block(vec![9]));
        assert_eq!(b.drain_inbound().len(), 1);
        assert!(b.drain_inbound().is_empty()); // already drained
    }

    #[test]
    fn tcp_transport_delivers_across_real_sockets() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Bind B first so we know its address, then bind A pointed at B.
        let b = TcpTransport::bind(SocketAddr::new(lo, 0), vec![]).unwrap();
        let b_addr = b.local_addr();
        let a = TcpTransport::bind(SocketAddr::new(lo, 0), vec![b_addr]).unwrap();

        a.broadcast(NetworkMessage::Transaction(vec![1, 2, 3]));
        // Give B's accept loop a moment to receive over the loopback socket.
        std::thread::sleep(std::time::Duration::from_millis(300));

        assert_eq!(
            b.drain_inbound(),
            vec![NetworkMessage::Transaction(vec![1, 2, 3])],
            "message crossed a real TCP socket"
        );
        // Nothing looped back to the sender.
        assert!(a.drain_inbound().is_empty());
    }
}
