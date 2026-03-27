//! Cross-chain message queue with ordered delivery.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedMessage { pub id: Hash256, pub nonce: u64, pub payload: Vec<u8>, pub processed: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageDeduplication { pub seen: Vec<Hash256> }
impl MessageDeduplication {
    pub fn new() -> Self { Self { seen: Vec::new() } }
    pub fn is_duplicate(&self, id: &Hash256) -> bool { self.seen.contains(id) }
    pub fn mark_seen(&mut self, id: Hash256) { self.seen.push(id); }
}
impl Default for MessageDeduplication { fn default() -> Self { Self::new() } }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderedDelivery { pub next_nonce: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueueStatus { pub pending: usize, pub processed: u64, pub failed: u64 }

pub struct CrossChainQueue { messages: std::collections::VecDeque<QueuedMessage> }
impl CrossChainQueue {
    pub fn new() -> Self { Self { messages: std::collections::VecDeque::new() } }
    pub fn enqueue(&mut self, m: QueuedMessage) { self.messages.push_back(m); }
    pub fn dequeue(&mut self) -> Option<QueuedMessage> { self.messages.pop_front() }
    pub fn len(&self) -> usize { self.messages.len() }
    pub fn is_empty(&self) -> bool { self.messages.is_empty() }
}
impl Default for CrossChainQueue { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn msg(n: u8) -> QueuedMessage {
        QueuedMessage { id: Hash256([n; 32]), nonce: u64::from(n), payload: vec![n], processed: false }
    }

    #[test]
    fn queue_enqueue_dequeue_fifo() {
        let mut q = CrossChainQueue::new();
        q.enqueue(msg(1));
        q.enqueue(msg(2));
        assert_eq!(q.dequeue().unwrap().nonce, 1);
        assert_eq!(q.dequeue().unwrap().nonce, 2);
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn queue_is_empty_initially() {
        let q = CrossChainQueue::default();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn queue_is_not_empty_after_enqueue() {
        let mut q = CrossChainQueue::new();
        q.enqueue(msg(5));
        assert!(!q.is_empty());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn deduplication_tracks_seen_ids() {
        let mut dedup = MessageDeduplication::new();
        let id = Hash256([7u8; 32]);
        assert!(!dedup.is_duplicate(&id));
        dedup.mark_seen(id);
        assert!(dedup.is_duplicate(&id));
    }
}
