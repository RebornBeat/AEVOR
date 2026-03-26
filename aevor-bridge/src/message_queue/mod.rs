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
}
impl Default for CrossChainQueue { fn default() -> Self { Self::new() } }
