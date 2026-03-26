//! Topology-aware and privacy-preserving message routing.

use serde::{Deserialize, Serialize};
use aevor_core::network::{GeographicRegion, NodeId};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutePath { pub hops: Vec<NodeId>, pub latency_ms: u32 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeographicRoute { pub source_region: GeographicRegion, pub dest_region: GeographicRegion, pub path: RoutePath }

pub struct RoutingTable { entries: std::collections::HashMap<[u8; 32], RoutePath> }
impl RoutingTable {
    pub fn new() -> Self { Self { entries: std::collections::HashMap::new() } }
    pub fn add(&mut self, dest: NodeId, path: RoutePath) { self.entries.insert(dest.0.0, path); }
    pub fn get(&self, dest: &NodeId) -> Option<&RoutePath> { self.entries.get(&dest.0.0) }
}
impl Default for RoutingTable { fn default() -> Self { Self::new() } }

pub struct TopologyAwareRouter { table: RoutingTable }
impl TopologyAwareRouter {
    pub fn new() -> Self { Self { table: RoutingTable::new() } }
    pub fn route(&self, dest: &NodeId) -> Option<&RoutePath> { self.table.get(dest) }
}
impl Default for TopologyAwareRouter { fn default() -> Self { Self::new() } }

pub struct PrivacyPreservingRouter;

pub struct Router { routing_table: RoutingTable }
impl Router {
    pub fn new() -> Self { Self { routing_table: RoutingTable::new() } }
}
impl Default for Router { fn default() -> Self { Self::new() } }
