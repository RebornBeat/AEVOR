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

    /// The underlying routing table mapping node IDs to paths.
    pub fn routing_table(&self) -> &RoutingTable { &self.routing_table }

    /// Register a route to `dest` via the given path.
    pub fn add_route(&mut self, dest: NodeId, path: RoutePath) {
        self.routing_table.add(dest, path);
    }

    /// Look up the route to `dest`, if one is registered.
    pub fn route(&self, dest: &NodeId) -> Option<&RoutePath> {
        self.routing_table.get(dest)
    }

    /// Number of routes in the routing table.
    pub fn route_count(&self) -> usize { self.routing_table.entries.len() }
}
impl Default for Router { fn default() -> Self { Self::new() } }
