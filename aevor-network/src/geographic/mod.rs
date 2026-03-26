//! Geographic routing optimization.

use serde::{Deserialize, Serialize};
pub use aevor_core::network::GeographicRegion;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegionConfig { pub region: GeographicRegion, pub min_peers: usize, pub max_latency_ms: u32 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencyMatrix {
    pub pairs: Vec<(GeographicRegion, GeographicRegion, u32)>,
}

impl LatencyMatrix {
    pub fn latency(&self, from: GeographicRegion, to: GeographicRegion) -> Option<u32> {
        self.pairs.iter().find(|(f, t, _)| *f == from && *t == to).map(|(_, _, l)| *l)
    }
}

pub struct GeoRouter { matrix: LatencyMatrix }
impl GeoRouter {
    pub fn new(matrix: LatencyMatrix) -> Self { Self { matrix } }
    pub fn fastest_region(&self, from: GeographicRegion) -> Option<GeographicRegion> {
        self.matrix.pairs.iter()
            .filter(|(f, _, _)| *f == from)
            .min_by_key(|(_, _, l)| l)
            .map(|(_, t, _)| *t)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeographicDistribution { pub by_region: std::collections::HashMap<String, usize> }

impl GeographicDistribution {
    pub fn region_count(&self) -> usize { self.by_region.values().filter(|&&c| c > 0).count() }
}
