//! Geographic routing optimization.
//!
//! Geographic diversity is a core AEVOR decentralization property —
//! validators and nodes should be distributed across multiple regions
//! to resist geographic-based attacks or regulatory shutdown.

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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::network::GeographicRegion;

    #[test]
    fn latency_matrix_lookup() {
        let matrix = LatencyMatrix {
            pairs: vec![
                (GeographicRegion::NorthAmerica, GeographicRegion::WesternEurope, 80),
                (GeographicRegion::WesternEurope, GeographicRegion::EastAsia, 120),
            ],
        };
        assert_eq!(matrix.latency(GeographicRegion::NorthAmerica, GeographicRegion::WesternEurope), Some(80));
        assert_eq!(matrix.latency(GeographicRegion::WesternEurope, GeographicRegion::EastAsia), Some(120));
        assert_eq!(matrix.latency(GeographicRegion::EastAsia, GeographicRegion::NorthAmerica), None);
    }

    #[test]
    fn geo_router_finds_fastest_region() {
        let matrix = LatencyMatrix {
            pairs: vec![
                (GeographicRegion::NorthAmerica, GeographicRegion::WesternEurope, 80),
                (GeographicRegion::NorthAmerica, GeographicRegion::EastAsia, 150),
            ],
        };
        let router = GeoRouter::new(matrix);
        // WesternEurope has lower latency from NorthAmerica
        assert_eq!(router.fastest_region(GeographicRegion::NorthAmerica), Some(GeographicRegion::WesternEurope));
    }

    #[test]
    fn geo_router_no_routes_returns_none() {
        let router = GeoRouter::new(LatencyMatrix { pairs: vec![] });
        assert_eq!(router.fastest_region(GeographicRegion::SouthAsia), None);
    }

    #[test]
    fn geographic_distribution_region_count() {
        let mut dist = GeographicDistribution { by_region: std::collections::HashMap::new() };
        dist.by_region.insert("NorthAmerica".into(), 5);
        dist.by_region.insert("WesternEurope".into(), 3);
        dist.by_region.insert("EastAsia".into(), 0); // zero does not count
        assert_eq!(dist.region_count(), 2);
    }

    #[test]
    fn region_config_stores_constraints() {
        let cfg = RegionConfig {
            region: GeographicRegion::WesternEurope,
            min_peers: 3,
            max_latency_ms: 200,
        };
        assert_eq!(cfg.region, GeographicRegion::WesternEurope);
        assert_eq!(cfg.min_peers, 3);
    }
}
