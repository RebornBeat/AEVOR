//! Node-wide metrics.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SystemMetrics { pub cpu_pct: f64, pub memory_bytes: u64, pub disk_bytes: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsystemMetrics { pub name: String, pub healthy: bool, pub requests: u64 }
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeMetrics { pub system: SystemMetrics, pub subsystems: Vec<SubsystemMetrics> }
pub struct MetricsDashboard;
