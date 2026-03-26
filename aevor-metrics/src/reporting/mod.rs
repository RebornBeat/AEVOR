//! Metrics reporting and dashboards.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportConfig { pub interval_seconds: u64, pub include_private_metrics: bool }
impl Default for ReportConfig { fn default() -> Self { Self { interval_seconds: 60, include_private_metrics: false } } }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsReport { pub timestamp_round: u64, pub sections: Vec<String> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationalDashboard { pub name: String, pub panels: Vec<String> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricSnapshot { pub metric: String, pub value: f64, pub round: u64 }
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ReportInterval { Second, Minute, Hour, Epoch }
