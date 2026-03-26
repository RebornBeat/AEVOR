//! Health checking and readiness probes.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus { Healthy, Degraded, Unhealthy }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsystemHealth { pub name: String, pub status: HealthStatus, pub message: Option<String> }
pub struct ReadinessProbe;
pub struct LivenessProbe;
impl ReadinessProbe {
    pub fn check(subsystems: &[SubsystemHealth]) -> bool {
        subsystems.iter().all(|s| s.status != HealthStatus::Unhealthy)
    }
}

pub struct HealthChecker { subsystems: Vec<SubsystemHealth> }
impl HealthChecker {
    pub fn new() -> Self { Self { subsystems: Vec::new() } }
    pub fn register(&mut self, h: SubsystemHealth) { self.subsystems.push(h); }
    pub fn overall_status(&self) -> HealthStatus {
        if self.subsystems.iter().any(|s| s.status == HealthStatus::Unhealthy) { HealthStatus::Unhealthy }
        else if self.subsystems.iter().any(|s| s.status == HealthStatus::Degraded) { HealthStatus::Degraded }
        else { HealthStatus::Healthy }
    }
}
impl Default for HealthChecker { fn default() -> Self { Self::new() } }
