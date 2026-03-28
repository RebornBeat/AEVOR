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

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(name: &str, status: HealthStatus) -> SubsystemHealth {
        SubsystemHealth { name: name.into(), status, message: None }
    }

    #[test]
    fn health_checker_all_healthy() {
        let mut hc = HealthChecker::new();
        hc.register(sub("consensus", HealthStatus::Healthy));
        hc.register(sub("network", HealthStatus::Healthy));
        assert_eq!(hc.overall_status(), HealthStatus::Healthy);
    }

    #[test]
    fn health_checker_one_degraded() {
        let mut hc = HealthChecker::new();
        hc.register(sub("consensus", HealthStatus::Healthy));
        hc.register(sub("storage", HealthStatus::Degraded));
        assert_eq!(hc.overall_status(), HealthStatus::Degraded);
    }

    #[test]
    fn health_checker_any_unhealthy_is_unhealthy() {
        let mut hc = HealthChecker::new();
        hc.register(sub("consensus", HealthStatus::Degraded));
        hc.register(sub("network", HealthStatus::Unhealthy));
        assert_eq!(hc.overall_status(), HealthStatus::Unhealthy);
    }

    #[test]
    fn readiness_probe_fails_if_any_unhealthy() {
        let subs = vec![sub("ok", HealthStatus::Healthy), sub("bad", HealthStatus::Unhealthy)];
        assert!(!ReadinessProbe::check(&subs));
    }

    #[test]
    fn readiness_probe_passes_with_degraded() {
        let subs = vec![sub("ok", HealthStatus::Healthy), sub("warn", HealthStatus::Degraded)];
        assert!(ReadinessProbe::check(&subs));
    }
}
