//! Hardware-agnostic compute abstraction.
//!
//! AEVOR maximises throughput on whatever processing units a validator runs.
//! Two kinds of parallelism compose (see the dual-DAG): **intra-lane** parallel
//! execution (independent transactions within a block) and **inter-lane**
//! concurrent block production across validators. This module governs the
//! *intra-lane* / per-node side: it detects the host's compute capabilities and
//! selects a [`ComputeBackend`] to run batchable, independent work in parallel.
//!
//! - **CPU** is the always-available backend and scales to every available core
//!   ([`CpuBackend`], via rayon). Calling [`ComputeProfile::configure`] at node
//!   startup sizes the global work-stealing pool to the detected core count, so
//!   the parallel execution in `aevor-execution` automatically uses all cores —
//!   no configuration needed by the operator.
//! - **GPU / TPU / NPU** are *pluggable accelerator backends*: they implement
//!   the same [`ComputeBackend`] trait to offload batchable primitives
//!   (signature verification, hashing, BLS pairing — the parts that are wide and
//!   uniform) where the hardware is present. The trait is the integration point;
//!   a concrete accelerator backend is added per target once that hardware is
//!   available to test against. General bytecode execution stays on the CPU
//!   (it is branchy and not accelerator-shaped); accelerators earn their place
//!   on the uniform batch primitives, which is exactly where they help.
//!
//! The point is that a validator on a 4-core laptop, a 128-core server, or a
//! server with an accelerator all run the *same* node and each extracts the
//! throughput its hardware allows, without code changes.

/// A class of processing unit a validator may run on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessingUnit {
    /// General-purpose CPU cores (always available).
    Cpu,
    /// Graphics processing unit.
    Gpu,
    /// Tensor processing unit.
    Tpu,
    /// Neural processing unit.
    Npu,
}

/// Detected compute capabilities of the host.
#[derive(Clone, Debug)]
pub struct ComputeCapabilities {
    /// Number of hardware threads available for CPU parallelism.
    pub cpu_threads: usize,
    /// Accelerators detected on the host (empty until an accelerator backend is
    /// present for the target — detection is per-backend).
    pub accelerators: Vec<ProcessingUnit>,
}

impl ComputeCapabilities {
    /// Detect the host's capabilities. CPU thread count comes from the OS;
    /// accelerator detection is delegated to accelerator backends and is empty
    /// by default.
    #[must_use]
    pub fn detect() -> Self {
        let cpu_threads = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get);
        Self { cpu_threads, accelerators: Vec::new() }
    }

    /// The intra-lane parallelism degree to use (at least 1).
    #[must_use]
    pub fn parallelism_degree(&self) -> usize {
        self.cpu_threads.max(1)
    }
}

/// A backend that runs a batch of independent boolean checks (e.g. per-signature
/// verifications) in parallel and reports how many passed.
///
/// This is deliberately the *shape* of the batchable primitives on AEVOR's hot
/// path: a wide set of independent, uniform checks. The CPU backend runs them on
/// the work-stealing pool; an accelerator backend offloads the whole batch. The
/// trait is object-safe so a node can hold `Box<dyn ComputeBackend>` chosen at
/// startup from the detected hardware.
pub trait ComputeBackend: Send + Sync {
    /// Which processing unit this backend targets.
    fn unit(&self) -> ProcessingUnit;
    /// The effective parallelism (lanes/threads/streams) of this backend.
    fn parallelism(&self) -> usize;
    /// Run all `checks` in parallel and return how many returned `true`.
    fn parallel_pass_count(&self, checks: Vec<Box<dyn Fn() -> bool + Send>>) -> usize;
}

/// The always-available CPU backend. Scales to every available core via rayon's
/// global work-stealing pool.
pub struct CpuBackend {
    threads: usize,
}

impl CpuBackend {
    /// Create a CPU backend sized to the detected core count.
    #[must_use]
    pub fn new() -> Self {
        Self { threads: ComputeCapabilities::detect().parallelism_degree() }
    }
}

impl Default for CpuBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputeBackend for CpuBackend {
    fn unit(&self) -> ProcessingUnit {
        ProcessingUnit::Cpu
    }

    fn parallelism(&self) -> usize {
        self.threads
    }

    fn parallel_pass_count(&self, checks: Vec<Box<dyn Fn() -> bool + Send>>) -> usize {
        use rayon::prelude::*;
        checks.into_par_iter().filter(|c| c()).count()
    }
}

/// An accelerator backend that offloads batchable primitives (signature
/// verification, hashing, BLS pairing) to a GPU / TPU / NPU.
///
/// Real acceleration is enabled per target behind an acceleration feature that
/// links the vendor runtime and supplies the device kernel — that is the ONLY
/// place vendor-specific code lives, keeping the node hardware-agnostic. Two
/// invariants make this safe and complete for operators who *do* have the
/// hardware, on a build that (like this one) does not:
///
/// 1. [`AcceleratorBackend::detect`] returns `None` unless the acceleration
///    feature is enabled *and* the device is present, so a default build simply
///    selects the CPU backend — no accelerator is ever assumed.
/// 2. If an accelerator backend is constructed but no device kernel is linked,
///    [`parallel_pass_count`](ComputeBackend::parallel_pass_count) falls back to
///    CPU parallelism. It is therefore always *functional* — never a panic and
///    never a silent no-op — so wiring an accelerator can never break a node; it
///    can only make it faster once the kernel is present.
///
/// This is the finalized integration contract: the selection, fallback, and
/// reporting are complete here; a target adds its detection + kernel behind its
/// feature to light up real acceleration.
pub struct AcceleratorBackend {
    unit: ProcessingUnit,
    /// Parallel streams/units the device exposes (its effective parallelism).
    lanes: usize,
}

impl AcceleratorBackend {
    /// Detect an accelerator of `unit` on this host.
    ///
    /// Returns `None` in a default build (no acceleration feature / no device),
    /// so the CPU backend is selected. A target enables detection by supplying
    /// its device query behind its acceleration feature.
    #[must_use]
    pub fn detect(unit: ProcessingUnit) -> Option<Self> {
        // Vendor detection extension point. No accelerator in a default build, so
        // this returns None and the CPU backend is selected. A target adds its
        // device query here behind its acceleration feature (and would return
        // `Some(Self::new(unit, device_lanes))` when the device is present).
        let _ = unit;
        None
    }

    /// Construct an accelerator backend explicitly (e.g. from a target's device
    /// query). `lanes` is the device's effective parallelism.
    #[must_use]
    pub fn new(unit: ProcessingUnit, lanes: usize) -> Self {
        Self { unit, lanes: lanes.max(1) }
    }
}

impl ComputeBackend for AcceleratorBackend {
    fn unit(&self) -> ProcessingUnit {
        self.unit
    }

    fn parallelism(&self) -> usize {
        self.lanes
    }

    fn parallel_pass_count(&self, checks: Vec<Box<dyn Fn() -> bool + Send>>) -> usize {
        // A real build dispatches the batch to the device kernel here. With no
        // kernel linked, fall back to CPU parallelism so the backend is always
        // functional.
        use rayon::prelude::*;
        checks.into_par_iter().filter(|c| c()).count()
    }
}

/// A validator's selected compute profile: the detected capabilities plus the
/// chosen backend. Built once at startup.
pub struct ComputeProfile {
    capabilities: ComputeCapabilities,
    backend: Box<dyn ComputeBackend>,
}

impl ComputeProfile {
    /// Detect capabilities and select the best available backend: an
    /// accelerator (GPU, then TPU, then NPU) if one is present, otherwise the
    /// CPU backend scaled to all cores. In a default build no accelerator is
    /// detected, so this is CPU.
    #[must_use]
    pub fn detect() -> Self {
        let mut capabilities = ComputeCapabilities::detect();
        let backend: Box<dyn ComputeBackend> = [
            ProcessingUnit::Gpu,
            ProcessingUnit::Tpu,
            ProcessingUnit::Npu,
        ]
        .into_iter()
        .find_map(AcceleratorBackend::detect)
        .map_or_else(
            || Box::new(CpuBackend::new()) as Box<dyn ComputeBackend>,
            |accel| {
                capabilities.accelerators.push(accel.unit());
                Box::new(accel) as Box<dyn ComputeBackend>
            },
        );
        Self { capabilities, backend }
    }

    /// The processing unit the selected backend runs on.
    #[must_use]
    pub fn backend_unit(&self) -> ProcessingUnit {
        self.backend.unit()
    }

    /// The detected capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &ComputeCapabilities {
        &self.capabilities
    }

    /// The selected backend.
    #[must_use]
    pub fn backend(&self) -> &dyn ComputeBackend {
        self.backend.as_ref()
    }

    /// Size the global work-stealing pool to the detected core count so that all
    /// parallel execution uses every available core. Idempotent-safe: returns
    /// `false` if a global pool was already configured (rayon allows this once),
    /// which is not an error.
    pub fn configure(&self) -> bool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(self.capabilities.parallelism_degree())
            .build_global()
            .is_ok()
    }
}

impl Default for ComputeProfile {
    fn default() -> Self {
        Self::detect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_at_least_one_thread() {
        let caps = ComputeCapabilities::detect();
        assert!(caps.cpu_threads >= 1);
        assert!(caps.parallelism_degree() >= 1);
    }

    #[test]
    fn cpu_backend_counts_passes_in_parallel() {
        let backend = CpuBackend::new();
        assert_eq!(backend.unit(), ProcessingUnit::Cpu);
        assert!(backend.parallelism() >= 1);
        // 100 checks; the even-indexed ones pass.
        let checks: Vec<Box<dyn Fn() -> bool + Send>> =
            (0..100).map(|i| Box::new(move || i % 2 == 0) as Box<dyn Fn() -> bool + Send>).collect();
        assert_eq!(backend.parallel_pass_count(checks), 50);
    }

    #[test]
    fn profile_selects_cpu_by_default() {
        let profile = ComputeProfile::detect();
        assert_eq!(profile.backend().unit(), ProcessingUnit::Cpu);
        assert_eq!(profile.backend_unit(), ProcessingUnit::Cpu);
        assert!(profile.capabilities().cpu_threads >= 1);
        // No accelerator detected in a default build.
        assert!(profile.capabilities().accelerators.is_empty());
    }

    #[test]
    fn no_accelerator_detected_by_default() {
        assert!(AcceleratorBackend::detect(ProcessingUnit::Gpu).is_none());
        assert!(AcceleratorBackend::detect(ProcessingUnit::Tpu).is_none());
        assert!(AcceleratorBackend::detect(ProcessingUnit::Npu).is_none());
    }

    #[test]
    fn accelerator_backend_is_functional_via_fallback() {
        // Constructed explicitly (as a target's device query would): reports its
        // unit and still does the work (CPU fallback with no kernel linked).
        let gpu = AcceleratorBackend::new(ProcessingUnit::Gpu, 4096);
        assert_eq!(gpu.unit(), ProcessingUnit::Gpu);
        assert_eq!(gpu.parallelism(), 4096);
        let checks: Vec<Box<dyn Fn() -> bool + Send>> =
            (0..64).map(|i| Box::new(move || i % 4 == 0) as Box<dyn Fn() -> bool + Send>).collect();
        assert_eq!(gpu.parallel_pass_count(checks), 16);
    }
}
