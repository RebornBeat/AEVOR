//! Execution pipeline: ordered stages from validation to commit.

use serde::{Deserialize, Serialize};
use aevor_core::execution::ExecutionResult;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    Validation, AccessControl, GasCheck, Execution,
    PrivacyVerification, TeeAttestation, StateCommit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub parallel_stages: bool,
    pub tee_required: bool,
    pub max_pipeline_depth: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self { Self { parallel_stages: true, tee_required: false, max_pipeline_depth: 256 } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineResult {
    pub stage: PipelineStage,
    pub success: bool,
    pub duration_ms: u64,
    pub execution_result: Option<ExecutionResult>,
}

pub struct PreExecutionCheck;
impl PreExecutionCheck {
    /// Validate a transaction before execution begins.
    ///
    /// # Errors
    /// Returns `ExecutionError::VmFailed` if the transaction has a zero gas limit.
    pub fn run(tx: &aevor_core::transaction::SignedTransaction) -> crate::ExecutionResult<()> {
        if tx.transaction.gas_limit == aevor_core::primitives::GasAmount::ZERO {
            return Err(crate::ExecutionError::VmFailed("zero gas limit".into()));
        }
        Ok(())
    }
}

pub struct PostExecutionCommit;
impl PostExecutionCommit {
    pub fn commit(result: &ExecutionResult) -> bool { result.success }
}

pub struct ExecutionPipeline { config: PipelineConfig }
impl ExecutionPipeline {
    pub fn new(config: PipelineConfig) -> Self { Self { config } }
    pub fn stage_count(&self) -> usize { 7 }
    /// The configuration for this pipeline.
    pub fn config(&self) -> &PipelineConfig { &self.config }
    /// Whether this pipeline runs stages in parallel.
    pub fn is_parallel(&self) -> bool { self.config.parallel_stages }
    /// Maximum depth of nested pipeline calls.
    pub fn max_depth(&self) -> usize { self.config.max_pipeline_depth }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::execution::{ExecutionLog, ExecutionResult};
    use aevor_core::primitives::GasAmount;

    fn success_result() -> ExecutionResult {
        ExecutionResult::success(GasAmount::from_u64(21_000), vec![], ExecutionLog::default(), vec![])
    }

    fn failure_result() -> ExecutionResult {
        ExecutionResult::failure(GasAmount::from_u64(5_000), "revert")
    }

    // ── PipelineConfig ──────────────────────────────────────────

    #[test]
    fn pipeline_config_default_parallel_not_tee_required() {
        let cfg = PipelineConfig::default();
        assert!(cfg.parallel_stages);
        assert!(!cfg.tee_required);
        assert_eq!(cfg.max_pipeline_depth, 256);
    }

    // ── PipelineStage ───────────────────────────────────────────

    #[test]
    fn pipeline_stage_variants_are_distinct() {
        assert_ne!(PipelineStage::Validation, PipelineStage::Execution);
        assert_ne!(PipelineStage::GasCheck, PipelineStage::StateCommit);
        assert_ne!(PipelineStage::TeeAttestation, PipelineStage::PrivacyVerification);
    }

    // ── PostExecutionCommit ─────────────────────────────────────

    #[test]
    fn post_execution_commit_true_for_success() {
        assert!(PostExecutionCommit::commit(&success_result()));
    }

    #[test]
    fn post_execution_commit_false_for_failure() {
        assert!(!PostExecutionCommit::commit(&failure_result()));
    }

    // ── PipelineResult ──────────────────────────────────────────

    #[test]
    fn pipeline_result_stores_fields() {
        let pr = PipelineResult {
            stage: PipelineStage::Execution,
            success: true,
            duration_ms: 42,
            execution_result: Some(success_result()),
        };
        assert_eq!(pr.stage, PipelineStage::Execution);
        assert!(pr.success);
        assert_eq!(pr.duration_ms, 42);
        assert!(pr.execution_result.is_some());
    }

    // ── ExecutionPipeline ───────────────────────────────────────

    #[test]
    fn execution_pipeline_stage_count_is_seven() {
        let p = ExecutionPipeline::new(PipelineConfig::default());
        assert_eq!(p.stage_count(), 7);
    }

    #[test]
    fn execution_pipeline_reflects_config() {
        let cfg = PipelineConfig { parallel_stages: false, tee_required: true, max_pipeline_depth: 64 };
        let p = ExecutionPipeline::new(cfg);
        assert!(!p.is_parallel());
        assert_eq!(p.max_depth(), 64);
        assert!(p.config().tee_required);
    }
}
