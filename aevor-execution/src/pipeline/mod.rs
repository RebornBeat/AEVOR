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
    pub fn run(tx: &aevor_core::transaction::SignedTransaction) -> crate::ExecutionResult<()> {
        if tx.transaction.gas_limit == aevor_core::primitives::GasAmount::ZERO {
            return Err(crate::ExecutionError::InvalidInput("zero gas limit".into()));
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
}
