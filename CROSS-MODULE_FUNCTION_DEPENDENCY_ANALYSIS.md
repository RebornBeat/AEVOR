# Cross-Module Function Dependency Analysis

## core Module
- `core::state::GlobalState`:
  - Used in: `execution::context`, `storage::state_store`
- `core::block::Block`:
  - Used in: `consensus::dag_manager`, `consensus::finality`, `consensus::pou`, `networking::protocol`, `storage::blockchain`, `api::handlers::block`, `cli::commands::chain`
- `core::transaction::Transaction`:
  - Used in: `consensus::validation`, `execution::engine`, `networking::protocol`, `storage::blockchain`, `api::handlers::transaction`, `cli::commands::transaction`
- `core::object::Object`:
  - Used in: `consensus::superposition`, `execution::context`, `execution::validator`, `storage::object_store`, `api::handlers::object`
- `core::merkle::MerkleTree`:
  - Used in: `storage::state_store`

## consensus Module
- `consensus::dag_manager::DAGManager`:
  - Used in: `execution::engine`
- `consensus::pou::ProofOfUncorruption`:
  - Used in: `networking::sync`, `cli::commands::validator`
- `consensus::validation::ValidationManager`:
  - Used in: `api::handlers::validator`
- `consensus::security_accelerator::SecurityAccelerator`:
  - Used in: `api::handlers::validator`

## execution Module
- `execution::engine::ExecutionEngine`:
  - Used in: `api::handlers::transaction`, `cli::commands::transaction`
- `execution::validator::ExecutionValidator`:
  - Used in: `api::handlers::transaction`, `cli::commands::transaction`

## storage Module
- `storage::blockchain::BlockchainStore`:
  - Used in: `core::state`, `networking::sync`, `api::handlers::block`, `cli::commands::chain`
- `storage::object_store::ObjectStore`:
  - Used in: `execution::context`, `execution::validator`, `api::handlers::object`
- `storage::state_store::StateStore`:
  - Used in: `core::state`

## networking Module
- `networking::protocol::Protocol`:
  - Used in: `consensus::dag_manager`, `consensus::pou`
- `networking::sync::SyncManager`:
  - Used in: `consensus::pou`

## crypto Module
- `crypto::hash::Hash`:
  - Used in: `core::block`, `core::object`, `core::transaction`, `execution::validator`, `cli::commands::utils`
- `crypto::signature::Signature`:
  - Used in: `core::block`, `core::transaction`, `consensus::pou`, `networking::peer`, `networking::protocol`

## vm Module
- `vm::move_vm::MoveVM`:
  - Used in: `execution::engine`, `api::handlers::contract`, `cli::commands::contract`

## api Module
- `api::handlers::block`:
  - Uses: `core::block`, `storage::blockchain`
- `api::handlers::transaction`:
  - Uses: `core::transaction`, `execution::engine`, `execution::validator`
- `api::handlers::object`:
  - Uses: `core::object`, `storage::object_store`
- `api::handlers::validator`:
  - Uses: `consensus::validation`, `consensus::security_accelerator`
- `api::handlers::contract`:
  - Uses: `vm::move_vm`

## cli Module
- `cli::commands::chain`:
  - Uses: `core::block`, `storage::blockchain`
- `cli::commands::transaction`:
  - Uses: `core::transaction`, `execution::engine`, `execution::validator`
- `cli::commands::validator`:
  - Uses: `consensus::pou`
- `cli::commands::contract`:
  - Uses: `vm::move_vm`
- `cli::commands::utils`:
  - Uses: `crypto::hash`
