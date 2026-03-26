//! Bytecode module: instruction encoding, verification.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
pub use crate::instructions::{Instruction, DecodedInstruction};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BytecodeModule {
    pub address: aevor_core::primitives::Address,
    pub name: String,
    pub bytes: Vec<u8>,
    pub hash: Hash256,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionDefinition {
    pub name: String,
    pub instructions: Vec<Instruction>,
    pub locals_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bytecode {
    pub module: BytecodeModule,
    pub functions: Vec<FunctionDefinition>,
}

pub struct BytecodeVerifier;

impl BytecodeVerifier {
    pub fn verify(bytecode: &Bytecode) -> crate::VmResult<()> {
        if bytecode.module.bytes.is_empty() {
            return Err(crate::VmError::BytecodeVerificationFailed("empty bytecode".into()));
        }
        Ok(())
    }
}
