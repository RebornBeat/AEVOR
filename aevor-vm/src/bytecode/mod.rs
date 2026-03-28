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
    /// Verify that bytecode is structurally valid.
    ///
    /// # Errors
    /// Returns an error if the bytecode is empty or fails structural validation.
    pub fn verify(bytecode: &Bytecode) -> crate::VmResult<()> {
        if bytecode.module.bytes.is_empty() {
            return Err(crate::VmError::BytecodeVerificationFailed("empty bytecode".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Hash256};

    fn module(bytes: Vec<u8>) -> BytecodeModule {
        BytecodeModule { address: Address([1u8; 32]), name: "TestModule".into(), bytes, hash: Hash256::ZERO }
    }

    fn bytecode(bytes: Vec<u8>) -> Bytecode {
        Bytecode { module: module(bytes), functions: vec![] }
    }

    #[test]
    fn verifier_accepts_nonempty_bytecode() {
        let bc = bytecode(vec![0x01, 0x02, 0x03]);
        assert!(BytecodeVerifier::verify(&bc).is_ok());
    }

    #[test]
    fn verifier_rejects_empty_bytecode() {
        let bc = bytecode(vec![]);
        assert!(BytecodeVerifier::verify(&bc).is_err());
    }

    #[test]
    fn bytecode_module_stores_fields() {
        let m = module(vec![0xAB; 10]);
        assert_eq!(m.name, "TestModule");
        assert_eq!(m.bytes.len(), 10);
    }

    #[test]
    fn function_definition_stores_name_and_locals() {
        let fd = FunctionDefinition { name: "transfer".into(), instructions: vec![], locals_count: 3 };
        assert_eq!(fd.name, "transfer");
        assert_eq!(fd.locals_count, 3);
    }
}
