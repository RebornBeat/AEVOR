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

/// Compact binary codec between raw bytecode (`Vec<u8>`) and the instruction
/// stream (`Vec<Instruction>`).
///
/// Encoding: one opcode byte per instruction; `Ld` is followed by its 8-byte
/// little-endian `u64` operand. This is the bridge between deployed contract
/// bytes and the interpreter.
pub struct BytecodeCodec;

impl BytecodeCodec {
    // Opcode assignments (stable wire format).
    const OP_NOP: u8 = 0x00;
    const OP_POP: u8 = 0x01;
    const OP_LD: u8 = 0x02;
    const OP_ST: u8 = 0x03;
    const OP_ADD: u8 = 0x04;
    const OP_SUB: u8 = 0x05;
    const OP_MUL: u8 = 0x06;
    const OP_DIV: u8 = 0x07;
    const OP_CALL: u8 = 0x08;
    const OP_RET: u8 = 0x09;
    const OP_JMP: u8 = 0x0A;
    const OP_JZ: u8 = 0x0B;
    const OP_ALLOC: u8 = 0x0C;
    const OP_FREE: u8 = 0x0D;
    const OP_TEE_ENTER: u8 = 0x0E;
    const OP_TEE_EXIT: u8 = 0x0F;
    const OP_TEE_ATTEST: u8 = 0x10;

    /// Encode an instruction stream to bytes.
    #[must_use]
    pub fn encode(program: &[Instruction]) -> Vec<u8> {
        let mut out = Vec::with_capacity(program.len());
        for instr in program {
            match instr {
                Instruction::Nop => out.push(Self::OP_NOP),
                Instruction::Pop => out.push(Self::OP_POP),
                Instruction::Ld(v) => {
                    out.push(Self::OP_LD);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                Instruction::St => out.push(Self::OP_ST),
                Instruction::Add => out.push(Self::OP_ADD),
                Instruction::Sub => out.push(Self::OP_SUB),
                Instruction::Mul => out.push(Self::OP_MUL),
                Instruction::Div => out.push(Self::OP_DIV),
                Instruction::Call => out.push(Self::OP_CALL),
                Instruction::Ret => out.push(Self::OP_RET),
                Instruction::Jmp => out.push(Self::OP_JMP),
                Instruction::Jz => out.push(Self::OP_JZ),
                Instruction::Alloc => out.push(Self::OP_ALLOC),
                Instruction::Free => out.push(Self::OP_FREE),
                Instruction::TeeEnter => out.push(Self::OP_TEE_ENTER),
                Instruction::TeeExit => out.push(Self::OP_TEE_EXIT),
                Instruction::TeeAttest => out.push(Self::OP_TEE_ATTEST),
            }
        }
        out
    }

    /// Decode bytes into an instruction stream.
    ///
    /// # Errors
    /// Returns [`crate::VmError::BytecodeVerificationFailed`] on an unknown
    /// opcode or a truncated `Ld` operand.
    pub fn decode(bytes: &[u8]) -> crate::VmResult<Vec<Instruction>> {
        let mut program = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            let op = bytes[i];
            i += 1;
            let instr = match op {
                Self::OP_NOP => Instruction::Nop,
                Self::OP_POP => Instruction::Pop,
                Self::OP_LD => {
                    let end = i + 8;
                    let operand = bytes.get(i..end).ok_or_else(|| {
                        crate::VmError::BytecodeVerificationFailed("truncated Ld operand".into())
                    })?;
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(operand);
                    i = end;
                    Instruction::Ld(u64::from_le_bytes(buf))
                }
                Self::OP_ST => Instruction::St,
                Self::OP_ADD => Instruction::Add,
                Self::OP_SUB => Instruction::Sub,
                Self::OP_MUL => Instruction::Mul,
                Self::OP_DIV => Instruction::Div,
                Self::OP_CALL => Instruction::Call,
                Self::OP_RET => Instruction::Ret,
                Self::OP_JMP => Instruction::Jmp,
                Self::OP_JZ => Instruction::Jz,
                Self::OP_ALLOC => Instruction::Alloc,
                Self::OP_FREE => Instruction::Free,
                Self::OP_TEE_ENTER => Instruction::TeeEnter,
                Self::OP_TEE_EXIT => Instruction::TeeExit,
                Self::OP_TEE_ATTEST => Instruction::TeeAttest,
                other => {
                    return Err(crate::VmError::BytecodeVerificationFailed(format!(
                        "unknown opcode 0x{other:02X}"
                    )))
                }
            };
            program.push(instr);
        }
        Ok(program)
    }
}

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

    #[test]
    fn codec_round_trips_all_instruction_kinds() {
        let program = vec![
            Instruction::Nop,
            Instruction::Ld(42),
            Instruction::Ld(u64::MAX),
            Instruction::Add,
            Instruction::Sub,
            Instruction::Mul,
            Instruction::Div,
            Instruction::Pop,
            Instruction::St,
            Instruction::Call,
            Instruction::Ret,
            Instruction::Jmp,
            Instruction::Jz,
            Instruction::Alloc,
            Instruction::Free,
            Instruction::TeeEnter,
            Instruction::TeeExit,
            Instruction::TeeAttest,
        ];
        let bytes = BytecodeCodec::encode(&program);
        let decoded = BytecodeCodec::decode(&bytes).unwrap();
        assert_eq!(decoded, program);
    }

    #[test]
    fn codec_empty_round_trips() {
        assert!(BytecodeCodec::decode(&BytecodeCodec::encode(&[])).unwrap().is_empty());
    }

    #[test]
    fn codec_rejects_unknown_opcode() {
        let err = BytecodeCodec::decode(&[0xFF]).unwrap_err();
        assert!(matches!(err, crate::VmError::BytecodeVerificationFailed(_)));
    }

    #[test]
    fn codec_rejects_truncated_ld_operand() {
        // 0x02 = Ld, but only 3 operand bytes follow instead of 8.
        let err = BytecodeCodec::decode(&[0x02, 0x01, 0x02, 0x03]).unwrap_err();
        assert!(matches!(err, crate::VmError::BytecodeVerificationFailed(_)));
    }
}
