//! AevorVM instruction set: encoding, decoding, and gas cost lookup.

use serde::{Deserialize, Serialize};

/// A single AevorVM bytecode instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    // ── Stack ──────────────────────────────────────────────────
    /// No operation.
    Nop,
    /// Pop the top value from the stack.
    Pop,
    /// Push a 64-bit integer literal.
    Ld(u64),
    /// Store TOS to memory.
    St,
    // ── Arithmetic ─────────────────────────────────────────────
    /// Add top two stack values.
    Add,
    /// Subtract: (TOS-1) - TOS.
    Sub,
    /// Multiply top two stack values.
    Mul,
    /// Integer divide: (TOS-1) / TOS.
    Div,
    // ── Control flow ───────────────────────────────────────────
    /// Call a function by index.
    Call,
    /// Return from current function.
    Ret,
    /// Unconditional jump.
    Jmp,
    /// Jump if TOS == 0.
    Jz,
    // ── Memory ─────────────────────────────────────────────────
    /// Allocate heap memory.
    Alloc,
    /// Free heap memory.
    Free,
    // ── TEE ────────────────────────────────────────────────────
    /// Enter a TEE execution context.
    TeeEnter,
    /// Exit the TEE execution context.
    TeeExit,
    /// Request a TEE attestation report.
    TeeAttest,
}

impl Instruction {
    /// Base gas cost of this instruction.
    pub fn base_gas(&self) -> u64 {
        match self {
            Self::Nop                          =>   0,
            Self::Pop | Self::Ld(_)            =>   1,
            Self::St                           =>   3,
            Self::Add | Self::Sub              =>   3,
            Self::Mul                          =>   5,
            Self::Div                          =>   8,
            Self::Call | Self::Ret             =>  20,
            Self::Jmp | Self::Jz              =>   4,
            Self::Alloc                        => 300,
            Self::Free                         => 100,
            Self::TeeEnter | Self::TeeExit     => 500,
            Self::TeeAttest                    => 2000,
        }
    }

    /// Returns `true` if this instruction modifies control flow.
    pub fn is_branch(&self) -> bool {
        matches!(self, Self::Jmp | Self::Jz | Self::Call | Self::Ret)
    }

    /// Returns `true` if this instruction requires TEE context.
    pub fn requires_tee(&self) -> bool {
        matches!(self, Self::TeeEnter | Self::TeeExit | Self::TeeAttest)
    }
}

/// A decoded instruction with its byte offset in the function body.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct DecodedInstruction {
    /// Byte offset within the function's instruction stream.
    pub offset: u32,
    /// The instruction at this offset.
    pub instruction: Instruction,
}

impl DecodedInstruction {
    /// Create a decoded instruction.
    pub fn new(offset: u32, instruction: Instruction) -> Self {
        Self { offset, instruction }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tee_instructions_require_tee() {
        assert!(Instruction::TeeEnter.requires_tee());
        assert!(Instruction::TeeAttest.requires_tee());
        assert!(!Instruction::Add.requires_tee());
    }

    #[test]
    fn branch_instructions_are_branches() {
        assert!(Instruction::Jmp.is_branch());
        assert!(Instruction::Call.is_branch());
        assert!(!Instruction::Add.is_branch());
    }

    #[test]
    fn nop_costs_zero_gas() {
        assert_eq!(Instruction::Nop.base_gas(), 0);
    }

    #[test]
    fn tee_attest_costs_most() {
        assert!(Instruction::TeeAttest.base_gas() > Instruction::Add.base_gas());
    }
}
