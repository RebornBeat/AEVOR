//! Bytecode interpreter for the AevorVM instruction set.
//!
//! Executes a slice of [`Instruction`]s **deterministically** with real gas
//! metering ([`GasMeter`]), a value stack, a simple linear memory, and
//! TEE-context tracking. Determinism and cross-platform consistency are core
//! AevorVM properties: identical input yields identical output *and* identical
//! gas cost on any platform.
//!
//! Termination is guaranteed: every instruction charges gas against a finite
//! limit, and an independent step bound backstops pathological jump loops.
//!
//! Control-flow opcodes in this instruction set carry no inline operand, so
//! they take their target/condition from the stack (documented per-opcode
//! below). This is the interpreter that the rest of the VM (contract deploy /
//! lookup) and the execution pipeline build on.

use crate::gas::GasMeter;
use crate::instructions::Instruction;
use crate::vm::VmState;
use crate::{VmError, VmResult};
use aevor_core::primitives::GasAmount;

/// Outcome of executing a program to completion.
#[derive(Clone, Debug)]
pub struct ExecutionOutcome {
    /// Value left on top of the stack at completion (0 if the stack is empty).
    pub return_value: u64,
    /// Total gas consumed.
    pub gas_used: GasAmount,
    /// Whether a TEE attestation was produced (`TeeAttest`) during execution.
    pub tee_attested: bool,
    /// Final VM state (gas used, call depth, TEE-active flag).
    pub final_state: VmState,
}

/// A deterministic interpreter for the `AevorVM` instruction set.
pub struct Interpreter {
    stack: Vec<u64>,
    memory: Vec<u64>,
    meter: GasMeter,
    state: VmState,
    attested: bool,
    max_call_depth: u32,
    max_steps: u64,
}

impl Interpreter {
    /// Create an interpreter with a gas limit and a maximum call depth.
    #[must_use]
    pub fn new(gas_limit: GasAmount, max_call_depth: u32) -> Self {
        Self {
            stack: Vec::new(),
            memory: Vec::new(),
            meter: GasMeter::system(gas_limit),
            state: VmState {
                gas_used: GasAmount::ZERO,
                call_depth: 0,
                tee_active: false,
            },
            attested: false,
            max_call_depth,
            // Backstop against jump loops that never exhaust gas in tests.
            max_steps: 1_000_000,
        }
    }

    fn pop(&mut self) -> VmResult<u64> {
        self.stack.pop().ok_or(VmError::ContractAbort {
            code: 1,
            message: "stack underflow".into(),
        })
    }

    fn to_index(value: u64, program_len: usize) -> VmResult<usize> {
        let idx = usize::try_from(value).map_err(|_| VmError::ContractAbort {
            code: 4,
            message: "jump target too large".into(),
        })?;
        if idx >= program_len {
            return Err(VmError::ContractAbort {
                code: 4,
                message: "jump out of bounds".into(),
            });
        }
        Ok(idx)
    }

    /// Execute `program` to completion.
    ///
    /// # Errors
    /// Returns:
    /// - [`VmError::OutOfGas`] when the gas limit is exhausted,
    /// - [`VmError::ContractAbort`] for stack underflow, division by zero, an
    ///   out-of-bounds jump, or exceeding the step bound,
    /// - [`VmError::StackOverflow`] when call depth exceeds the configured max,
    /// - [`VmError::TeeUnavailable`] for `TeeAttest` outside a TEE context.
    // A bytecode dispatch loop is inherently one large match; splitting it would
    // reduce clarity without benefit.
    #[allow(clippy::too_many_lines)]
    pub fn execute(&mut self, program: &[Instruction]) -> VmResult<ExecutionOutcome> {
        let mut pc = 0usize;
        let mut steps = 0u64;

        while pc < program.len() {
            steps += 1;
            if steps > self.max_steps {
                return Err(VmError::ContractAbort {
                    code: 2,
                    message: "step limit exceeded".into(),
                });
            }

            let instr = program[pc];
            // Real gas metering: charge before executing; halts on OutOfGas.
            self.meter.charge(GasAmount(instr.base_gas()))?;

            // Pop and Free share an implementation today (both discard the top
            // of stack) but are kept as distinct arms: Free releases an
            // allocation handle and will diverge once real heap tracking lands.
            #[allow(clippy::match_same_arms)]
            match instr {
                Instruction::Nop => {}
                Instruction::Pop => {
                    self.pop()?;
                }
                Instruction::Ld(v) => self.stack.push(v),
                Instruction::St => {
                    let v = self.pop()?;
                    self.memory.push(v);
                }
                Instruction::Add => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.stack.push(a.wrapping_add(b));
                }
                Instruction::Sub => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.stack.push(a.wrapping_sub(b));
                }
                Instruction::Mul => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.stack.push(a.wrapping_mul(b));
                }
                Instruction::Div => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    if b == 0 {
                        return Err(VmError::ContractAbort {
                            code: 3,
                            message: "division by zero".into(),
                        });
                    }
                    self.stack.push(a / b);
                }
                // Jmp: pop target address from the stack and jump there.
                Instruction::Jmp => {
                    let target = Self::to_index(self.pop()?, program.len())?;
                    pc = target;
                    continue;
                }
                // Jz: pop condition, then target; jump if condition == 0.
                Instruction::Jz => {
                    let cond = self.pop()?;
                    let target = self.pop()?;
                    if cond == 0 {
                        pc = Self::to_index(target, program.len())?;
                        continue;
                    }
                }
                Instruction::Call => {
                    self.state.call_depth += 1;
                    if self.state.call_depth > self.max_call_depth {
                        return Err(VmError::StackOverflow {
                            depth: self.state.call_depth,
                        });
                    }
                }
                Instruction::Ret => {
                    self.state.call_depth = self.state.call_depth.saturating_sub(1);
                }
                // Alloc: grow linear memory by one slot; push its handle (index).
                Instruction::Alloc => {
                    let handle = u64::try_from(self.memory.len()).unwrap_or(u64::MAX);
                    self.memory.push(0);
                    self.stack.push(handle);
                }
                Instruction::Free => {
                    self.pop()?;
                }
                Instruction::TeeEnter => self.state.tee_active = true,
                Instruction::TeeExit => self.state.tee_active = false,
                Instruction::TeeAttest => {
                    if !self.state.tee_active {
                        return Err(VmError::TeeUnavailable {
                            reason: "TeeAttest outside a TEE context".into(),
                        });
                    }
                    self.attested = true;
                }
            }

            pc += 1;
        }

        self.state.gas_used = self.meter.consumed();
        Ok(ExecutionOutcome {
            return_value: self.stack.last().copied().unwrap_or(0),
            gas_used: self.meter.consumed(),
            tee_attested: self.attested,
            final_state: self.state.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instructions::Instruction::{
        Add, Alloc, Call, Div, Free, Jmp, Jz, Ld, Mul, Nop, Pop, Ret, St, Sub, TeeAttest, TeeEnter,
        TeeExit,
    };

    fn run(program: &[Instruction], gas: u64) -> VmResult<ExecutionOutcome> {
        Interpreter::new(GasAmount(gas), 16).execute(program)
    }

    #[test]
    fn arithmetic_add_mul() {
        // (2 + 3) * 4 = 20
        let out = run(&[Ld(2), Ld(3), Add, Ld(4), Mul], 1000).unwrap();
        assert_eq!(out.return_value, 20);
    }

    #[test]
    fn subtraction_order_is_tos1_minus_tos() {
        // 10 - 4 = 6
        let out = run(&[Ld(10), Ld(4), Sub], 1000).unwrap();
        assert_eq!(out.return_value, 6);
    }

    #[test]
    fn division_by_zero_aborts() {
        let err = run(&[Ld(10), Ld(0), Div], 1000).unwrap_err();
        assert!(matches!(err, VmError::ContractAbort { code: 3, .. }));
    }

    #[test]
    fn division_works() {
        let out = run(&[Ld(20), Ld(4), Div], 1000).unwrap();
        assert_eq!(out.return_value, 5);
    }

    #[test]
    fn stack_underflow_aborts() {
        let err = run(&[Add], 1000).unwrap_err();
        assert!(matches!(err, VmError::ContractAbort { code: 1, .. }));
    }

    #[test]
    fn out_of_gas_halts() {
        // Alloc costs 300; a tiny limit cannot afford it.
        let err = run(&[Alloc], 10).unwrap_err();
        assert!(matches!(err, VmError::OutOfGas { .. }));
    }

    #[test]
    fn gas_is_metered_deterministically() {
        // Ld(1) + Ld(1) + Add = 1 + 1 + 3 = 5 gas.
        let out = run(&[Ld(1), Ld(1), Add], 1000).unwrap();
        assert_eq!(out.gas_used, GasAmount(5));
    }

    #[test]
    fn nop_and_pop_behave() {
        let out = run(&[Ld(7), Nop, Ld(9), Pop], 1000).unwrap();
        assert_eq!(out.return_value, 7);
    }

    #[test]
    fn unconditional_jump_skips_code() {
        // Ld(target=4), Jmp -> pc=4 (Ld 99), skipping the Ld(1) at index 2..3.
        // layout: 0:Ld(4) 1:Jmp 2:Ld(1) 3:Nop 4:Ld(99)
        let out = run(&[Ld(4), Jmp, Ld(1), Nop, Ld(99)], 1000).unwrap();
        assert_eq!(out.return_value, 99);
    }

    #[test]
    fn conditional_jump_taken_when_zero() {
        // target=5, cond=0 -> jump to index 5 (Ld 42)
        // 0:Ld(5) 1:Ld(0) 2:Jz 3:Ld(1) 4:Nop 5:Ld(42)
        let out = run(&[Ld(5), Ld(0), Jz, Ld(1), Nop, Ld(42)], 1000).unwrap();
        assert_eq!(out.return_value, 42);
    }

    #[test]
    fn conditional_jump_not_taken_when_nonzero() {
        // cond=1 -> fall through, execute Ld(7)
        let out = run(&[Ld(5), Ld(1), Jz, Ld(7)], 1000).unwrap();
        assert_eq!(out.return_value, 7);
    }

    #[test]
    fn jump_out_of_bounds_aborts() {
        let err = run(&[Ld(99), Jmp], 1000).unwrap_err();
        assert!(matches!(err, VmError::ContractAbort { code: 4, .. }));
    }

    #[test]
    fn call_depth_overflow() {
        // 17 consecutive Calls exceed max_call_depth = 16.
        let program: Vec<Instruction> = std::iter::repeat(Call).take(17).collect();
        let err = Interpreter::new(GasAmount(100_000), 16)
            .execute(&program)
            .unwrap_err();
        assert!(matches!(err, VmError::StackOverflow { depth } if depth == 17));
    }

    #[test]
    fn call_ret_balances_depth() {
        let out = run(&[Call, Call, Ret, Ret], 1000).unwrap();
        assert_eq!(out.final_state.call_depth, 0);
    }

    #[test]
    fn alloc_pushes_handle_and_free_pops() {
        let out = run(&[Alloc, Free], 1000).unwrap();
        // handle 0 was pushed then freed; stack empty -> return 0
        assert_eq!(out.return_value, 0);
    }

    #[test]
    fn store_moves_tos_to_memory() {
        let out = run(&[Ld(5), St], 1000).unwrap();
        // St pops the value; stack empty afterwards.
        assert_eq!(out.return_value, 0);
    }

    #[test]
    fn tee_attest_requires_active_context() {
        let err = run(&[TeeAttest], 100_000).unwrap_err();
        assert!(matches!(err, VmError::TeeUnavailable { .. }));
    }

    #[test]
    fn tee_enter_attest_exit_flow() {
        let out = run(&[TeeEnter, TeeAttest, TeeExit], 100_000).unwrap();
        assert!(out.tee_attested);
        assert!(!out.final_state.tee_active);
    }
}
