//! Gas metering, scheduling, and cost calculation.
//!
//! `GasPrice` is the user-specified price per unit of gas (nAVR/gas).
//! `GasAmount` is the quantity of gas consumed. The transaction fee is:
//! `fee = gas_used * gas_price`.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Amount, GasAmount, GasPrice};

/// Per-instruction gas costs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstructionGas {
    /// Opcode name (e.g. `"Add"`, `"Call"`).
    pub opcode: String,
    /// Fixed base cost in gas units.
    pub base_cost: u64,
    /// Additional cost per byte of data argument.
    pub per_byte_cost: u64,
}

/// Memory-access gas costs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryGas {
    /// Gas cost per 32-byte word allocated.
    pub per_word_cost: u64,
}

/// TEE execution overhead premium.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeExecutionPremium {
    /// Multiplier applied to base gas cost, in percent (130 = 1.3×).
    pub multiplier_pct: u32,
}

impl TeeExecutionPremium {
    /// Apply the premium multiplier to a base gas amount.
    pub fn apply(&self, base: GasAmount) -> GasAmount {
        GasAmount::from_u64(base.as_u64().saturating_mul(u64::from(self.multiplier_pct)) / 100)
    }
}

/// Complete gas cost schedule for the current protocol version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasSchedule {
    /// Per-opcode costs.
    pub instructions: Vec<InstructionGas>,
    /// Memory allocation cost.
    pub memory: MemoryGas,
    /// TEE execution overhead.
    pub tee_premium: TeeExecutionPremium,
}

impl Default for GasSchedule {
    fn default() -> Self {
        Self {
            instructions: Vec::new(),
            memory: MemoryGas { per_word_cost: 3 },
            tee_premium: TeeExecutionPremium { multiplier_pct: 130 },
        }
    }
}

/// Tracks gas consumption during execution and enforces the limit.
pub struct GasMeter {
    limit: GasAmount,
    consumed: GasAmount,
    price: GasPrice,
}

impl GasMeter {
    /// Create a gas meter with the given limit and price per unit.
    ///
    /// `price` is the nAVR per gas unit the sender is paying.
    pub fn new(limit: GasAmount, price: GasPrice) -> Self {
        Self { limit, consumed: GasAmount::ZERO, price }
    }

    /// Create a gas meter with zero price (for internal/system operations).
    pub fn system(limit: GasAmount) -> Self {
        Self::new(limit, GasPrice(0))
    }

    /// Deduct `amount` from the gas budget.
    ///
    /// Returns `OutOfGas` if the budget is exhausted.
    ///
    /// # Errors
    /// Returns `VmError::OutOfGas` if the accumulated gas exceeds the configured limit.
    pub fn charge(&mut self, amount: GasAmount) -> crate::VmResult<()> {
        self.consumed = self.consumed.checked_add(amount)
            .ok_or(crate::VmError::OutOfGas {
                used: self.limit.as_u64(),
                limit: self.limit.as_u64(),
            })?;
        if self.consumed > self.limit {
            return Err(crate::VmError::OutOfGas {
                used: self.consumed.as_u64(),
                limit: self.limit.as_u64(),
            });
        }
        Ok(())
    }

    /// Remaining gas budget.
    pub fn remaining(&self) -> GasAmount {
        GasAmount::from_u64(self.limit.as_u64().saturating_sub(self.consumed.as_u64()))
    }

    /// Gas consumed so far.
    pub fn consumed(&self) -> GasAmount { self.consumed }

    /// The price per gas unit set for this meter.
    pub fn price(&self) -> GasPrice { self.price }

    /// Total fee in nAVR for the gas consumed at the configured price.
    pub fn fee(&self) -> Amount {
        Amount::from_nano(u128::from(self.consumed.as_u64()) * u128::from(self.price.0))
    }

    /// Maximum possible fee (if all gas were consumed).
    pub fn max_fee(&self) -> Amount {
        Amount::from_nano(u128::from(self.limit.as_u64()) * u128::from(self.price.0))
    }
}

/// Estimates gas costs before execution.
pub struct GasEstimator {
    schedule: GasSchedule,
}

impl GasEstimator {
    /// Create an estimator with the given schedule.
    pub fn new(schedule: GasSchedule) -> Self { Self { schedule } }

    /// Create an estimator with default protocol costs.
    pub fn default_schedule() -> Self { Self::new(GasSchedule::default()) }

    /// Estimate the gas cost of a plain ETH-style call with `data_len` bytes.
    pub fn estimate_call(data_len: usize) -> GasAmount {
        GasAmount::from_u64(21_000 + data_len as u64 * 16)
    }

    /// Estimate total fee given an estimated gas amount and a price.
    pub fn estimate_fee(gas: GasAmount, price: GasPrice) -> Amount {
        Amount::from_nano(u128::from(gas.as_u64()) * u128::from(price.0))
    }

    /// Estimate gas for a TEE-executed call (applies the TEE premium).
    pub fn estimate_tee_call(&self, data_len: usize) -> GasAmount {
        let base = Self::estimate_call(data_len);
        self.schedule.tee_premium.apply(base)
    }

    /// Estimate memory allocation cost for `words` 32-byte words.
    pub fn estimate_memory(&self, words: usize) -> GasAmount {
        GasAmount::from_u64(words as u64 * self.schedule.memory.per_word_cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_meter_charges_correctly() {
        let mut meter = GasMeter::system(GasAmount::from_u64(1_000_000));
        meter.charge(GasAmount::from_u64(21_000)).unwrap();
        assert_eq!(meter.consumed().as_u64(), 21_000);
        assert_eq!(meter.remaining().as_u64(), 979_000);
    }

    #[test]
    fn gas_meter_rejects_over_limit() {
        let mut meter = GasMeter::system(GasAmount::from_u64(100));
        assert!(meter.charge(GasAmount::from_u64(101)).is_err());
    }

    #[test]
    fn gas_meter_fee_calculation() {
        let meter = GasMeter::new(GasAmount::from_u64(21_000), GasPrice(1_000_000_000));
        // max_fee = 21_000 * 1e9 nAVR = 21e12 nAVR = 21,000 AVR
        assert_eq!(meter.max_fee().as_nano(), 21_000 * 1_000_000_000);
    }

    #[test]
    fn tee_premium_multiplier() {
        let premium = TeeExecutionPremium { multiplier_pct: 130 };
        let base = GasAmount::from_u64(1_000);
        assert_eq!(premium.apply(base).as_u64(), 1_300);
    }

    #[test]
    fn estimator_tee_call_greater_than_base() {
        let estimator = GasEstimator::default_schedule();
        let base = GasEstimator::estimate_call(64);
        let tee = estimator.estimate_tee_call(64);
        assert!(tee.as_u64() > base.as_u64());
    }

    #[test]
    fn estimator_fee_is_gas_times_price() {
        let gas = GasAmount::from_u64(21_000);
        let price = GasPrice(100);
        let fee = GasEstimator::estimate_fee(gas, price);
        assert_eq!(fee.as_nano(), 2_100_000);
    }
}
