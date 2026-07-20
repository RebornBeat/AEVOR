//! Data availability via **real Reed-Solomon erasure coding** over GF(256).
//!
//! `data` is split into `data_shards` (K) systematic shards plus
//! `parity_shards` (M) computed shards. **Any K of the K+M shards** are
//! sufficient to reconstruct the original — so up to M shards can be lost.
//!
//! Pure Rust, no external dependency: GF(256) arithmetic (primitive polynomial
//! `0x11D`), a systematic coding matrix derived from a Vandermonde matrix, and
//! Gauss-Jordan inversion over the field for reconstruction.

use serde::{Deserialize, Serialize};

/// Erasure coding parameters: `data_shards` originals + `parity_shards` parity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErasureConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
}
impl Default for ErasureConfig {
    fn default() -> Self {
        Self { data_shards: 8, parity_shards: 4 }
    }
}

// ── GF(256) arithmetic ─────────────────────────────────────────────────────

/// Finite field GF(2^8) with primitive polynomial `x^8+x^4+x^3+x^2+1` (`0x11D`)
/// and generator `0x02`. Multiplication/division via exp/log tables.
struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    #[allow(clippy::needless_range_loop, clippy::cast_possible_truncation)] // field tables: i,x provably < 256
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u8 = 1;
        for i in 0..255usize {
            exp[i] = x;
            log[x as usize] = i as u8;
            // x *= generator 0x02 in GF(256): left shift, reduce by 0x1D on carry.
            let carry = x & 0x80;
            x <<= 1;
            if carry != 0 {
                x ^= 0x1D;
            }
        }
        for i in 255..512usize {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    fn div(&self, a: u8, b: u8) -> u8 {
        debug_assert!(b != 0, "division by zero in GF(256)");
        if a == 0 {
            0
        } else {
            self.exp[(self.log[a as usize] as usize + 255 - self.log[b as usize] as usize) % 255]
        }
    }

    fn pow(&self, base: u8, exp: usize) -> u8 {
        let mut result = 1u8;
        for _ in 0..exp {
            result = self.mul(result, base);
        }
        result
    }
}

// ── Matrix operations over GF(256) ─────────────────────────────────────────

type Matrix = Vec<Vec<u8>>;

#[allow(clippy::needless_range_loop)] // explicit indices are clearer for matrix math
fn matmul(gf: &Gf256, a: &Matrix, b: &Matrix) -> Matrix {
    let rows = a.len();
    let cols = b[0].len();
    let inner = b.len();
    let mut out = vec![vec![0u8; cols]; rows];
    for r in 0..rows {
        for c in 0..cols {
            let mut acc = 0u8;
            for k in 0..inner {
                acc ^= gf.mul(a[r][k], b[k][c]);
            }
            out[r][c] = acc;
        }
    }
    out
}

/// Invert a square matrix over GF(256) via Gauss-Jordan elimination.
/// Returns `None` if the matrix is singular.
#[allow(clippy::needless_range_loop)]
fn invert(gf: &Gf256, matrix: &Matrix) -> Option<Matrix> {
    let n = matrix.len();
    // Augment [matrix | I].
    let mut m: Matrix = matrix.clone();
    let mut inv: Matrix = (0..n)
        .map(|i| (0..n).map(|j| u8::from(i == j)).collect())
        .collect();

    for col in 0..n {
        // Find a pivot row with a non-zero entry in this column.
        if m[col][col] == 0 {
            let mut swap = None;
            for r in (col + 1)..n {
                if m[r][col] != 0 {
                    swap = Some(r);
                    break;
                }
            }
            let r = swap?;
            m.swap(col, r);
            inv.swap(col, r);
        }
        // Normalize the pivot row so the pivot becomes 1.
        let pivot = m[col][col];
        for j in 0..n {
            m[col][j] = gf.div(m[col][j], pivot);
            inv[col][j] = gf.div(inv[col][j], pivot);
        }
        // Eliminate this column from all other rows.
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = m[r][col];
            if factor != 0 {
                for j in 0..n {
                    m[r][j] ^= gf.mul(factor, m[col][j]);
                    inv[r][j] ^= gf.mul(factor, inv[col][j]);
                }
            }
        }
    }
    Some(inv)
}

/// Build a systematic `(K+M) x K` coding matrix: the top `K x K` block is the
/// identity (data shards pass through), and the bottom `M x K` block generates
/// parity. Derived from a Vandermonde matrix so every `K x K` submatrix is
/// invertible (for `K+M <= 256`), guaranteeing any K shards can reconstruct.
#[allow(clippy::cast_possible_truncation)] // r < total <= 256 for valid configs
fn build_coding_matrix(gf: &Gf256, k: usize, m: usize) -> Matrix {
    let total = k + m;
    let vander: Matrix = (0..total)
        .map(|r| (0..k).map(|c| gf.pow(r as u8, c)).collect())
        .collect();
    let top: Matrix = vander[..k].to_vec();
    let top_inv = invert(gf, &top).expect("Vandermonde top block is invertible");
    matmul(gf, &vander, &top_inv)
}

// ── Erasure code ───────────────────────────────────────────────────────────

/// The result of encoding: the K+M shards plus the metadata needed to
/// reconstruct (original length; every shard has the same size).
#[derive(Clone, Debug)]
pub struct EncodedData {
    /// K data shards followed by M parity shards (K+M total).
    pub shards: Vec<Vec<u8>>,
    /// Length of the original (pre-padding) data.
    pub original_len: usize,
    /// Size in bytes of each shard.
    pub shard_size: usize,
}

/// A real Reed-Solomon erasure coder.
pub struct ErasureCode {
    config: ErasureConfig,
    gf: Gf256,
    coding: Matrix,
}

impl ErasureCode {
    /// Build an erasure coder for the given configuration.
    #[must_use]
    pub fn new(config: ErasureConfig) -> Self {
        let gf = Gf256::new();
        let coding = build_coding_matrix(&gf, config.data_shards, config.parity_shards);
        Self { config, gf, coding }
    }

    /// Total number of shards produced (`data_shards + parity_shards`).
    #[must_use]
    pub fn total_shards(&self) -> usize {
        self.config.data_shards + self.config.parity_shards
    }

    /// Encode `data` into `data_shards + parity_shards` shards.
    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn encode(&self, data: &[u8]) -> EncodedData {
        let k = self.config.data_shards;
        let total = self.total_shards();
        let original_len = data.len();
        let shard_size = original_len.div_ceil(k).max(1);

        // Pad and split into K equal data shards.
        let mut padded = data.to_vec();
        padded.resize(shard_size * k, 0);

        // shards = coding · data (each output byte independently).
        let mut shards = vec![vec![0u8; shard_size]; total];
        for byte in 0..shard_size {
            for r in 0..total {
                let mut acc = 0u8;
                for c in 0..k {
                    acc ^= self.gf.mul(self.coding[r][c], padded[c * shard_size + byte]);
                }
                shards[r][byte] = acc;
            }
        }

        EncodedData { shards, original_len, shard_size }
    }

    /// Reconstruct the original data from a position-indexed set of shards.
    ///
    /// `received[i]` is `Some(shard)` if shard `i` survived, or `None` if lost.
    /// Returns `None` if fewer than `data_shards` survived.
    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn reconstruct(&self, received: &[Option<Vec<u8>>], original_len: usize) -> Option<Vec<u8>> {
        let k = self.config.data_shards;
        let total = self.total_shards();

        let present: Vec<usize> = (0..total)
            .filter(|&i| received.get(i).is_some_and(Option::is_some))
            .collect();
        if present.len() < k {
            return None;
        }
        let use_idx = &present[..k];
        let shard_size = received[use_idx[0]].as_ref()?.len();

        // Sub-matrix of the coding rows we actually have; invert it.
        let sub: Matrix = use_idx.iter().map(|&r| self.coding[r].clone()).collect();
        let inv = invert(&self.gf, &sub)?;

        // data = inv · received_shards.
        let mut data = vec![0u8; shard_size * k];
        for byte in 0..shard_size {
            for out_row in 0..k {
                let mut acc = 0u8;
                for c in 0..k {
                    let shard = received[use_idx[c]].as_ref()?;
                    acc ^= self.gf.mul(inv[out_row][c], shard[byte]);
                }
                data[out_row * shard_size + byte] = acc;
            }
        }
        data.truncate(original_len);
        Some(data)
    }
}

/// A sample proving a validator holds a particular shard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilitySample {
    pub shard_index: usize,
    pub data_hash: aevor_core::primitives::Hash256,
}

/// Convenience entry point for reconstruction from a config.
pub struct DataReconstruction;
impl DataReconstruction {
    /// Reconstruct original data of length `original_len` from position-indexed
    /// shards, using the given erasure configuration.
    #[must_use]
    pub fn reconstruct(
        config: ErasureConfig,
        received: &[Option<Vec<u8>>],
        original_len: usize,
    ) -> Option<Vec<u8>> {
        ErasureCode::new(config).reconstruct(received, original_len)
    }
}

/// The data-availability layer: erasure-code data for distribution across
/// validators, and reconstruct it from any sufficient subset of shards.
pub struct DataAvailability {
    code: ErasureCode,
}
impl DataAvailability {
    /// Create a data availability layer with the given erasure coding configuration.
    #[must_use]
    pub fn new(config: ErasureConfig) -> Self {
        Self { code: ErasureCode::new(config) }
    }

    /// The underlying erasure code.
    #[must_use]
    pub fn erasure_code(&self) -> &ErasureCode {
        &self.code
    }

    /// Encode `data` into shards for distributed availability. Any
    /// `data_shards` of the returned shards suffice to reconstruct.
    #[must_use]
    pub fn encode(&self, data: &[u8]) -> EncodedData {
        self.code.encode(data)
    }

    /// Reconstruct original data from a sufficient subset of shards.
    #[must_use]
    pub fn reconstruct(&self, received: &[Option<Vec<u8>>], original_len: usize) -> Option<Vec<u8>> {
        self.code.reconstruct(received, original_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_produces_data_plus_parity_shards() {
        let code = ErasureCode::new(ErasureConfig { data_shards: 4, parity_shards: 2 });
        let encoded = code.encode(&[0u8; 40]);
        assert_eq!(encoded.shards.len(), 6);
        assert!(encoded.shards.iter().all(|s| s.len() == encoded.shard_size));
    }

    #[test]
    fn systematic_data_shards_match_original() {
        // The first K shards are the (padded) original data itself.
        let code = ErasureCode::new(ErasureConfig { data_shards: 3, parity_shards: 2 });
        let data = vec![1u8, 2, 3, 4, 5, 6];
        let encoded = code.encode(&data);
        let mut flat: Vec<u8> = Vec::new();
        for s in &encoded.shards[..3] {
            flat.extend_from_slice(s);
        }
        flat.truncate(data.len());
        assert_eq!(flat, data);
    }

    #[test]
    fn roundtrip_with_all_shards() {
        let code = ErasureCode::new(ErasureConfig { data_shards: 4, parity_shards: 2 });
        let data: Vec<u8> = (0..37).collect();
        let encoded = code.encode(&data);
        let received: Vec<Option<Vec<u8>>> = encoded.shards.iter().cloned().map(Some).collect();
        assert_eq!(code.reconstruct(&received, encoded.original_len).unwrap(), data);
    }

    #[test]
    fn recovers_from_losing_up_to_parity_shards() {
        // 8 data + 4 parity: losing ANY 4 shards must still reconstruct.
        let code = ErasureCode::new(ErasureConfig { data_shards: 8, parity_shards: 4 });
        let data: Vec<u8> = (0..100u16).map(|x| (x % 256) as u8).collect();
        let encoded = code.encode(&data);

        // Drop shards 0,1,2,3 (four data shards) — the hardest case.
        let mut received: Vec<Option<Vec<u8>>> = encoded.shards.iter().cloned().map(Some).collect();
        for i in 0..4 {
            received[i] = None;
        }
        assert_eq!(code.reconstruct(&received, encoded.original_len).unwrap(), data);

        // Drop a mix of data and parity shards (2,5,9,11).
        let mut received2: Vec<Option<Vec<u8>>> = encoded.shards.iter().cloned().map(Some).collect();
        for i in [2usize, 5, 9, 11] {
            received2[i] = None;
        }
        assert_eq!(code.reconstruct(&received2, encoded.original_len).unwrap(), data);
    }

    #[test]
    fn fails_when_too_many_shards_lost() {
        // Losing more than `parity_shards` (5 of 12) → unrecoverable.
        let code = ErasureCode::new(ErasureConfig { data_shards: 8, parity_shards: 4 });
        let encoded = code.encode(&(0..50u8).collect::<Vec<_>>());
        let mut received: Vec<Option<Vec<u8>>> = encoded.shards.iter().cloned().map(Some).collect();
        for i in 0..5 {
            received[i] = None;
        }
        assert!(code.reconstruct(&received, encoded.original_len).is_none());
    }

    #[test]
    fn data_availability_roundtrip_via_wrapper() {
        let da = DataAvailability::new(ErasureConfig { data_shards: 2, parity_shards: 2 });
        let original = vec![10u8, 20, 30, 40, 50];
        let encoded = da.encode(&original);
        // Lose one shard, reconstruct via the wrapper.
        let mut received: Vec<Option<Vec<u8>>> = encoded.shards.iter().cloned().map(Some).collect();
        received[1] = None;
        assert_eq!(da.reconstruct(&received, encoded.original_len).unwrap(), original);
    }

    #[test]
    fn gf256_field_axioms() {
        let gf = Gf256::new();
        // a / a == 1 and a * 1 == a for all non-zero a.
        for a in 1u8..=255 {
            assert_eq!(gf.div(a, a), 1);
            assert_eq!(gf.mul(a, 1), a);
        }
        // Multiplication is commutative on a sample.
        assert_eq!(gf.mul(0x53, 0xCA), gf.mul(0xCA, 0x53));
    }
}
