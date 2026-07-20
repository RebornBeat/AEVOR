//! Real Pedersen commitments over Ristretto (curve25519-dalek).
//!
//! This provides a real elliptic-curve commitment for the general
//! commitment-scheme wrapper in [`crate::commitment`] (committing arbitrary
//! bytes), replacing what used to be a second, hash-based implementation.
//!
//! Confidential **amounts** — which additionally need a *range proof* proving
//! `0 <= amount < 2^n` — live in `aevor_zk::bulletproofs`, where the commitment
//! uses the Bulletproofs Pedersen generators so the commitment and its range
//! proof are coherent. Keeping the amount commitment there (and not here) avoids
//! a second amount-commitment with mismatched generators.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// The second, independent generator `H`.
///
/// Derived by hashing a domain string onto the curve so that its discrete log
/// with respect to `G` is unknown — without that, a commitment could be opened
/// two ways and the scheme would not be binding.
fn generator_h() -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"aevor-pedersen-generator-H-v1");
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// The core commitment operation on scalars: `value*G + blinding*H`.
fn commit_points(value: Scalar, blinding: Scalar) -> RistrettoPoint {
    value * RISTRETTO_BASEPOINT_POINT + blinding * generator_h()
}

/// Derive a blinding scalar deterministically from a seed (reproducible).
#[must_use]
pub fn blinding_from_seed(seed: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"aevor-pedersen-blinding-v1:");
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Real EC Pedersen commitment to arbitrary bytes: the value is hashed to a
/// scalar and committed as `value_scalar*G + blinding*H`. Used by the general
/// commitment-scheme wrapper in [`crate::commitment`]; confidential **amounts**
/// use `aevor_zk::bulletproofs` instead (which pairs the commitment with a range
/// proof under matching generators).
#[must_use]
pub fn commit_bytes(value: &[u8], blinding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"aevor-pedersen-value-scalar:");
    hasher.update(value);
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    let value_scalar = Scalar::from_bytes_mod_order_wide(&wide);
    let blinding_scalar = Scalar::from_bytes_mod_order(*blinding);
    commit_points(value_scalar, blinding_scalar).compress().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_bytes_is_deterministic() {
        let b = [3u8; 32];
        assert_eq!(commit_bytes(b"value", &b), commit_bytes(b"value", &b));
    }

    #[test]
    fn commit_bytes_different_values_differ() {
        let b = [3u8; 32];
        assert_ne!(commit_bytes(b"value-a", &b), commit_bytes(b"value-b", &b));
    }

    #[test]
    fn commit_bytes_different_blinding_hides_value() {
        // Same value, different blinding -> different commitment (hiding).
        assert_ne!(commit_bytes(b"same", &[1u8; 32]), commit_bytes(b"same", &[2u8; 32]));
    }

    #[test]
    fn blinding_from_seed_is_deterministic() {
        assert_eq!(blinding_from_seed(b"seed"), blinding_from_seed(b"seed"));
        assert_ne!(blinding_from_seed(b"a"), blinding_from_seed(b"b"));
    }
}
