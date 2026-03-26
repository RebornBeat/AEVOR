//! BLS12-381 signature aggregation for consensus finality proofs.
//!
//! Aggregation reduces n validator signatures to a single constant-size
//! signature enabling O(1) aggregate verification regardless of n.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use crate::signatures::{BlsPublicKey, BlsSignature};

/// Aggregated BLS signature from multiple validators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsAggregateSignature {
    /// The aggregated signature bytes (single BLS12-381 point).
    pub aggregate: Vec<u8>,
    /// Number of individual signatures combined in this aggregate.
    pub signer_count: usize,
    /// Bitmap indicating which validators in the known set signed.
    pub participant_bitmap: ParticipantBitmap,
    /// Hash of the message all signers signed.
    pub message_hash: Hash256,
}

impl BlsAggregateSignature {
    /// Verify the aggregate signature against the participant public keys.
    pub fn verify(
        &self,
        message: &[u8],
        public_keys: &[(usize, BlsPublicKey)],
    ) -> crate::CryptoResult<bool> {
        use blst::min_sig::{AggregatePublicKey, Signature};

        if self.aggregate.is_empty() {
            return Ok(false);
        }

        let Ok(sig) = Signature::uncompress(&self.aggregate) else {
            return Ok(false);
        };

        let mut pk_refs = Vec::new();
        for (idx, pk) in public_keys {
            if self.participant_bitmap.is_set(*idx) {
                if let Ok(bls_pk) = blst::min_sig::PublicKey::uncompress(&pk.0) {
                    pk_refs.push(bls_pk);
                }
            }
        }

        if pk_refs.is_empty() {
            return Ok(false);
        }

        let pk_ref_slice: Vec<&blst::min_sig::PublicKey> = pk_refs.iter().collect();
        let agg_pk = AggregatePublicKey::aggregate(&pk_ref_slice, true)
            .map_err(|e| crate::CryptoError::ProofVerificationFailed {
                system: format!("BLS aggregate key: {:?}", e),
            })?
            .to_public_key();

        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        Ok(matches!(
            sig.verify(true, message, dst, &[], &agg_pk, true),
            blst::BLST_ERROR::BLST_SUCCESS
        ))
    }

    /// Number of signers in this aggregate.
    pub fn signer_count(&self) -> usize {
        self.signer_count
    }
}

/// Accumulates BLS signatures from individual validators before aggregating.
pub struct BlsAggregator {
    signatures: Vec<Vec<u8>>,
    participant_indices: Vec<usize>,
    message_hash: Hash256,
    total_validators: usize,
}

impl BlsAggregator {
    /// Create a new aggregator for signatures over `message_hash`.
    ///
    /// `total_validators` is the size of the full validator set (for the bitmap).
    pub fn new(message_hash: Hash256, total_validators: usize) -> Self {
        Self {
            signatures: Vec::new(),
            participant_indices: Vec::new(),
            message_hash,
            total_validators,
        }
    }

    /// Add a validator's BLS signature. Duplicate indices are silently ignored.
    pub fn add_signature(
        &mut self,
        validator_index: usize,
        signature: &BlsSignature,
    ) -> crate::CryptoResult<()> {
        if self.participant_indices.contains(&validator_index) {
            return Ok(());
        }
        self.signatures.push(signature.0.clone());
        self.participant_indices.push(validator_index);
        Ok(())
    }

    /// Aggregate all collected signatures into a single `BlsAggregateSignature`.
    pub fn aggregate(self) -> crate::CryptoResult<BlsAggregateSignature> {
        use blst::min_sig::{AggregateSignature as BlstAgg, Signature};

        if self.signatures.is_empty() {
            return Err(crate::CryptoError::CommitmentError(
                "cannot aggregate zero signatures".into(),
            ));
        }

        let sigs: Vec<Signature> = self.signatures.iter()
            .filter_map(|s| Signature::uncompress(s).ok())
            .collect();

        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg = BlstAgg::aggregate(&sig_refs, true).map_err(|e| {
            crate::CryptoError::ProofVerificationFailed {
                system: format!("BLS aggregation: {:?}", e),
            }
        })?;

        let mut bitmap = ParticipantBitmap::new(self.total_validators);
        for idx in &self.participant_indices {
            bitmap.set(*idx);
        }

        Ok(BlsAggregateSignature {
            aggregate: agg.to_signature().compress().to_vec(),
            signer_count: self.participant_indices.len(),
            participant_bitmap: bitmap,
            message_hash: self.message_hash,
        })
    }

    /// Number of signatures collected so far.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

/// Batch verifier for multiple independent BLS signatures in a single pass.
pub struct BlsBatchVerifier {
    items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

impl BlsBatchVerifier {
    /// Create a new batch verifier.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Add a (message, public_key, signature) triple to the batch.
    pub fn add(
        &mut self,
        message: Vec<u8>,
        public_key: &BlsPublicKey,
        signature: &BlsSignature,
    ) {
        self.items.push((message, public_key.0.clone(), signature.0.clone()));
    }

    /// Verify all signatures in the batch. Returns `false` if any fail.
    pub fn verify_all(self) -> crate::CryptoResult<bool> {
        for (msg, pk_bytes, sig_bytes) in &self.items {
            use blst::min_sig::{PublicKey, Signature};
            let Ok(pk) = PublicKey::uncompress(pk_bytes) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::uncompress(sig_bytes) else {
                return Ok(false);
            };
            let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
            if !matches!(
                sig.verify(true, msg, dst, &[], &pk, true),
                blst::BLST_ERROR::BLST_SUCCESS
            ) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Number of items in this batch.
    pub fn item_count(&self) -> usize {
        self.items.len()
    }
}

impl Default for BlsBatchVerifier {
    fn default() -> Self { Self::new() }
}

/// Compact bitmap tracking which validators in a set have signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantBitmap {
    /// The raw bit storage (1 bit per validator, packed into bytes).
    pub bits: Vec<u8>,
    /// Total number of validators this bitmap covers.
    pub total: usize,
}

impl ParticipantBitmap {
    /// Create a new empty bitmap for `total` validators.
    pub fn new(total: usize) -> Self {
        let bytes = (total + 7) / 8;
        Self { bits: vec![0u8; bytes], total }
    }

    /// Mark validator at `index` as participating.
    pub fn set(&mut self, index: usize) {
        if index < self.total {
            self.bits[index / 8] |= 1 << (index % 8);
        }
    }

    /// Check if validator at `index` is marked as participating.
    pub fn is_set(&self, index: usize) -> bool {
        if index >= self.total {
            return false;
        }
        self.bits[index / 8] & (1 << (index % 8)) != 0
    }

    /// Count the number of participating validators.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Participation fraction as a float in [0.0, 1.0].
    pub fn participation_fraction(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.count() as f64 / self.total as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_bitmap_set_and_check() {
        let mut bm = ParticipantBitmap::new(100);
        bm.set(0);
        bm.set(7);
        bm.set(99);
        assert!(bm.is_set(0));
        assert!(bm.is_set(7));
        assert!(bm.is_set(99));
        assert!(!bm.is_set(1));
        assert_eq!(bm.count(), 3);
    }

    #[test]
    fn participant_bitmap_out_of_bounds_is_false() {
        let bm = ParticipantBitmap::new(10);
        assert!(!bm.is_set(100));
    }

    #[test]
    fn participant_bitmap_participation_fraction() {
        let mut bm = ParticipantBitmap::new(4);
        bm.set(0);
        bm.set(1);
        assert!((bm.participation_fraction() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn bls_aggregator_empty_fails() {
        let agg = BlsAggregator::new(Hash256::ZERO, 100);
        assert!(agg.aggregate().is_err());
    }

    #[test]
    fn bls_batch_verifier_empty_succeeds() {
        let verifier = BlsBatchVerifier::new();
        assert_eq!(verifier.item_count(), 0);
        assert!(verifier.verify_all().unwrap());
    }
}
