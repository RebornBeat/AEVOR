//! Account identity and key migration across the classical → post-quantum
//! transition.
//!
//! This answers a concrete user question: a wallet created today with a
//! classical key must be able to (a) switch its controlling key *without*
//! creating a new wallet or losing its identity/assets, and (b) remain safe
//! when quantum computers arrive.
//!
//! ## Model
//! An account has a **stable [`AccountId`]** that is independent of whichever
//! key currently controls it. Assets and identity bind to the `AccountId`, so
//! rotating keys never changes who you are.
//!
//! A user may create a key as Ed25519 (classical), ML-DSA-65 (post-quantum), or
//! Hybrid (both) — see [`SignatureSchemeId`]. Two migration paths keep a
//! classical wallet safe:
//!
//! 1. **Signed key rotation** ([`AccountKeyRecord::rotate`]) — while the current
//!    key's scheme is unbroken, the current key authorizes a switch to a new
//!    key (e.g. Ed25519 → Hybrid). Same `AccountId`, new controlling key.
//!
//! 2. **Quantum-safe migration pre-commitment**
//!    ([`AccountKeyRecord::set_pq_commitment`] / [`activate_pq_migration`]) — the
//!    current key commits `hash(future_pq_key)` *now*, while it is still secure.
//!    Later — **even if the classical key has since been broken** — revealing the
//!    matching PQ key activates PQ control. An adversary who broke the classical
//!    key still cannot forge this migration, because they cannot find a key
//!    whose hash equals the commitment (preimage resistance, only quadratically
//!    weakened by Grover → use a 256-bit hash for 128-bit PQ security).
//!
//! 3. **Hybrid from the start** — a Hybrid key needs *both* Ed25519 and ML-DSA
//!    to forge, so it is already safe when Ed25519 falls, with no migration
//!    needed. (Enforced by the `HybridEd25519MlDsa65` verification path.)
//!
//! [`activate_pq_migration`]: AccountKeyRecord::activate_pq_migration

use aevor_core::crypto::{MultiPublicKey, MultiSignature, SignatureSchemeId};
use aevor_core::primitives::Hash256;

use crate::agility::{verify_multi, Signer};
use crate::hash::Blake3Hasher;

/// A stable account identity, independent of the key that currently controls it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AccountId(pub Hash256);

impl AccountId {
    /// Derive an account id from the key a wallet is first created with. The id
    /// stays fixed for the life of the account, even after key rotation.
    #[must_use]
    pub fn from_initial_key(pk: &MultiPublicKey) -> Self {
        let mut h = Blake3Hasher::new();
        h.update(b"aevor-account-id");
        h.update(&(pk.scheme as u16).to_le_bytes());
        h.update(&pk.bytes);
        Self(h.finalize().0)
    }
}

/// Errors from account key migration.
#[derive(Debug, PartialEq, Eq)]
pub enum MigrationError {
    /// A rotation/commitment was not authorized by the current key.
    Unauthorized,
    /// No post-quantum migration was committed.
    NoCommitment,
    /// The revealed key does not match the committed hash.
    CommitmentMismatch,
}

/// The record of which key currently controls an account, plus an optional
/// quantum-safe pre-commitment to a future post-quantum key. In a running
/// chain this record lives in account state.
#[derive(Clone, Debug)]
pub struct AccountKeyRecord {
    /// Stable account identity.
    pub account: AccountId,
    /// Scheme of the current controlling key.
    pub scheme: SignatureSchemeId,
    /// Bytes of the current controlling public key.
    pub public_key: Vec<u8>,
    /// Increments on every rotation/migration (replay protection).
    pub version: u64,
    /// Optional committed hash of a future post-quantum key.
    pub pq_migration_commitment: Option<Hash256>,
}

impl AccountKeyRecord {
    /// Open a new account controlled by the given key. The user chooses the
    /// scheme here — Ed25519, ML-DSA-65, or Hybrid — all are supported.
    #[must_use]
    pub fn open(pk: &MultiPublicKey) -> Self {
        Self {
            account: AccountId::from_initial_key(pk),
            scheme: pk.scheme,
            public_key: pk.bytes.clone(),
            version: 0,
            pq_migration_commitment: None,
        }
    }

    /// The current controlling key as a `MultiPublicKey`.
    #[must_use]
    pub fn current_key(&self) -> MultiPublicKey {
        MultiPublicKey::new(self.scheme, self.public_key.clone())
    }

    fn rotation_message(&self, new: &MultiPublicKey, new_version: u64) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"aevor-key-rotation");
        m.extend_from_slice(&self.account.0 .0);
        m.extend_from_slice(&new_version.to_le_bytes());
        m.extend_from_slice(&(new.scheme as u16).to_le_bytes());
        m.extend_from_slice(&new.bytes);
        m
    }

    /// Produce a rotation authorization by signing with the current key.
    #[must_use]
    pub fn authorize_rotation<S: Signer>(
        &self,
        current: &S,
        new_key: &MultiPublicKey,
    ) -> MultiSignature {
        current.sign_message(&self.rotation_message(new_key, self.version + 1))
    }

    /// Rotate the controlling key. The authorization must verify against the
    /// **current** key (safe while the current scheme is unbroken). The
    /// `AccountId` does not change — only the key and version.
    ///
    /// # Errors
    /// [`MigrationError::Unauthorized`] if the authorization does not verify.
    pub fn rotate(
        &mut self,
        new_key: &MultiPublicKey,
        authorization: &MultiSignature,
    ) -> Result<(), MigrationError> {
        let new_version = self.version + 1;
        let message = self.rotation_message(new_key, new_version);
        if !verify_multi(&message, authorization, &self.current_key()).is_valid() {
            return Err(MigrationError::Unauthorized);
        }
        self.scheme = new_key.scheme;
        self.public_key.clone_from(&new_key.bytes);
        self.version = new_version;
        self.pq_migration_commitment = None; // superseded by the rotation
        Ok(())
    }

    /// The quantum-safe commitment for a future post-quantum key.
    #[must_use]
    pub fn commitment_of(pk: &MultiPublicKey) -> Hash256 {
        let mut h = Blake3Hasher::new();
        h.update(b"aevor-pq-migration-commitment");
        h.update(&(pk.scheme as u16).to_le_bytes());
        h.update(&pk.bytes);
        h.finalize().0
    }

    fn commitment_message(&self, commitment: &Hash256) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"aevor-pq-commit");
        m.extend_from_slice(&self.account.0 .0);
        m.extend_from_slice(&commitment.0);
        m
    }

    /// Produce an authorization to set a post-quantum migration commitment,
    /// signed by the current key. Returns the commitment and its authorization.
    #[must_use]
    pub fn authorize_pq_commitment<S: Signer>(
        &self,
        current: &S,
        future_pq_key: &MultiPublicKey,
    ) -> (Hash256, MultiSignature) {
        let commitment = Self::commitment_of(future_pq_key);
        let auth = current.sign_message(&self.commitment_message(&commitment));
        (commitment, auth)
    }

    /// Record a quantum-safe pre-commitment to a future post-quantum key. Must
    /// be authorized by the **current** key while it is still secure.
    ///
    /// # Errors
    /// [`MigrationError::Unauthorized`] if the authorization does not verify.
    pub fn set_pq_commitment(
        &mut self,
        commitment: Hash256,
        authorization: &MultiSignature,
    ) -> Result<(), MigrationError> {
        let message = self.commitment_message(&commitment);
        if !verify_multi(&message, authorization, &self.current_key()).is_valid() {
            return Err(MigrationError::Unauthorized);
        }
        self.pq_migration_commitment = Some(commitment);
        Ok(())
    }

    /// Activate a previously-committed post-quantum migration by revealing the
    /// key. **No signature from the current key is required** — the commitment
    /// itself is the authorization, and it is quantum-safe, so this works even
    /// if the classical key has since been broken.
    ///
    /// # Errors
    /// [`MigrationError::NoCommitment`] if nothing was committed;
    /// [`MigrationError::CommitmentMismatch`] if the revealed key does not match.
    pub fn activate_pq_migration(
        &mut self,
        revealed_pq_key: &MultiPublicKey,
    ) -> Result<(), MigrationError> {
        let commitment = self
            .pq_migration_commitment
            .ok_or(MigrationError::NoCommitment)?;
        if Self::commitment_of(revealed_pq_key) != commitment {
            return Err(MigrationError::CommitmentMismatch);
        }
        self.scheme = revealed_pq_key.scheme;
        self.public_key.clone_from(&revealed_pq_key.bytes);
        self.version += 1;
        self.pq_migration_commitment = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post_quantum::ml_dsa::MlDsa65KeyPair;
    use crate::post_quantum::HybridKeyPair;
    use crate::signatures::Ed25519KeyPair;

    #[test]
    fn account_can_be_created_with_any_scheme() {
        // Ed25519, ML-DSA, and Hybrid wallets are all creatable.
        let ed = Ed25519KeyPair::generate().unwrap();
        let ml = MlDsa65KeyPair::generate().unwrap();
        let hy = HybridKeyPair::generate().unwrap();

        let a_ed = AccountKeyRecord::open(&ed.public_key_multi());
        let a_ml = AccountKeyRecord::open(&ml.public_key_multi());
        let a_hy = AccountKeyRecord::open(&hy.public_key_multi());

        assert_eq!(a_ed.scheme, SignatureSchemeId::Ed25519);
        assert_eq!(a_ml.scheme, SignatureSchemeId::MlDsa65);
        assert_eq!(a_hy.scheme, SignatureSchemeId::HybridEd25519MlDsa65);
        // Distinct identities.
        assert_ne!(a_ed.account, a_ml.account);
    }

    #[test]
    fn rotate_classical_to_hybrid_keeps_identity_no_new_wallet() {
        // A user with an Ed25519 wallet upgrades to a Hybrid key WITHOUT a new
        // wallet — the account id (identity/assets) is preserved.
        let ed = Ed25519KeyPair::generate().unwrap();
        let mut account = AccountKeyRecord::open(&ed.public_key_multi());
        let original_id = account.account;

        let hybrid = HybridKeyPair::generate().unwrap();
        let new_key = hybrid.public_key_multi();
        let auth = account.authorize_rotation(&ed, &new_key);
        account.rotate(&new_key, &auth).unwrap();

        assert_eq!(account.account, original_id, "identity unchanged across rotation");
        assert_eq!(account.scheme, SignatureSchemeId::HybridEd25519MlDsa65);
        assert_eq!(account.version, 1);

        // The new hybrid key now controls the account; verify by signing.
        let msg = b"spend from rotated account";
        let sig = hybrid.sign_message(msg);
        assert_eq!(
            verify_multi(msg, &sig, &account.current_key()),
            crate::agility::MultiVerify::Valid
        );
    }

    #[test]
    fn rotation_by_wrong_key_is_rejected() {
        let ed = Ed25519KeyPair::generate().unwrap();
        let mut account = AccountKeyRecord::open(&ed.public_key_multi());
        let attacker = Ed25519KeyPair::generate().unwrap();
        let new_key = HybridKeyPair::generate().unwrap().public_key_multi();

        // Attacker signs the rotation with THEIR key, not the account's.
        let bad_auth = account.authorize_rotation(&attacker, &new_key);
        assert_eq!(account.rotate(&new_key, &bad_auth), Err(MigrationError::Unauthorized));
        assert_eq!(account.version, 0, "no rotation applied");
    }

    #[test]
    fn quantum_safe_migration_activates_even_if_classical_key_is_broken() {
        // Pre-quantum: an Ed25519 account commits to a future ML-DSA key.
        let ed = Ed25519KeyPair::generate().unwrap();
        let mut account = AccountKeyRecord::open(&ed.public_key_multi());
        let original_id = account.account;

        let future_pq = MlDsa65KeyPair::generate().unwrap();
        let future_key = future_pq.public_key_multi();
        let (commitment, auth) = account.authorize_pq_commitment(&ed, &future_key);
        account.set_pq_commitment(commitment, &auth).unwrap();

        // Post-quantum: the classical key is now assumed broken — NO classical
        // signature is used. Revealing the committed PQ key activates control.
        account.activate_pq_migration(&future_key).unwrap();

        assert_eq!(account.account, original_id, "identity survives the migration");
        assert_eq!(account.scheme, SignatureSchemeId::MlDsa65);
        assert!(account.pq_migration_commitment.is_none());

        // The PQ key now controls the account.
        let msg = b"post-quantum spend";
        let sig = future_pq.sign_message(msg);
        assert_eq!(
            verify_multi(msg, &sig, &account.current_key()),
            crate::agility::MultiVerify::Valid
        );
    }

    #[test]
    fn migration_rejects_wrong_revealed_key() {
        let ed = Ed25519KeyPair::generate().unwrap();
        let mut account = AccountKeyRecord::open(&ed.public_key_multi());
        let committed = MlDsa65KeyPair::generate().unwrap();
        let (commitment, auth) = account.authorize_pq_commitment(&ed, &committed.public_key_multi());
        account.set_pq_commitment(commitment, &auth).unwrap();

        // An attacker reveals a DIFFERENT key — cannot match the committed hash.
        let attacker_key = MlDsa65KeyPair::generate().unwrap();
        assert_eq!(
            account.activate_pq_migration(&attacker_key.public_key_multi()),
            Err(MigrationError::CommitmentMismatch)
        );
        // Original commitment still stands; account not hijacked.
        assert_eq!(account.scheme, SignatureSchemeId::Ed25519);
    }

    #[test]
    fn setting_commitment_requires_current_key() {
        let ed = Ed25519KeyPair::generate().unwrap();
        let mut account = AccountKeyRecord::open(&ed.public_key_multi());
        let future = MlDsa65KeyPair::generate().unwrap();
        let commitment = AccountKeyRecord::commitment_of(&future.public_key_multi());

        // Authorization signed by an unrelated key must be rejected.
        let attacker = Ed25519KeyPair::generate().unwrap();
        let bad_auth = attacker.sign_message(&account.commitment_message(&commitment));
        assert_eq!(
            account.set_pq_commitment(commitment, &bad_auth),
            Err(MigrationError::Unauthorized)
        );
    }
}
