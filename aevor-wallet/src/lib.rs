//! AEVOR wallet: key custody, address derivation, and transaction construction.
//!
//! This is the bottom of the user-facing stack. Everything a client does — submit
//! a transaction, register as a validator, deploy a program — starts with holding a
//! key and producing a correctly signed transaction, so this layer comes first.
//!
//! Three responsibilities, deliberately separated:
//!
//! - [`Wallet`] — an in-memory keypair with its derived address and nonce
//!   position. It constructs and signs transactions.
//! - [`Keystore`] — encrypted at-rest storage of a wallet's seed, so a key can
//!   survive a restart without sitting in plaintext on disk.
//! - Nonce management — a signed transaction commits to its nonce, so the wallet
//!   tracks the next value and only advances it once a transaction is actually
//!   produced.
//!
//! **What this layer does not do.** It does not submit transactions: submission
//! belongs to the node interface, which is the next subject. A wallet here produces
//! a `SignedTransaction` and hands it on.

#![forbid(unsafe_code)]

use aevor_core::crypto::SignatureSchemeId;
use aevor_core::primitives::{Address, Nonce, ObjectId};
use aevor_core::transaction::{SignedTransaction, Transaction};
use aevor_crypto::agility::Signer;
use aevor_crypto::post_quantum::ml_dsa::{MlDsa65KeyPair, ML_DSA_65_SK_LEN};
use aevor_crypto::post_quantum::HybridKeyPair;
use aevor_crypto::signatures::Ed25519KeyPair;

/// Errors this layer can produce.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Entropy generation failed.
    #[error("entropy generation failed: {0}")]
    Entropy(String),
    /// Key generation or recovery failed.
    #[error("key material invalid: {0}")]
    Key(String),
    /// Key derivation from the passphrase failed.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    /// The keystore could not be decrypted — usually a wrong passphrase.
    #[error("keystore could not be decrypted (wrong passphrase, or the file is corrupt)")]
    Decryption,
    /// The keystore file is not in a recognised format.
    #[error("keystore format invalid: {0}")]
    Format(String),
    /// Filesystem failure.
    #[error("keystore io: {0}")]
    Io(String),
}

/// Result alias for wallet operations.
pub type WalletResult<T> = Result<T, WalletError>;

/// Which signature scheme a wallet holds.
///
/// These are exactly the schemes the transaction layer accepts (each implements
/// [`Signer`]), so a wallet can hold any identity the chain can verify. Hybrid
/// signs with **both** Ed25519 and ML-DSA-65, so it stays valid if either is
/// broken — the migration path to post-quantum without abandoning classical
/// security in the meantime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Scheme {
    /// Ed25519 — small and fast; the default.
    Ed25519,
    /// ML-DSA-65 (FIPS 204) — post-quantum.
    MlDsa65,
    /// Ed25519 + ML-DSA-65 together.
    Hybrid,
}

impl Scheme {
    /// Parse a scheme name as accepted on the command line.
    ///
    /// # Errors
    /// Returns [`WalletError::Key`] for an unrecognised name.
    pub fn parse(name: &str) -> WalletResult<Self> {
        match name.to_ascii_lowercase().replace(['_', ' '], "-").as_str() {
            "ed25519" => Ok(Self::Ed25519),
            "ml-dsa-65" | "ml-dsa65" | "mldsa65" | "dilithium3" => Ok(Self::MlDsa65),
            "hybrid" => Ok(Self::Hybrid),
            other => Err(WalletError::Key(format!(
                "unknown scheme '{other}' (supported: ed25519, ml-dsa-65, hybrid)"
            ))),
        }
    }

    /// The canonical name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa-65",
            Self::Hybrid => "hybrid",
        }
    }

    /// Whether signatures from this scheme resist quantum attack.
    #[must_use]
    pub fn is_post_quantum(self) -> bool {
        matches!(self, Self::MlDsa65 | Self::Hybrid)
    }
}

// The variants differ greatly in size (an ML-DSA secret key is ~4 KB against
// Ed25519's 32 bytes), which is inherent to holding post-quantum key material.
// Boxing would add an indirection on every signature for no benefit, since a
// wallet holds exactly one key.
#[allow(clippy::large_enum_variant)]
enum Keys {
    Ed25519(Ed25519KeyPair),
    MlDsa65(MlDsa65KeyPair),
    Hybrid(HybridKeyPair),
}

/// A keypair with its derived address and nonce position.
///
/// The secret material is retained so the wallet can be persisted and recovered;
/// it is never serialised except through [`Keystore`], which encrypts it.
pub struct Wallet {
    keys: Keys,
    scheme: Scheme,
    address: Address,
    next_nonce: u64,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render secret material.
        f.debug_struct("Wallet")
            .field("scheme", &self.scheme)
            .field("address", &self.address)
            .field("next_nonce", &self.next_nonce)
            .finish_non_exhaustive()
    }
}

/// Derive an address from a scheme-tagged public key.
///
/// The scheme id is folded in, so the same bytes under different schemes cannot
/// collide onto one address.
fn address_of(public: &aevor_core::crypto::MultiPublicKey) -> Address {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(public.scheme as u16).to_le_bytes());
    hasher.update(&public.bytes);
    Address(*hasher.finalize().as_bytes())
}

impl Wallet {
    fn from_keys(keys: Keys, scheme: Scheme) -> Self {
        let public = match &keys {
            Keys::Ed25519(k) => k.public_key_multi(),
            Keys::MlDsa65(k) => k.public_key_multi(),
            Keys::Hybrid(k) => k.public_key_multi(),
        };
        // Ed25519 keeps its established derivation so existing identities are
        // unchanged; the other schemes fold in their scheme id.
        let address = if scheme == Scheme::Ed25519 {
            match &keys {
                Keys::Ed25519(k) => k.public_key().to_address(),
                _ => address_of(&public),
            }
        } else {
            address_of(&public)
        };
        Self { keys, scheme, address, next_nonce: 0 }
    }

    /// Create an Ed25519 wallet from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::from_keys(Keys::Ed25519(Ed25519KeyPair::from_seed(seed)), Scheme::Ed25519)
    }

    /// Generate a wallet for `scheme` from fresh operating-system entropy.
    ///
    /// # Errors
    /// Returns an error if the OS entropy source or key generation fails.
    pub fn generate_scheme(scheme: Scheme) -> WalletResult<Self> {
        let keys = match scheme {
            Scheme::Ed25519 => {
                let mut seed = [0u8; 32];
                getrandom::getrandom(&mut seed)
                    .map_err(|e| WalletError::Entropy(e.to_string()))?;
                Keys::Ed25519(Ed25519KeyPair::from_seed(seed))
            }
            Scheme::MlDsa65 => Keys::MlDsa65(
                MlDsa65KeyPair::generate().map_err(|e| WalletError::Key(e.to_string()))?,
            ),
            Scheme::Hybrid => Keys::Hybrid(
                HybridKeyPair::generate().map_err(|e| WalletError::Key(e.to_string()))?,
            ),
        };
        Ok(Self::from_keys(keys, scheme))
    }

    /// Generate an Ed25519 wallet (the default scheme).
    ///
    /// # Errors
    /// Returns [`WalletError::Entropy`] if the OS entropy source fails.
    pub fn generate() -> WalletResult<Self> {
        Self::generate_scheme(Scheme::Ed25519)
    }

    /// This wallet's signature scheme.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// This wallet's address — the identity that holds balance and pays fees.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    /// The scheme-tagged public key.
    #[must_use]
    pub fn public_key(&self) -> aevor_core::crypto::MultiPublicKey {
        match &self.keys {
            Keys::Ed25519(k) => k.public_key_multi(),
            Keys::MlDsa65(k) => k.public_key_multi(),
            Keys::Hybrid(k) => k.public_key_multi(),
        }
    }

    /// The public key bytes, scheme-specific.
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key().bytes
    }

    /// The scheme id carried in transactions signed by this wallet.
    #[must_use]
    pub fn scheme_id(&self) -> SignatureSchemeId {
        self.public_key().scheme
    }

    /// The nonce the next transaction will use.
    #[must_use]
    pub fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    /// Set the next nonce, e.g. after querying the chain for the account's current
    /// position. Necessary whenever the wallet has been offline or used elsewhere.
    pub fn set_next_nonce(&mut self, nonce: u64) {
        self.next_nonce = nonce;
    }

    /// Secret material for custody. Treat as the private key.
    fn secret_bytes(&self) -> Vec<u8> {
        match &self.keys {
            Keys::Ed25519(k) => k.seed().to_vec(),
            Keys::MlDsa65(k) => k.to_secret_bytes().to_vec(),
            Keys::Hybrid(k) => k.to_secret_bytes(),
        }
    }

    /// Recover a wallet from `scheme` and its secret material.
    ///
    /// # Errors
    /// Returns [`WalletError::Key`] if the material is the wrong length or invalid.
    pub fn from_secret_bytes(scheme: Scheme, bytes: &[u8]) -> WalletResult<Self> {
        let keys = match scheme {
            Scheme::Ed25519 => {
                let seed: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| WalletError::Key("ed25519 seed must be 32 bytes".into()))?;
                Keys::Ed25519(Ed25519KeyPair::from_seed(seed))
            }
            Scheme::MlDsa65 => {
                let sk: [u8; ML_DSA_65_SK_LEN] = bytes.try_into().map_err(|_| {
                    WalletError::Key(format!("ml-dsa-65 secret must be {ML_DSA_65_SK_LEN} bytes"))
                })?;
                Keys::MlDsa65(
                    MlDsa65KeyPair::from_secret_bytes(&sk)
                        .map_err(|e| WalletError::Key(e.to_string()))?,
                )
            }
            Scheme::Hybrid => Keys::Hybrid(
                HybridKeyPair::from_secret_bytes(bytes)
                    .map_err(|e| WalletError::Key(e.to_string()))?,
            ),
        };
        Ok(Self::from_keys(keys, scheme))
    }

    /// Build and sign a transaction, advancing the nonce.
    ///
    /// The sender is set **before** signing, so the signature commits to it — a
    /// transaction cannot be re-attributed to a different account after the fact.
    /// The nonce advances only here, once a transaction has actually been produced.
    pub fn sign_transaction(
        &mut self,
        reads: &[ObjectId],
        writes: &[ObjectId],
        bytecode: Vec<u8>,
    ) -> SignedTransaction {
        let tx = Transaction::new_simple(
            self.public_key(),
            Nonce(self.next_nonce),
            reads,
            writes,
            bytecode,
        );
        self.next_nonce = self.next_nonce.saturating_add(1);
        self.sign_prepared(tx)
    }

    /// Sign an already-constructed transaction, forcing the sender to this wallet's
    /// address first. Does not touch the nonce: the caller owns the nonce it chose.
    #[must_use]
    pub fn sign_prepared(&self, mut tx: Transaction) -> SignedTransaction {
        tx.sender = self.address;
        match &self.keys {
            Keys::Ed25519(k) => aevor_crypto::agility::sign_transaction(tx, k),
            Keys::MlDsa65(k) => aevor_crypto::agility::sign_transaction(tx, k),
            Keys::Hybrid(k) => aevor_crypto::agility::sign_transaction(tx, k),
        }
    }
}

/// Encrypted at-rest storage for a wallet seed.
///
/// The passphrase is stretched with **Argon2id** — a memory-hard function with a
/// real work factor — rather than a plain hash or HKDF, because a keystore
/// passphrase is low-entropy by nature and a cheap KDF makes offline guessing
/// trivial. The derived key encrypts the seed with ChaCha20-Poly1305, whose
/// authentication tag is what makes a wrong passphrase fail loudly instead of
/// yielding garbage.
pub struct Keystore;

/// The on-disk keystore format. Everything here is public except the ciphertext.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeystoreFile {
    version: u32,
    scheme: String,
    address: String,
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
    tag: String,
}

const KEYSTORE_VERSION: u32 = 1;

impl Keystore {
    fn derive_key(passphrase: &str, salt: &[u8]) -> WalletResult<[u8; 32]> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(64 * 1024, 3, 1, Some(32))
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
        Ok(key)
    }

    /// Encrypt `wallet`'s seed under `passphrase` and write it to `path`.
    ///
    /// # Errors
    /// Returns an error if entropy generation, key derivation, encryption, or the
    /// filesystem write fails.
    pub fn save(wallet: &Wallet, passphrase: &str, path: &std::path::Path) -> WalletResult<()> {
        use aevor_crypto::encryption::{ChaCha20Poly1305Cipher, EncryptionKey};

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|e| WalletError::Entropy(e.to_string()))?;

        let key = EncryptionKey(Self::derive_key(passphrase, &salt)?);
        // The cipher generates its own nonce, which is returned alongside the
        // ciphertext and stored so decryption can reproduce it.
        let secret = wallet.secret_bytes();
        let encrypted = ChaCha20Poly1305Cipher::encrypt(&key, &secret, &[])
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;

        let file = KeystoreFile {
            version: KEYSTORE_VERSION,
            scheme: wallet.scheme.name().to_string(),
            address: hex::encode(wallet.address.0),
            kdf: "argon2id".to_string(),
            salt: hex::encode(salt),
            nonce: hex::encode(encrypted.nonce.0),
            ciphertext: hex::encode(&encrypted.ciphertext),
            tag: hex::encode(encrypted.auth_tag.0),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| WalletError::Format(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| WalletError::Io(e.to_string()))
    }

    /// Load and decrypt a wallet from `path`.
    ///
    /// # Errors
    /// Returns [`WalletError::Decryption`] when the passphrase is wrong or the file
    /// has been tampered with (the authentication tag fails), and
    /// [`WalletError::Format`] when the file is not a recognised keystore.
    pub fn load(passphrase: &str, path: &std::path::Path) -> WalletResult<Wallet> {
        use aevor_crypto::encryption::{
            AuthTag, ChaCha20Poly1305Cipher, EncryptedData, EncryptionKey, Nonce as CipherNonce,
        };

        let json = std::fs::read_to_string(path).map_err(|e| WalletError::Io(e.to_string()))?;
        let file: KeystoreFile =
            serde_json::from_str(&json).map_err(|e| WalletError::Format(e.to_string()))?;
        if file.version != KEYSTORE_VERSION {
            return Err(WalletError::Format(format!(
                "unsupported keystore version {}",
                file.version
            )));
        }
        if file.kdf != "argon2id" {
            return Err(WalletError::Format(format!("unsupported kdf {}", file.kdf)));
        }
        let unhex = |s: &str, what: &str| -> WalletResult<Vec<u8>> {
            hex::decode(s).map_err(|e| WalletError::Format(format!("{what}: {e}")))
        };
        let salt = unhex(&file.salt, "salt")?;
        let nonce_bytes: [u8; 12] = unhex(&file.nonce, "nonce")?
            .try_into()
            .map_err(|_| WalletError::Format("nonce must be 12 bytes".to_string()))?;
        let tag_bytes: [u8; 16] = unhex(&file.tag, "tag")?
            .try_into()
            .map_err(|_| WalletError::Format("tag must be 16 bytes".to_string()))?;

        let key = EncryptionKey(Self::derive_key(passphrase, &salt)?);
        let encrypted = EncryptedData {
            ciphertext: unhex(&file.ciphertext, "ciphertext")?,
            nonce: CipherNonce::from_bytes(nonce_bytes),
            auth_tag: AuthTag(tag_bytes),
        };
        let secret = ChaCha20Poly1305Cipher::decrypt(&key, &encrypted, &[])
            .map_err(|_| WalletError::Decryption)?;
        let scheme = Scheme::parse(&file.scheme)
            .map_err(|e| WalletError::Format(e.to_string()))?;
        Wallet::from_secret_bytes(scheme, &secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_deterministic_from_the_seed() {
        let a = Wallet::from_seed([7u8; 32]);
        let b = Wallet::from_seed([7u8; 32]);
        assert_eq!(a.address(), b.address(), "same seed gives the same identity");
        let c = Wallet::from_seed([8u8; 32]);
        assert_ne!(a.address(), c.address(), "different seeds give different identities");
    }

    #[test]
    fn generated_wallets_are_distinct() {
        let a = Wallet::generate().expect("entropy");
        let b = Wallet::generate().expect("entropy");
        assert_ne!(a.address(), b.address());
    }

    #[test]
    fn signing_advances_the_nonce_and_commits_to_the_sender() {
        let mut w = Wallet::from_seed([3u8; 32]);
        assert_eq!(w.next_nonce(), 0);
        let tx = w.sign_transaction(&[], &[], vec![1, 2, 3]);
        assert_eq!(w.next_nonce(), 1, "nonce advances once a transaction is produced");
        assert_eq!(tx.sender(), w.address(), "the signature commits to this sender");
        assert!(aevor_crypto::agility::verify_transaction(&tx), "signature verifies");

        let tx2 = w.sign_transaction(&[], &[], vec![4]);
        assert_eq!(w.next_nonce(), 2);
        assert_ne!(tx.hash(), tx2.hash(), "distinct nonces give distinct transactions");
    }

    #[test]
    fn nonce_can_be_resynchronised_with_the_chain() {
        let mut w = Wallet::from_seed([4u8; 32]);
        w.set_next_nonce(42);
        assert_eq!(w.next_nonce(), 42);
        let _ = w.sign_transaction(&[], &[], vec![]);
        assert_eq!(w.next_nonce(), 43);
    }

    #[test]
    fn debug_never_reveals_the_seed() {
        let w = Wallet::from_seed([0xAB; 32]);
        let rendered = format!("{w:?}");
        assert!(!rendered.contains("seed"), "the seed must not appear in Debug output");
        assert!(!rendered.to_lowercase().contains("abababab"));
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("aevor-wallet-{tag}-{}.json", std::process::id()));
        p
    }

    #[test]
    fn every_scheme_signs_verifiably_and_is_distinct() {
        // The wallet must cover every scheme the transaction layer accepts —
        // classical, post-quantum, and hybrid — not just Ed25519.
        for scheme in [Scheme::Ed25519, Scheme::MlDsa65, Scheme::Hybrid] {
            let mut w = Wallet::generate_scheme(scheme).expect("generates");
            assert_eq!(w.scheme(), scheme);
            let tx = w.sign_transaction(&[], &[], vec![1, 2, 3]);
            assert_eq!(tx.sender(), w.address(), "signature commits to the sender");
            assert!(
                aevor_crypto::agility::verify_transaction(&tx),
                "{} signature must verify",
                scheme.name()
            );
            assert_eq!(w.next_nonce(), 1);
        }
        // Post-quantum classification is correct.
        assert!(!Scheme::Ed25519.is_post_quantum());
        assert!(Scheme::MlDsa65.is_post_quantum());
        assert!(Scheme::Hybrid.is_post_quantum(), "hybrid resists quantum attack");
    }

    #[test]
    fn schemes_produce_distinct_addresses() {
        // The scheme id is folded into the address, so identical key bytes under
        // different schemes cannot collide onto one identity.
        let a = Wallet::generate_scheme(Scheme::Ed25519).unwrap();
        let b = Wallet::generate_scheme(Scheme::MlDsa65).unwrap();
        let c = Wallet::generate_scheme(Scheme::Hybrid).unwrap();
        assert_ne!(a.address(), b.address());
        assert_ne!(b.address(), c.address());
        assert_ne!(a.address(), c.address());
    }

    #[test]
    fn scheme_names_round_trip() {
        for s in [Scheme::Ed25519, Scheme::MlDsa65, Scheme::Hybrid] {
            assert_eq!(Scheme::parse(s.name()).unwrap(), s);
        }
        assert_eq!(Scheme::parse("dilithium3").unwrap(), Scheme::MlDsa65);
        assert!(Scheme::parse("rsa").is_err(), "unknown schemes are rejected");
    }

    #[test]
    fn post_quantum_and_hybrid_identities_survive_a_keystore_round_trip() {
        // Before this, ML-DSA and hybrid keys could only be generated — never
        // persisted or recovered — which made them unusable for custody.
        for scheme in [Scheme::MlDsa65, Scheme::Hybrid] {
            let w = Wallet::generate_scheme(scheme).expect("generates");
            let path = temp_path(&format!("pq-{}", scheme.name()));
            Keystore::save(&w, "pq passphrase", &path).expect("saves");

            let loaded = Keystore::load("pq passphrase", &path).expect("loads");
            assert_eq!(loaded.scheme(), scheme, "scheme survives the round trip");
            assert_eq!(loaded.address(), w.address(), "the same identity is recovered");
            assert_eq!(loaded.public_key_bytes(), w.public_key_bytes());

            // And the recovered key still signs verifiably.
            let mut loaded = loaded;
            let tx = loaded.sign_transaction(&[], &[], vec![9]);
            assert!(aevor_crypto::agility::verify_transaction(&tx));

            assert!(Keystore::load("wrong", &path).is_err());
            let _ = std::fs::remove_file(&path);
        }
    }

    #[test]
    fn keystore_round_trips_and_rejects_a_wrong_passphrase() {
        let w = Wallet::from_seed([9u8; 32]);
        let path = temp_path("roundtrip");
        Keystore::save(&w, "correct horse battery staple", &path).expect("saves");

        let loaded = Keystore::load("correct horse battery staple", &path).expect("loads");
        assert_eq!(loaded.address(), w.address(), "the same identity is recovered");
        assert_eq!(loaded.public_key_bytes(), w.public_key_bytes());

        let wrong = Keystore::load("wrong passphrase", &path);
        assert!(
            matches!(wrong, Err(WalletError::Decryption)),
            "a wrong passphrase must fail loudly, not yield a different key"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn keystore_never_stores_the_seed_in_plaintext() {
        let seed = [0x5Au8; 32];
        let w = Wallet::from_seed(seed);
        // (Ed25519: the seed IS the secret material.)
        let path = temp_path("plaintext");
        Keystore::save(&w, "pass", &path).expect("saves");
        let contents = std::fs::read_to_string(&path).expect("readable");
        assert!(
            !contents.contains(&hex::encode(seed)),
            "the seed must never appear in the keystore file"
        );
        assert!(contents.contains("argon2id"), "the KDF is recorded for future compatibility");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampering_with_the_keystore_is_detected() {
        let w = Wallet::from_seed([0x11; 32]);
        let path = temp_path("tamper");
        Keystore::save(&w, "pass", &path).expect("saves");
        let contents = std::fs::read_to_string(&path).expect("readable");

        // Flip a byte of the ciphertext; the authentication tag must catch it.
        let file: serde_json::Value = serde_json::from_str(&contents).unwrap();
        let ct = file["ciphertext"].as_str().unwrap();
        let mut bytes = hex::decode(ct).unwrap();
        bytes[0] ^= 0xFF;
        let tampered = contents.replace(ct, &hex::encode(&bytes));
        std::fs::write(&path, tampered).unwrap();

        assert!(
            matches!(Keystore::load("pass", &path), Err(WalletError::Decryption)),
            "tampering must be detected by the authentication tag"
        );
        let _ = std::fs::remove_file(&path);
    }
}
