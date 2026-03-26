//! # Primitive Types
//!
//! Fundamental value types used throughout AEVOR: hashes, addresses, amounts,
//! identifiers, and their associated arithmetic. All types are canonical
//! (deterministic serialization), cross-platform consistent, and TEE-compatible.

use std::fmt;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ============================================================
// HASH TYPES
// ============================================================

/// A 256-bit (32-byte) cryptographic hash value.
///
/// Used for content addressing, object identifiers, block hashes,
/// transaction hashes, Merkle nodes, and commitment values.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// The zero hash (all bytes are 0x00).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create from a raw byte array.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// View as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns `true` if this is the zero hash.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Parse from a hex string (with or without 0x prefix).
    pub fn from_hex(s: &str) -> Result<Self, crate::error::ValidationError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() != 64 {
            return Err(crate::error::ValidationError::InvalidFormat {
                field: "Hash256".into(),
                reason: format!("expected 64 hex chars, got {}", s.len()),
            });
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| {
            crate::error::ValidationError::InvalidFormat {
                field: "Hash256".into(),
                reason: "invalid hex characters".into(),
            }
        })?;
        Ok(Self(bytes))
    }

    /// Encode to hex string (no 0x prefix).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Default for Hash256 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A 512-bit (64-byte) hash value. Used for SHA-512 outputs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash512(pub [u8; 64]);

impl serde::Serialize for Hash512 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Hash512 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Hash512;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "64 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Hash512, E> {
                let bytes: [u8; 64] = v.try_into().map_err(|_| E::invalid_length(v.len(), &self))?;
                Ok(Hash512(bytes))
            }
        }
        d.deserialize_bytes(V)
    }
}

impl Hash512 {
    /// The zero hash.
    pub const ZERO: Self = Self([0u8; 64]);

    /// View as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash512({}...)", hex::encode(&self.0[..8]))
    }
}

impl Default for Hash512 {
    fn default() -> Self {
        Self::ZERO
    }
}

// ============================================================
// ALIAS: CryptoHash = Hash256
// ============================================================

/// Generic cryptographic hash. An alias for `Hash256`.
pub type CryptoHash = Hash256;

// ============================================================
// ADDRESS
// ============================================================

/// A 32-byte canonical AEVOR address.
///
/// Derived from the holder's public key via BLAKE3(public_key_bytes).
/// Addresses are deterministic: the same key always produces the same address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// The zero address. Used as a sentinel / null value.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// View as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parse from hex string (with or without 0x prefix).
    pub fn from_hex(s: &str) -> Result<Self, crate::error::ValidationError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() != 64 {
            return Err(crate::error::ValidationError::InvalidFormat {
                field: "Address".into(),
                reason: format!("expected 64 hex chars, got {}", s.len()),
            });
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| {
            crate::error::ValidationError::InvalidFormat {
                field: "Address".into(),
                reason: "invalid hex characters".into(),
            }
        })?;
        Ok(Self(bytes))
    }

    /// Encode to hex string (no 0x prefix).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns `true` if this is the zero address.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({}...)", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<Hash256> for Address {
    fn from(h: Hash256) -> Self {
        Self(h.0)
    }
}

/// Contract address — semantically identical to `Address`, typed for clarity.
pub type ContractAddress = Address;

// ============================================================
// AMOUNT
// ============================================================

/// A token amount in nanoAEVOR (the smallest indivisible unit).
///
/// 1 AEVOR = 1,000,000,000 nanoAEVOR (10^9).
/// Maximum representable: ~18.4 × 10^18 AEVOR (u128 max).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Amount(pub u128);

impl Amount {
    /// Zero amount.
    pub const ZERO: Self = Self(0);

    /// One nanoAEVOR.
    pub const ONE_NANO: Self = Self(1);

    /// One AEVOR in nanoAEVOR.
    pub const ONE_AEVOR: Self = Self(1_000_000_000);

    /// Create from a nanoAEVOR value.
    pub const fn from_nano(nano: u128) -> Self {
        Self(nano)
    }

    /// Create from a whole AEVOR value.
    pub fn from_aevor(aevor: u128) -> Option<Self> {
        aevor.checked_mul(1_000_000_000).map(Self)
    }

    /// Get the raw nanoAEVOR value.
    pub const fn as_nano(&self) -> u128 {
        self.0
    }

    /// Checked addition. Returns `None` on overflow.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// Checked subtraction. Returns `None` on underflow.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    /// Checked multiplication by a scalar.
    pub fn checked_mul(self, rhs: u128) -> Option<Self> {
        self.0.checked_mul(rhs).map(Self)
    }

    /// Saturating addition (clamps to `u128::MAX`).
    pub fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction (clamps to 0).
    pub fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    /// Returns `true` if the amount is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({} nAEVOR)", self.0)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let aevor = self.0 / 1_000_000_000;
        let frac = self.0 % 1_000_000_000;
        if frac == 0 {
            write!(f, "{aevor} AEVOR")
        } else {
            write!(f, "{}.{:09} AEVOR", aevor, frac)
        }
    }
}

// ============================================================
// GAS
// ============================================================

/// Gas amount for VM execution metering.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct GasAmount(pub u64);

impl GasAmount {
    /// Zero gas.
    pub const ZERO: Self = Self(0);

    /// Create from raw value.
    pub const fn from_u64(v: u64) -> Self {
        Self(v)
    }

    /// Raw u64 value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Checked subtraction.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    /// Checked addition.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }
}

impl fmt::Debug for GasAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GasAmount({})", self.0)
    }
}

impl fmt::Display for GasAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} gas", self.0)
    }
}

/// Gas price in nanoAEVOR per gas unit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct GasPrice(pub u64);

impl GasPrice {
    /// Zero price.
    pub const ZERO: Self = Self(0);

    /// Create from nanoAEVOR per gas unit.
    pub const fn from_nano_per_gas(v: u64) -> Self {
        Self(v)
    }

    /// Compute the total fee for a given gas amount.
    pub fn total_fee(&self, gas: GasAmount) -> Option<Amount> {
        (self.0 as u128)
            .checked_mul(gas.0 as u128)
            .map(Amount)
    }
}

impl fmt::Debug for GasPrice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GasPrice({} nAEVOR/gas)", self.0)
    }
}

// ============================================================
// BLOCK HEIGHT / NUMBER / HASH
// ============================================================

/// Block height (sequential block index from genesis = 0).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct BlockHeight(pub u64);

impl BlockHeight {
    /// Genesis block height.
    pub const GENESIS: Self = Self(0);

    /// Create from raw value.
    pub const fn from_u64(v: u64) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Increment by one.
    pub fn next(&self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Debug for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHeight({})", self.0)
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Block number — alias for `BlockHeight` for compatibility.
pub type BlockNumber = BlockHeight;

/// Block hash — a `Hash256` that specifically identifies a block.
pub type BlockHash = Hash256;

/// Transaction hash — a `Hash256` that specifically identifies a transaction.
pub type TransactionHash = Hash256;

// ============================================================
// EPOCH
// ============================================================

/// Epoch number. An epoch is a fixed number of consensus rounds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct EpochNumber(pub u64);

impl EpochNumber {
    /// Genesis epoch.
    pub const GENESIS: Self = Self(0);

    /// Create from raw value.
    pub const fn from_u64(v: u64) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Next epoch.
    pub fn next(&self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Debug for EpochNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EpochNumber({})", self.0)
    }
}

// ============================================================
// NONCE
// ============================================================

/// Transaction nonce — a per-account sequence number preventing replay.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Nonce(pub u64);

impl Nonce {
    /// Initial nonce for a new account.
    pub const INITIAL: Self = Self(0);

    /// Create from raw value.
    pub const fn from_u64(v: u64) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Next nonce.
    pub fn increment(&self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", self.0)
    }
}

// ============================================================
// CHAIN ID
// ============================================================

/// Network chain identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub u64);

impl ChainId {
    /// AEVOR mainnet chain ID.
    pub const MAINNET: Self = Self(1);
    /// AEVOR testnet chain ID.
    pub const TESTNET: Self = Self(2);
    /// AEVOR devnet chain ID.
    pub const DEVNET: Self = Self(3);

    /// Create from raw value.
    pub const fn from_u64(v: u64) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns `true` if this is the mainnet chain.
    pub fn is_mainnet(&self) -> bool {
        *self == Self::MAINNET
    }
}

impl fmt::Debug for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MAINNET => write!(f, "ChainId(mainnet=1)"),
            Self::TESTNET => write!(f, "ChainId(testnet=2)"),
            Self::DEVNET => write!(f, "ChainId(devnet=3)"),
            _ => write!(f, "ChainId({})", self.0),
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for ChainId {
    fn default() -> Self {
        Self::MAINNET
    }
}

// ============================================================
// OBJECT ID
// ============================================================

/// A unique identifier for a blockchain object.
///
/// Derived from the transaction hash that created the object and an
/// output index. Globally unique across the entire network lifetime.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub Hash256);

impl ObjectId {
    /// Create from a hash value.
    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }

    /// View the inner hash.
    pub fn as_hash(&self) -> &Hash256 {
        &self.0
    }

    /// View as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({}...)", hex::encode(&self.0.0[..6]))
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================
// CRYPTOGRAPHIC KEY TYPES
// ============================================================

/// A 32-byte Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// View as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive the address corresponding to this public key.
    ///
    /// Address = BLAKE3(public_key_bytes)
    pub fn to_address(&self) -> Address {
        let hash = blake3::hash(&self.0);
        Address(*hash.as_bytes())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}...)", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// A 32-byte Ed25519 secret (private) key. Zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    /// View as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never log secret key material.
        write!(f, "SecretKey([REDACTED])")
    }
}

/// A 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; 64]);

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Signature;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "64 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Signature, E> {
                let bytes: [u8; 64] = v.try_into().map_err(|_| E::invalid_length(v.len(), &self))?;
                Ok(Signature(bytes))
            }
        }
        d.deserialize_bytes(V)
    }
}

impl Signature {
    /// The zero signature (all bytes 0). Used as a placeholder.
    pub const ZERO: Self = Self([0u8; 64]);

    /// View as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}...)", hex::encode(&self.0[..8]))
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::ZERO
    }
}

// ============================================================
// VALIDATOR TYPES
// ============================================================

/// Unique validator identifier (Ed25519 public key hash).
pub type ValidatorId = Hash256;

/// Validator index within a validator set (0-based).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct ValidatorIndex(pub u32);

impl ValidatorIndex {
    /// Create from raw value.
    pub const fn from_u32(v: u32) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Debug for ValidatorIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValidatorIndex({})", self.0)
    }
}

/// Validator voting weight (proportional to stake).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct ValidatorWeight(pub u64);

impl ValidatorWeight {
    /// Zero weight.
    pub const ZERO: Self = Self(0);

    /// Create from raw value.
    pub const fn from_u64(v: u64) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Debug for ValidatorWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValidatorWeight({})", self.0)
    }
}

// ============================================================
// BALANCE / STAKE
// ============================================================

/// An account balance (nanoAEVOR). Distinct from `Amount` in that it represents
/// a running total rather than a transfer quantum.
pub type Balance = Amount;

/// Validator stake amount.
pub type StakeAmount = Amount;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash256_zero_is_all_zeros() {
        assert_eq!(Hash256::ZERO.0, [0u8; 32]);
    }

    #[test]
    fn hash256_roundtrip_hex() {
        let hex = "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809";
        assert_eq!(hex.len(), 64, "hex literal must be 64 chars");
        let h = Hash256::from_hex(hex).unwrap();
        assert_eq!(h.to_hex(), hex);
    }

    #[test]
    fn address_from_hex_and_display() {
        let bytes = [0xABu8; 32];
        let addr = Address::from_bytes(bytes);
        let hex = addr.to_hex();
        assert_eq!(hex.len(), 64);
        let recovered = Address::from_hex(&hex).unwrap();
        assert_eq!(addr, recovered);
    }

    #[test]
    fn amount_display_whole_aevor() {
        let a = Amount::ONE_AEVOR;
        assert_eq!(a.to_string(), "1 AEVOR");
    }

    #[test]
    fn amount_display_fractional_aevor() {
        let a = Amount::from_nano(1_500_000_000);
        assert_eq!(a.to_string(), "1.500000000 AEVOR");
    }

    #[test]
    fn amount_checked_add_overflow_returns_none() {
        let max = Amount(u128::MAX);
        assert!(max.checked_add(Amount::ONE_NANO).is_none());
    }

    #[test]
    fn amount_checked_sub_underflow_returns_none() {
        assert!(Amount::ZERO.checked_sub(Amount::ONE_NANO).is_none());
    }

    #[test]
    fn gas_price_total_fee() {
        let price = GasPrice::from_nano_per_gas(10);
        let gas = GasAmount::from_u64(100);
        let fee = price.total_fee(gas).unwrap();
        assert_eq!(fee.as_nano(), 1_000);
    }

    #[test]
    fn block_height_increments() {
        let h = BlockHeight::GENESIS;
        assert_eq!(h.next().as_u64(), 1);
    }

    #[test]
    fn public_key_to_address_is_deterministic() {
        let key = PublicKey([1u8; 32]);
        let addr1 = key.to_address();
        let addr2 = key.to_address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn chain_id_mainnet() {
        assert!(ChainId::MAINNET.is_mainnet());
        assert!(!ChainId::TESTNET.is_mainnet());
    }

    #[test]
    fn nonce_increments() {
        let n = Nonce::INITIAL;
        assert_eq!(n.increment().as_u64(), 1);
    }

    #[test]
    fn validator_index_ordering() {
        let a = ValidatorIndex::from_u32(0);
        let b = ValidatorIndex::from_u32(1);
        assert!(a < b);
    }
}
