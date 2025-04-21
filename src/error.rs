use std::fmt;
use std::io;
use thiserror::Error;

/// The main error enum representing various error categories throughout the Aevor blockchain.
#[derive(Error, Debug)]
pub enum AevorError {
    /// Errors originating from the blockchain module
    #[error("Blockchain error: {0}")]
    Blockchain(String),

    /// Errors related to consensus mechanisms
    #[error("Consensus error: {0}")]
    Consensus(String),

    /// Errors occurring during validation processes
    #[error("Validation error: {0}")]
    Validation(String),

    /// Errors in execution layer
    #[error("Execution error: {0}")]
    Execution(String),

    /// Errors specific to TEE (Trusted Execution Environment) operations
    #[error("TEE error: {reason} - {details}")]
    TEEError {
        reason: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Cryptography related errors
    #[error("Cryptographic error: {reason} - {details}")]
    CryptoError {
        reason: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors from the storage layer
    #[error("Storage error: {0}")]
    Storage(String),

    /// Errors in networking layer
    #[error("Network error: {0}")]
    Network(String),

    /// Errors from the API layer
    #[error("API error: {0}")]
    API(String),

    /// Errors originating in the virtual machine
    #[error("VM error: {0}")]
    VM(String),

    /// Errors related to wallet operations
    #[error("Wallet error: {0}")]
    Wallet(String),

    /// Errors in configuration handling
    #[error("Configuration error: {0}")]
    Config(String),

    /// Standard I/O errors
    #[error("I/O error: {0}")]
    IO(#[from] io::Error),

    /// Errors during serialization
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Errors during deserialization
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Errors in the Dual-DAG structure
    #[error("DAG error: {0}")]
    DAG(String),

    /// Errors in security level acceleration
    #[error("Security acceleration error: {0}")]
    SecurityAcceleration(String),

    /// Errors in BLS signature operations
    #[error("BLS signature error: {0}")]
    BLSSignature(String),

    /// Errors in multi-party computation
    #[error("MPC error: {0}")]
    MultiPartyComputation(String),

    /// Errors in transaction dependency tracking
    #[error("Dependency error: {0}")]
    Dependency(String),

    /// Errors in object versioning
    #[error("Object versioning error: {0}")]
    ObjectVersioning(String),

    /// Timeout errors
    #[error("Timeout error: {0}")]
    Timeout(String),

    /// Authentication errors
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Authorization errors
    #[error("Authorization error: {0}")]
    Authorization(String),

    /// Rate limiting errors
    #[error("Rate limit error: {0}")]
    RateLimit(String),

    /// Database consistency errors
    #[error("Database consistency error: {0}")]
    DatabaseConsistency(String),
    
    /// Unsupported feature errors
    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),

    /// Catch-all for other internal errors
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Shorthand for a Result with an AevorError
pub type Result<T> = std::result::Result<T, AevorError>;

/// Specific result type for TEE-related operations
pub type TEEResult<T> = std::result::Result<T, AevorError>;

/// Converts any standard error to an AevorError::Internal
pub fn to_internal_err<E>(err: E) -> AevorError 
where 
    E: std::error::Error
{
    AevorError::Internal(err.to_string())
}

// Extension methods for creating specific error types
impl AevorError {
    /// Create a new blockchain error
    pub fn blockchain<S: Into<String>>(msg: S) -> Self {
        AevorError::Blockchain(msg.into())
    }

    /// Create a new consensus error
    pub fn consensus<S: Into<String>>(msg: S) -> Self {
        AevorError::Consensus(msg.into())
    }

    /// Create a new validation error
    pub fn validation<S: Into<String>>(msg: S) -> Self {
        AevorError::Validation(msg.into())
    }

    /// Create a new execution error
    pub fn execution<S: Into<String>>(msg: S) -> Self {
        AevorError::Execution(msg.into())
    }

    /// Create a new TEE error
    pub fn tee<R, D, E>(reason: R, details: D, source: Option<E>) -> Self
    where
        R: Into<String>,
        D: Into<String>,
        E: std::error::Error + Send + Sync + 'static,
    {
        AevorError::TEEError {
            reason: reason.into(),
            details: details.into(),
            source: source.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }

    /// Create a new crypto error
    pub fn crypto<R, D, E>(reason: R, details: D, source: Option<E>) -> Self
    where
        R: Into<String>,
        D: Into<String>,
        E: std::error::Error + Send + Sync + 'static,
    {
        AevorError::CryptoError {
            reason: reason.into(),
            details: details.into(),
            source: source.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }

    /// Create a new storage error
    pub fn storage<S: Into<String>>(msg: S) -> Self {
        AevorError::Storage(msg.into())
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(msg: S) -> Self {
        AevorError::Network(msg.into())
    }

    /// Create a new API error
    pub fn api<S: Into<String>>(msg: S) -> Self {
        AevorError::API(msg.into())
    }

    /// Create a new VM error
    pub fn vm<S: Into<String>>(msg: S) -> Self {
        AevorError::VM(msg.into())
    }

    /// Create a new wallet error
    pub fn wallet<S: Into<String>>(msg: S) -> Self {
        AevorError::Wallet(msg.into())
    }

    /// Create a new configuration error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        AevorError::Config(msg.into())
    }

    /// Create a new serialization error
    pub fn serialization<S: Into<String>>(msg: S) -> Self {
        AevorError::Serialization(msg.into())
    }

    /// Create a new deserialization error
    pub fn deserialization<S: Into<String>>(msg: S) -> Self {
        AevorError::Deserialization(msg.into())
    }

    /// Create a new DAG error
    pub fn dag<S: Into<String>>(msg: S) -> Self {
        AevorError::DAG(msg.into())
    }

    /// Create a new security acceleration error
    pub fn security_acceleration<S: Into<String>>(msg: S) -> Self {
        AevorError::SecurityAcceleration(msg.into())
    }

    /// Create a new BLS signature error
    pub fn bls_signature<S: Into<String>>(msg: S) -> Self {
        AevorError::BLSSignature(msg.into())
    }

    /// Create a new multi-party computation error
    pub fn mpc<S: Into<String>>(msg: S) -> Self {
        AevorError::MultiPartyComputation(msg.into())
    }

    /// Create a new dependency error
    pub fn dependency<S: Into<String>>(msg: S) -> Self {
        AevorError::Dependency(msg.into())
    }

    /// Create a new object versioning error
    pub fn object_versioning<S: Into<String>>(msg: S) -> Self {
        AevorError::ObjectVersioning(msg.into())
    }

    /// Create a new timeout error
    pub fn timeout<S: Into<String>>(msg: S) -> Self {
        AevorError::Timeout(msg.into())
    }

    /// Create a new authentication error
    pub fn authentication<S: Into<String>>(msg: S) -> Self {
        AevorError::Authentication(msg.into())
    }

    /// Create a new authorization error
    pub fn authorization<S: Into<String>>(msg: S) -> Self {
        AevorError::Authorization(msg.into())
    }

    /// Create a new rate limit error
    pub fn rate_limit<S: Into<String>>(msg: S) -> Self {
        AevorError::RateLimit(msg.into())
    }

    /// Create a new database consistency error
    pub fn database_consistency<S: Into<String>>(msg: S) -> Self {
        AevorError::DatabaseConsistency(msg.into())
    }

    /// Create a new unsupported feature error
    pub fn unsupported_feature<S: Into<String>>(msg: S) -> Self {
        AevorError::UnsupportedFeature(msg.into())
    }

    /// Create a new internal error
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        AevorError::Internal(msg.into())
    }

    /// Return whether this error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            AevorError::Network(_) => true,
            AevorError::Timeout(_) => true,
            AevorError::RateLimit(_) => true,
            // Generally not retryable
            AevorError::Validation(_) => false,
            AevorError::Blockchain(_) => false,
            AevorError::Consensus(_) => false,
            AevorError::CryptoError { .. } => false,
            AevorError::TEEError { .. } => false,
            AevorError::Storage(_) => false,
            AevorError::VM(_) => false,
            AevorError::Wallet(_) => false,
            AevorError::Config(_) => false,
            AevorError::IO(_) => false,
            AevorError::Serialization(_) => false,
            AevorError::Deserialization(_) => false,
            AevorError::API(_) => false,
            AevorError::DAG(_) => false,
            AevorError::SecurityAcceleration(_) => false,
            AevorError::BLSSignature(_) => false,
            AevorError::MultiPartyComputation(_) => false,
            AevorError::Dependency(_) => false,
            AevorError::ObjectVersioning(_) => false,
            AevorError::Authentication(_) => false,
            AevorError::Authorization(_) => false,
            AevorError::DatabaseConsistency(_) => false,
            AevorError::UnsupportedFeature(_) => false,
            AevorError::Internal(_) => false,
            AevorError::Execution(_) => false,
        }
    }
}
