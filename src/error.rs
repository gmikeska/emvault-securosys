//! Error types for the Securosys connector.

use thiserror::Error;

/// Errors produced while configuring or connecting to a Securosys `CloudHSM`.
#[derive(Debug, Error)]
pub enum SecurosysError {
    /// A required configuration value was missing from the environment.
    #[error("missing Securosys config: {0}")]
    MissingConfig(String),

    /// A configuration value was present but malformed.
    #[error("invalid Securosys config for `{key}`: {reason}")]
    InvalidConfig {
        /// The offending config key.
        key: String,
        /// Why it was rejected.
        reason: String,
    },

    /// Error surfaced from `emvault-pkcs11` while building the config/signer.
    #[error(transparent)]
    Pkcs11(#[from] emvault_pkcs11::Pkcs11Error),

    /// Error parsing a BIP-32 derivation path.
    #[error("invalid derivation path: {0}")]
    DerivationPath(#[from] bitcoin::bip32::Error),
}
