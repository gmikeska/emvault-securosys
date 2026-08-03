//! Transaction Security Broker (REST) transport — Schnorr / BIP-340 for Taproot.
//!
//! **Phase 3 (Taproot).** Securosys exposes Schnorr signing only over the TSB
//! REST API (`POST /v1/sign`, BIP-0340), never through the PKCS#11 provider, so
//! Taproot signing lives here rather than in the [`crate::pkcs11`] transport.
//!
//! This module is a skeleton: it establishes the client shape and auth handling
//! seam. The BIP-340 signing flow (nonce handling, key/script-path) is
//! implemented when roadmap item #3 (Taproot) is picked up.

use secrecy::SecretString;

/// Minimal client for the Securosys Transaction Security Broker REST API.
pub struct TsbClient {
    base_url: String,
    jwt: SecretString,
    http: reqwest::Client,
}

impl std::fmt::Debug for TsbClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsbClient")
            .field("base_url", &self.base_url)
            .field("jwt", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl TsbClient {
    /// Create a client for a TSB base URL (e.g. `https://sbx-rest-api.cloudshsm.com`)
    /// authenticating with the account JWT.
    #[must_use]
    pub fn new(base_url: impl Into<String>, jwt: SecretString) -> Self {
        Self {
            base_url: base_url.into(),
            jwt,
            http: reqwest::Client::new(),
        }
    }

    /// The configured TSB base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Schnorr / BIP-340 sign (Taproot). **Not yet implemented — Phase 3.**
    ///
    /// # Errors
    /// Always returns an error until the BIP-340 flow lands.
    #[allow(clippy::unused_async)] // async is the intended shape; body lands in Phase 3.
    pub async fn sign_bip340(
        &self,
        _key_label: &str,
        _sighash: &[u8; 32],
    ) -> Result<[u8; 64], TsbError> {
        // TODO(securosys, phase 3): POST /v1/sign with signatureType BIP340,
        // handle the public-nonce component, return the 64-byte Schnorr sig.
        let _ = (&self.jwt, &self.http);
        Err(TsbError::NotImplemented)
    }
}

/// Errors from the TSB transport.
#[derive(Debug, thiserror::Error)]
pub enum TsbError {
    /// The BIP-340 signing flow is not implemented yet (Phase 3).
    #[error("TSB BIP-340 signing not implemented yet (Taproot / Phase 3)")]
    NotImplemented,

    /// Underlying HTTP/transport error.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
