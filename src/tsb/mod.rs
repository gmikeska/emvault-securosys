//! Transaction Security Broker (REST) transport — BIP-340 Schnorr for Taproot.
//!
//! Securosys exposes Schnorr signing **only** over the TSB REST API
//! (`POST /v1/synchronousSign`, `NONE_WITH_EC_SCHNORR_BIP0340`), never through
//! the PKCS#11 provider — so Taproot signing lives here rather than in
//! [`crate::pkcs11`]. Derivation is server-side and *temporary*: the sign
//! request names the key as `"<masterLabel>/<bip32 path>"` and TSB derives the
//! SLIP-10 child on the fly (no persisted leaf).
//!
//! [`SecurosysTaprootSigner`](crate::pkcs11::SecurosysTaprootSigner) implements
//! the vendor-neutral [`emvault_pkcs11::TaprootSigner`] on top of this.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use emvault_pkcs11::bitcoin::secp256k1::{PublicKey, schnorr};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

// ---------------------------------------------------------------------------
// JWT provider (refresh seam)
// ---------------------------------------------------------------------------

/// Supplies the current bearer JWT for TSB requests.
///
/// The Securosys sandbox token is effectively non-expiring, so [`StaticJwt`]
/// suffices there. A production deployment implements a provider that refreshes
/// against the Securosys Cloud Authorization Service; the [`TsbClient`] calls
/// [`current`](JwtProvider::current) on **every** request, so refresh is
/// transparent.
pub trait JwtProvider: Send + Sync + fmt::Debug {
    /// The bearer token to use for the next request.
    fn current(&self) -> SecretString;
}

/// A fixed, non-refreshing JWT (sandbox / long-lived tokens).
#[derive(Clone)]
pub struct StaticJwt(SecretString);

impl StaticJwt {
    /// Wrap a static bearer token.
    #[must_use]
    pub fn new(jwt: SecretString) -> Self {
        Self(jwt)
    }
}

impl fmt::Debug for StaticJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StaticJwt").field(&"<redacted>").finish()
    }
}

impl JwtProvider for StaticJwt {
    fn current(&self) -> SecretString {
        self.0.clone()
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Blocking client for the Securosys Transaction Security Broker REST API.
///
/// `base_url` is the versioned root, e.g.
/// `https://sbx-rest-api.cloudshsm.com/v1`.
pub struct TsbClient {
    base_url: String,
    jwt: Box<dyn JwtProvider>,
    http: reqwest::blocking::Client,
}

impl fmt::Debug for TsbClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsbClient")
            .field("base_url", &self.base_url)
            .field("jwt", &self.jwt)
            .finish_non_exhaustive()
    }
}

impl TsbClient {
    /// Create a client for a TSB versioned base URL with a JWT provider.
    ///
    /// # Errors
    /// [`TsbError::Http`] if the HTTP client can't be built.
    pub fn new(base_url: impl Into<String>, jwt: Box<dyn JwtProvider>) -> Result<Self, TsbError> {
        let http = reqwest::blocking::Client::builder().build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            jwt,
            http,
        })
    }

    /// Convenience: a client with a static (non-refreshing) JWT.
    ///
    /// # Errors
    /// [`TsbError::Http`] if the HTTP client can't be built.
    pub fn with_static_jwt(
        base_url: impl Into<String>,
        jwt: SecretString,
    ) -> Result<Self, TsbError> {
        Self::new(base_url, Box::new(StaticJwt::new(jwt)))
    }

    /// The configured TSB base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn bearer(&self) -> String {
        self.jwt.current().expose_secret().to_string()
    }

    /// BIP-340 Schnorr sign the 32-byte `sighash` with the key named
    /// `sign_key_name` (`"<masterLabel>/<bip32 path>"` for a temporary SLIP-10
    /// child). Returns the raw 64-byte `R‖s` signature.
    ///
    /// Script-path taproot ⇒ the leaf is untweaked, so no tweak/merkle data.
    ///
    /// # Errors
    /// [`TsbError::Api`] on a non-2xx response, [`TsbError::Http`] on transport
    /// failure, [`TsbError::Decode`] if the returned signature isn't 64 bytes.
    pub fn sign_bip340(
        &self,
        sign_key_name: &str,
        sighash: &[u8; 32],
    ) -> Result<[u8; 64], TsbError> {
        let body = json!({
            "signRequest": {
                "payload": B64.encode(sighash),
                "payloadType": "UNSPECIFIED",
                "signKeyName": sign_key_name,
                "signatureAlgorithm": "NONE_WITH_EC_SCHNORR_BIP0340",
            }
        });
        let resp = self
            .http
            .post(format!("{}/synchronousSign", self.base_url))
            .bearer_auth(self.bearer())
            .json(&body)
            .send()?;
        let status = resp.status();
        let text = resp.text()?;
        if !status.is_success() {
            return Err(TsbError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| TsbError::Decode(e.to_string()))?;
        let sig_b64 = v
            .get("signature")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| TsbError::Decode("response missing `signature`".into()))?;
        let raw = B64
            .decode(sig_b64)
            .map_err(|e| TsbError::Decode(format!("signature base64: {e}")))?;
        raw.try_into().map_err(|v: Vec<u8>| {
            TsbError::Decode(format!("BIP-340 signature is {} bytes, want 64", v.len()))
        })
    }

    /// Import a SLIP-10 **master** key from a BIP-39 `seed`, registered under
    /// `label` and marked TSB-derivable (`slip10:true`). This is what makes the
    /// key addressable for on-the-fly BIP-32 derivation + BIP-340 signing; a
    /// PKCS#11-created SLIP-10 key is *not* TSB-derivable. Deterministic: the
    /// same seed yields the same key (and the same PKCS#11 object), byte-identical
    /// to a native `CKM_EC_SLIP10_KEY_PAIR_GEN` master.
    ///
    /// The imported key is also usable via PKCS#11 (ECDSA/derivation), so one
    /// master serves both `SegWit` and Taproot.
    ///
    /// # Errors
    /// [`TsbError::Api`] on a non-2xx response (including "already exists" —
    /// callers that want idempotency should check the token first), or
    /// [`TsbError::Http`] on transport failure.
    pub fn import_slip10_master(&self, label: &str, seed: &[u8]) -> Result<(), TsbError> {
        let body = json!({
            "label": label,
            "algorithm": "EC",
            "curveOid": "1.3.132.0.10",
            "attributes": {
                "encrypt": false, "decrypt": false, "verify": true, "sign": true,
                "wrap": false, "unwrap": false, "derive": true,
                "bip32": false, "slip10": true,
                "extractable": false, "modifiable": true, "destroyable": true,
                "sensitive": true, "copyable": false
            },
            "seed": B64.encode(seed),
        });
        let resp = self
            .http
            .post(format!("{}/importedKey", self.base_url))
            .bearer_auth(self.bearer())
            .json(&body)
            .send()?;
        let status = resp.status();
        let text = resp.text()?;
        if !status.is_success() {
            return Err(TsbError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        Ok(())
    }

    /// Fetch the secp256k1 public key of a (temporarily-derived) key, for
    /// verification/testing. `master_label` + `path` (e.g. `"86'/1'/0'/0/0"`).
    ///
    /// # Errors
    /// [`TsbError::Api`] / [`TsbError::Http`] / [`TsbError::Decode`].
    pub fn derived_public_key(
        &self,
        master_label: &str,
        path: &str,
    ) -> Result<PublicKey, TsbError> {
        let body = json!({
            "masterKeyLabel": master_label,
            "derivationPath": path,
            "attributes": { "sign": true, "derive": true, "slip10": true, "extractable": false, "destroyable": true },
        });
        let resp = self
            .http
            .post(format!("{}/derivedKey", self.base_url))
            .bearer_auth(self.bearer())
            .json(&body)
            .send()?;
        let status = resp.status();
        let text = resp.text()?;
        if !status.is_success() {
            return Err(TsbError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| TsbError::Decode(e.to_string()))?;
        // publicKey is base64 DER SubjectPublicKeyInfo; the SEC1 point is the
        // trailing 65 bytes (0x04 ‖ x ‖ y).
        let spki_b64 = v
            .pointer("/json/publicKey")
            .or_else(|| v.get("publicKey"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| TsbError::Decode("response missing `publicKey`".into()))?;
        let spki = B64
            .decode(spki_b64)
            .map_err(|e| TsbError::Decode(format!("publicKey base64: {e}")))?;
        if spki.len() < 65 {
            return Err(TsbError::Decode("publicKey SPKI too short".into()));
        }
        let sec1 = &spki[spki.len() - 65..];
        PublicKey::from_slice(sec1).map_err(|e| TsbError::Decode(format!("secp256k1 point: {e}")))
    }
}

/// Parse a raw 64-byte BIP-340 signature.
///
/// # Errors
/// [`TsbError::Decode`] if the bytes aren't a valid Schnorr signature.
pub fn schnorr_from_bytes(raw: &[u8; 64]) -> Result<schnorr::Signature, TsbError> {
    schnorr::Signature::from_slice(raw).map_err(|e| TsbError::Decode(e.to_string()))
}

// ---------------------------------------------------------------------------
// Vendor-neutral TaprootSigner over TSB
// ---------------------------------------------------------------------------

use emvault_pkcs11::bitcoin::bip32::DerivationPath;
use emvault_pkcs11::cryptoki::object::ObjectHandle;
use emvault_pkcs11::cryptoki::session::Session;
use emvault_pkcs11::{HsmBackendError, TaprootSigner};

/// Env var naming the TSB versioned base URL (e.g.
/// `https://sbx-rest-api.cloudshsm.com/v1`).
pub const TSB_URL_ENV: &str = "SECUROSYS_TSB_URL";
/// Env var carrying the TSB bearer JWT.
pub const TSB_JWT_ENV: &str = "SECUROSYS_TSB_JWT";

/// The Securosys [`TaprootSigner`]: BIP-340 Schnorr over TSB REST.
///
/// Bridges the vendor-neutral signing contract onto [`TsbClient`]. The
/// [`Pkcs11Signer`](emvault_pkcs11::Pkcs11Signer) hands us the signer's `EmVault`
/// `label` + the full BIP-32 path to the leaf; we reconstruct the TSB
/// `signKeyName` (`"<master priv label>/<path>"`) and let TSB derive + sign the
/// leaf in one round-trip. No PKCS#11 session/handle is used — Schnorr on
/// Securosys is REST-only.
pub struct SecurosysTaprootSigner {
    tsb: TsbClient,
}

impl fmt::Debug for SecurosysTaprootSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurosysTaprootSigner")
            .field("tsb", &self.tsb)
            .finish()
    }
}

impl SecurosysTaprootSigner {
    /// Wrap a ready [`TsbClient`].
    #[must_use]
    pub fn new(tsb: TsbClient) -> Self {
        Self { tsb }
    }

    /// The underlying TSB client (for tests / pubkey lookups).
    #[must_use]
    pub fn client(&self) -> &TsbClient {
        &self.tsb
    }

    /// Build from the environment: [`TSB_URL_ENV`] + [`TSB_JWT_ENV`].
    ///
    /// Returns `Ok(None)` when **neither** is set (Taproot is simply
    /// unavailable — the backend reports no taproot capability). Returns an
    /// error if only one is set (a half-configured deployment) or the HTTP
    /// client can't be built.
    ///
    /// # Errors
    /// [`TsbError::Decode`] on partial configuration, [`TsbError::Http`] on
    /// client-build failure.
    pub fn from_env() -> Result<Option<Self>, TsbError> {
        let url = std::env::var(TSB_URL_ENV).ok().filter(|s| !s.is_empty());
        let jwt = std::env::var(TSB_JWT_ENV).ok().filter(|s| !s.is_empty());
        match (url, jwt) {
            (Some(url), Some(jwt)) => {
                let client = TsbClient::with_static_jwt(url, SecretString::from(jwt))?;
                Ok(Some(Self::new(client)))
            }
            (None, None) => Ok(None),
            (Some(_), None) => Err(TsbError::Decode(format!(
                "{TSB_URL_ENV} set but {TSB_JWT_ENV} missing"
            ))),
            (None, Some(_)) => Err(TsbError::Decode(format!(
                "{TSB_JWT_ENV} set but {TSB_URL_ENV} missing"
            ))),
        }
    }

    /// The TSB `signKeyName` for a leaf: `"<master priv label>/<bip32 path>"`.
    ///
    /// The master's on-token name is `key_ops::priv_label(label)`
    /// (`emvault.v1.<label>.priv`); TSB derives the SLIP-10 child named by the
    /// path suffix on the fly.
    fn sign_key_name(label: &str, full_path: &DerivationPath) -> String {
        let master = emvault_pkcs11::key_ops::priv_label(label);
        let path = full_path
            .into_iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("/");
        if path.is_empty() {
            master
        } else {
            format!("{master}/{path}")
        }
    }
}

impl TaprootSigner for SecurosysTaprootSigner {
    fn sign_schnorr(
        &self,
        _session: &Session,
        _key: ObjectHandle,
        label: &str,
        full_path: &DerivationPath,
        sighash: &[u8; 32],
    ) -> Result<schnorr::Signature, HsmBackendError> {
        let sign_key_name = Self::sign_key_name(label, full_path);
        let raw = self
            .tsb
            .sign_bip340(&sign_key_name, sighash)
            .map_err(|e| HsmBackendError::Signing(e.to_string()))?;
        schnorr_from_bytes(&raw).map_err(|e| HsmBackendError::Signing(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn sign_key_name_joins_master_and_path() {
        let path = DerivationPath::from_str("m/86'/1'/0'/0/5").unwrap();
        assert_eq!(
            SecurosysTaprootSigner::sign_key_name("fed-1", &path),
            "emvault.v1.fed-1.priv/86'/1'/0'/0/5"
        );
    }

    #[test]
    fn sign_key_name_empty_path_is_bare_master() {
        let path = DerivationPath::master();
        assert_eq!(
            SecurosysTaprootSigner::sign_key_name("fed-1", &path),
            "emvault.v1.fed-1.priv"
        );
    }
}

/// Errors from the TSB transport.
#[derive(Debug, thiserror::Error)]
pub enum TsbError {
    /// The TSB API returned a non-success status.
    #[error("TSB API error (HTTP {status}): {body}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Response body (may carry a Securosys `reason`/`message`).
        body: String,
    },

    /// Response decoding failure (bad base64, wrong length, missing field).
    #[error("TSB decode error: {0}")]
    Decode(String),

    /// Underlying HTTP/transport error.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}
