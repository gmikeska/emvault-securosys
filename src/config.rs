//! Runtime configuration for the Securosys connector, sourced from the
//! environment so **no secret is ever compiled in**.
//!
//! Environment variables (all read by [`SecurosysConfig::from_env`]):
//!
//! | Var | Meaning | Example |
//! |-----|---------|---------|
//! | `SECUROSYS_PKCS11_LIB` | path to `libprimusP11.so` (falls back to `PKCS11_LIB`) | `/opt/primus/lib/libprimusP11.so` |
//! | `SECUROSYS_SLOT_LABEL` *or* `SECUROSYS_SLOT_ID` | partition/slot to open | `EmeraldFoundation` / `0` |
//! | `SECUROSYS_PKCS11_PASSWORD` | PKCS#11 user password (secret) | — |
//! | `SECUROSYS_DERIVATION_PATH` | BIP-32 path root for the federation key | `m/48'/1'/0'/2'` |
//! | `SECUROSYS_ENDPOINT` | native-API host (informational; Primus provider config carries the real target) | `ch01-api.cloudshsm.com` |
//! | `SECUROSYS_PKCS11_PORT` | native-API PKCS#11 port | `2310` |
//!
//! The endpoint/port are recorded for diagnostics; the Primus PKCS#11 provider
//! actually learns its target from its own provider config file (referenced by
//! `PRIMUS_HSM_CONFIG` / installed alongside the `.so`). Wiring that file is done
//! in [`crate::pkcs11::pkcs11_config`].

use std::path::PathBuf;

use bitcoin::bip32::DerivationPath;
use emvault_pkcs11::SlotIdentifier;
use secrecy::SecretString;

use crate::error::SecurosysError;

/// The default native-API PKCS#11 port for Securosys `CloudHSM`.
pub const DEFAULT_PKCS11_PORT: u16 = 2310;

/// Everything needed to open a Securosys PKCS#11 session, minus the permanent
/// secret (which the Primus provider fetches on first connect).
pub struct SecurosysConfig {
    /// Filesystem path to `libprimusP11.so`.
    pub library_path: PathBuf,
    /// Partition/slot to open.
    pub slot: SlotIdentifier,
    /// PKCS#11 user password. Held in [`SecretString`] so it doesn't land in
    /// logs or `Debug` output.
    pub pin: SecretString,
    /// Root BIP-32 derivation path for the federation key.
    pub derivation_path: DerivationPath,
    /// Native-API endpoint host (diagnostics only).
    pub endpoint: Option<String>,
    /// Native-API PKCS#11 port (diagnostics only).
    pub port: u16,
}

impl std::fmt::Debug for SecurosysConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the PIN.
        f.debug_struct("SecurosysConfig")
            .field("library_path", &self.library_path)
            .field("slot", &self.slot)
            .field("pin", &"<redacted>")
            .field("derivation_path", &self.derivation_path)
            .field("endpoint", &self.endpoint)
            .field("port", &self.port)
            .finish()
    }
}

impl SecurosysConfig {
    /// Load configuration from the environment (`.env` honored via `dotenvy`).
    ///
    /// # Errors
    /// Returns [`SecurosysError::MissingConfig`] if a required variable is
    /// absent, or [`SecurosysError::InvalidConfig`] / [`SecurosysError::DerivationPath`]
    /// if a value is malformed.
    pub fn from_env() -> Result<Self, SecurosysError> {
        let _ = dotenvy::dotenv();

        let library_path = std::env::var("SECUROSYS_PKCS11_LIB")
            .or_else(|_| std::env::var("PKCS11_LIB"))
            .map(PathBuf::from)
            .map_err(|_| {
                SecurosysError::MissingConfig("SECUROSYS_PKCS11_LIB (or PKCS11_LIB)".to_string())
            })?;

        let slot = if let Ok(label) = std::env::var("SECUROSYS_SLOT_LABEL") {
            SlotIdentifier::label(label)
        } else if let Ok(id) = std::env::var("SECUROSYS_SLOT_ID") {
            let id: u64 = id.parse().map_err(|e| SecurosysError::InvalidConfig {
                key: "SECUROSYS_SLOT_ID".to_string(),
                reason: format!("{e}"),
            })?;
            SlotIdentifier::slot_id(id)
        } else {
            return Err(SecurosysError::MissingConfig(
                "SECUROSYS_SLOT_LABEL or SECUROSYS_SLOT_ID".to_string(),
            ));
        };

        let pin = std::env::var("SECUROSYS_PKCS11_PASSWORD")
            .map(SecretString::from)
            .map_err(|_| SecurosysError::MissingConfig("SECUROSYS_PKCS11_PASSWORD".to_string()))?;

        let derivation_path = std::env::var("SECUROSYS_DERIVATION_PATH")
            .map_err(|_| SecurosysError::MissingConfig("SECUROSYS_DERIVATION_PATH".to_string()))?
            .parse::<DerivationPath>()?;

        let endpoint = std::env::var("SECUROSYS_ENDPOINT").ok();
        let port = match std::env::var("SECUROSYS_PKCS11_PORT") {
            Ok(p) => p.parse().map_err(|e| SecurosysError::InvalidConfig {
                key: "SECUROSYS_PKCS11_PORT".to_string(),
                reason: format!("{e}"),
            })?,
            Err(_) => DEFAULT_PKCS11_PORT,
        };

        Ok(Self {
            library_path,
            slot,
            pin,
            derivation_path,
            endpoint,
            port,
        })
    }
}
