//! # emvault-securosys
//!
//! Securosys `CloudHSM` connector for the emvault suite.
//!
//! This crate keeps everything Securosys-specific out of `emvault-pkcs11`,
//! which stays a vendor-neutral PKCS#11 consumer. It hosts **two transports**
//! behind one Securosys facade, because Securosys splits our needs across them:
//!
//! - **PKCS#11 (Primus provider) — [`pkcs11`] module.** ECDSA multisig + BIP-32 /
//!   SLIP-10 key derivation. `emvault-pkcs11` already speaks PKCS#11, so the
//!   entire existing signer surface flows through with a small
//!   [`HsmBackend`](emvault_pkcs11::HsmBackend) implementation
//!   ([`SecurosysBackend`](pkcs11::SecurosysBackend)) plus connection
//!   provisioning. This mirrors how `emvault-dev-signer` backs the `SoftHSM` shim.
//!
//! - **TSB REST (Transaction Security Broker) — [`tsb`] module (feature `tsb`).**
//!   Schnorr / BIP-340, required for Taproot (BIP-341). Securosys exposes Schnorr
//!   **only** over the REST `/v1/sign` endpoint, never through the PKCS#11
//!   provider — so Taproot is a second transport. Deferred to Phase 3.
//!
//! ## Secrets
//! Credentials (setup password, PKCS#11 password, JWT) are sourced at runtime
//! from the environment / a secret file — never compiled in. See
//! [`config::SecurosysConfig`]. The permanent secret is **fetched automatically
//! by each provider on its first connection**; it is not a value this crate
//! stores in source.
//!
//! ## Status
//! Scaffold. The PKCS#11 vendor derive constants in
//! [`SecurosysBackend`](pkcs11::SecurosysBackend) are **placeholders** pending
//! confirmation against the installed `libprimusP11` and the Securosys docs —
//! see that type's docs for the derivation seam.

// This crate is safe except for the Securosys SLIP-10 vendor-extension FFI in
// `pkcs11::backend` (`C_GenerateKeyPair` / `C_DeriveKeyPair`), which is isolated
// and locally `#![allow(unsafe_code)]`. Everywhere else, unsafe is denied.
#![deny(unsafe_code)]

pub mod config;
pub mod error;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(feature = "tsb")]
pub mod tsb;

pub use config::SecurosysConfig;
pub use error::SecurosysError;

#[cfg(feature = "pkcs11")]
pub use pkcs11::{SecurosysBackend, pkcs11_config};

#[cfg(feature = "tsb")]
pub use tsb::{JwtProvider, SecurosysTaprootSigner, StaticJwt, TsbClient, TsbError};
