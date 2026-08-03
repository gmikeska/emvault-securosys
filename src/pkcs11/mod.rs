//! Native PKCS#11 (Primus provider) transport — ECDSA + BIP-32/SLIP-10.

mod backend;
mod connect;

pub use backend::SecurosysBackend;
pub use connect::{pkcs11_config, securosys_registrar};
