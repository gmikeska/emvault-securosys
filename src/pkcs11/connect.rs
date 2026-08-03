//! Build a ready-to-use [`Pkcs11Config`] pointed at a Securosys `CloudHSM`,
//! plus the [`securosys_registrar`] that plugs Securosys into the vendor-neutral
//! [`emvault_pkcs11::fleet`] so it can co-sign in a mixed-vendor federation.

use emvault_pkcs11::fleet::{BackendFactory, BackendRegistrar, MemberEnv};
use emvault_pkcs11::{HsmBackend, Pkcs11Config};

use crate::config::SecurosysConfig;
use crate::error::SecurosysError;
use crate::pkcs11::backend::SecurosysBackend;

/// The registry entry `("securosys", registrar)` for [`emvault_pkcs11::fleet`].
///
/// Register it before [`emvault_pkcs11::Fleet::from_env`] so members with
/// `EMVAULT_FLEET_<i>_VENDOR=securosys` get a [`SecurosysBackend`] pointed at
/// that member's `_LIB`:
///
/// ```no_run
/// use emvault_pkcs11::BackendRegistry;
/// let mut registry = BackendRegistry::new();
/// let (tag, registrar) = emvault_securosys::pkcs11::securosys_registrar();
/// registry.register(tag, registrar);
/// ```
#[must_use]
pub fn securosys_registrar() -> (&'static str, BackendRegistrar) {
    let registrar: BackendRegistrar = Box::new(|m: &MemberEnv| {
        let lib = m.library_path.clone();
        let factory: BackendFactory =
            Box::new(move || Box::new(SecurosysBackend::new(lib.clone())) as Box<dyn HsmBackend>);
        Ok(factory)
    });
    ("securosys", registrar)
}

/// Turn a [`SecurosysConfig`] into an `emvault-pkcs11` [`Pkcs11Config`] whose
/// backend is the Securosys one. Hand the result to
/// `emvault_pkcs11::Pkcs11Signer` exactly like the dev shim's config.
///
/// The Primus PKCS#11 provider learns its cloud target and credentials from its
/// own provider config file (installed alongside `libprimusP11.so` and usually
/// referenced by an env var such as `PRIMUS_HSM_CONFIG`). Wiring / generating
/// that file from [`SecurosysConfig`] is the remaining Phase-1 task once the
/// package layout is known — see the crate README.
///
/// # Errors
/// Currently infallible in practice, but returns [`SecurosysError`] to leave
/// room for provider-config validation once the Primus package lands.
pub fn pkcs11_config(cfg: SecurosysConfig) -> Result<Pkcs11Config, SecurosysError> {
    // TODO(securosys, phase 1): if a provider config file must be generated or
    // located (endpoint at `cfg.endpoint:cfg.port`, partition = `cfg.slot`),
    // do it here and/or set the provider's env var before the first session.
    log::debug!(
        "building Securosys Pkcs11Config: lib={} slot={} endpoint={:?}:{}",
        cfg.library_path.display(),
        cfg.slot,
        cfg.endpoint,
        cfg.port,
    );

    // The backend dlopens the same provider lib to reach the vendor
    // `C_DeriveKeyPair` extension, so it needs its own copy of the path.
    let backend = SecurosysBackend::new(cfg.library_path.clone());
    Ok(Pkcs11Config::new(
        cfg.library_path,
        cfg.slot,
        cfg.pin,
        cfg.derivation_path,
        Box::new(backend),
    ))
}
