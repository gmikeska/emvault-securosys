//! [`SecurosysBackend`] — the [`HsmBackend`] implementation for Securosys
//! Primus / `CloudHSM` over PKCS#11 (SLIP-10 HD derivation).
//!
//! ## Real SLIP-10 model (validated against the live SBX01 HSM)
//!
//! Securosys does HD derivation unlike `emvault-pkcs11`'s default (which assumes
//! `C_DeriveKey` + per-level child index + attribute-readback). So this backend
//! **overrides** the derivation methods with the real Securosys flow:
//! - **Master:** `C_GenerateKeyPair` with [`CKM_EC_SLIP10_KEY_PAIR_GEN`], key type
//!   [`CKK_EC_SLIP10`], the seed as the mechanism parameter, secp256k1 `CKA_EC_PARAMS`,
//!   `CKA_DERIVE=true`. Persisted as a token object (so `load()` can find it).
//! - **Child:** [`CKM_SLIP10_CHILD_DERIVE`] with `CK_SLIP10_CHILD_DERIVE_PARAMS`
//!   (the **whole path** as a `CK_ULONG` vector) via the vendor `C_DeriveKeyPair`
//!   function. Children are session objects, marked both `CKA_DERIVE` + `CKA_SIGN`
//!   so a returned handle can be an account-parent *or* a leaf-signer.
//! - **XPUB metadata:** Securosys exposes only [`CKA_SLIP10_CHAIN_CODE`] + the EC
//!   point (on the *public* key — the private key does **not** expose `CKA_EC_POINT`,
//!   confirmed live: `C_GetAttributeValue` returns `CKR_ATTRIBUTE_TYPE_INVALID`).
//!   So `read_xpub` reads the point off the paired public key (via a `priv→pub`
//!   handle map populated at derive time, with a label fallback for the persisted
//!   master) and builds a **normalized** xpub (depth/parent-fp/child = 0). That's
//!   correct for emvault: the descriptor origin comes from the master fingerprint +
//!   path, not the xpub's internal fields.
//!
//! Both create operations (`C_GenerateKeyPair`, the vendor `C_DeriveKeyPair`) use
//! raw FFI — the vendor key type / mechanism params aren't expressible through
//! `cryptoki`'s typed API. This mirrors the proven `examples/slip10_probe.rs`
//! recipe exactly. Reads/finds use `cryptoki`'s safe `Session` API.

// The only unsafe here is the isolated Securosys vendor-extension FFI below.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::mem::size_of;
use std::os::raw::c_void;
use std::path::PathBuf;
use std::ptr::addr_of_mut;
use std::sync::{Mutex, OnceLock};

use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_PTR, CK_ATTRIBUTE_TYPE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE,
    CK_MECHANISM, CK_MECHANISM_PTR, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV,
    CK_SESSION_HANDLE, CK_TRUE, CK_ULONG, CKA_CLASS, CKA_DERIVE, CKA_EC_PARAMS, CKA_EXTRACTABLE,
    CKA_KEY_TYPE, CKA_LABEL, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_VERIFY, CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY, CKR_OK,
};
use emvault_pkcs11::bitcoin::NetworkKind;
use emvault_pkcs11::bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpub};
use emvault_pkcs11::bitcoin::hashes::{Hash, hash160};
use emvault_pkcs11::bitcoin::secp256k1::PublicKey;
use emvault_pkcs11::{ECDSA_SIGNER, HsmBackend, HsmBackendError, MasterKeyHandle, SegwitSigner};

// --- Real Securosys constants (from /usr/local/primus/include/pkcs11.h) ---
/// `CKM_EC_SLIP10_KEY_PAIR_GEN` — master keypair generation (seed as mech param).
pub const CKM_EC_SLIP10_KEY_PAIR_GEN: u64 = 0x8000_0E02;
/// `CKM_SLIP10_CHILD_DERIVE` — child derivation (whole-path params).
pub const CKM_SLIP10_CHILD_DERIVE: u64 = 0x8000_0E01;
/// `CKK_EC_SLIP10` — key type for SLIP-10 EC keys (secp256k1 / secp256r1).
pub const CKK_EC_SLIP10: u64 = 0x8000_0014;
/// `CKA_SLIP10_CHAIN_CODE` — vendor attribute carrying the 32-byte chain code.
pub const CKA_SLIP10_CHAIN_CODE: u64 = 0x8000_1100;
/// secp256k1 curve OID (DER: 1.3.132.0.10).
const SECP256K1_OID: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];

/// `CK_SLIP10_CHILD_DERIVE_PARAMS` (matches the vendor header layout).
#[repr(C)]
struct CkSlip10ChildDeriveParams {
    pul_path_indexes: *mut CK_ULONG,
    ul_index_count: CK_ULONG,
}

/// Standard `C_GenerateKeyPair` (used for the SLIP-10 master keypair).
type CGenerateKeyPairFn = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

/// The vendor-extension `C_DeriveKeyPair` (whole-path SLIP-10 child derive).
type CDeriveKeyPairFn = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, // base (parent) private key
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

/// The two vendor entry points, plus the library that owns them (kept loaded).
/// Function pointers are `Send + Sync`, so the whole struct is thread-safe.
struct Ffi {
    _lib: libloading::Library,
    generate_key_pair: CGenerateKeyPairFn,
    derive_key_pair: CDeriveKeyPairFn,
}

/// Upper bound on the `priv→pub` handle map. Every `derive_path` (including the
/// per-signature leaf derivation at sign time) records a pair, but only the
/// master/account handle is ever looked up by `read_xpub` — and always right
/// after it is derived. So a bounded FIFO can never evict a still-needed entry
/// (those are the most recent), while keeping a long-running signer's map from
/// growing without limit.
const PUB_MAP_CAP: usize = 4096;

/// A bounded `priv→pub` handle map with FIFO eviction.
#[derive(Default)]
struct PubMap {
    order: std::collections::VecDeque<CK_OBJECT_HANDLE>,
    map: HashMap<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>,
}

/// `HsmBackend` for Securosys Primus / `CloudHSM`.
pub struct SecurosysBackend {
    lib_path: PathBuf,
    ffi: OnceLock<Ffi>,
    /// derived/generated private-key handle → its paired public-key handle,
    /// so `read_xpub` can read the EC point (which lives on the public key).
    /// Bounded (see [`PUB_MAP_CAP`]) so per-signature leaf derivations don't
    /// leak.
    pub_of: Mutex<PubMap>,
}

impl std::fmt::Debug for SecurosysBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurosysBackend")
            .field("lib_path", &self.lib_path)
            .finish_non_exhaustive()
    }
}

impl SecurosysBackend {
    /// Create a backend that loads the vendor entry points from `lib_path` on
    /// first use.
    #[must_use]
    pub fn new(lib_path: impl Into<PathBuf>) -> Self {
        Self {
            lib_path: lib_path.into(),
            ffi: OnceLock::new(),
            pub_of: Mutex::new(PubMap::default()),
        }
    }

    fn ffi(&self) -> Result<&Ffi, HsmBackendError> {
        if let Some(f) = self.ffi.get() {
            return Ok(f);
        }
        let lib = unsafe { libloading::Library::new(&self.lib_path) }
            .map_err(|e| HsmBackendError::Derivation(format!("dlopen Securosys lib: {e}")))?;
        let generate_key_pair: CGenerateKeyPairFn = {
            let sym: libloading::Symbol<'_, CGenerateKeyPairFn> = unsafe {
                lib.get(b"C_GenerateKeyPair")
            }
            .map_err(|e| HsmBackendError::Derivation(format!("dlsym C_GenerateKeyPair: {e}")))?;
            *sym
        };
        let derive_key_pair: CDeriveKeyPairFn = {
            let sym: libloading::Symbol<'_, CDeriveKeyPairFn> = unsafe {
                lib.get(b"C_DeriveKeyPair")
            }
            .map_err(|e| HsmBackendError::Derivation(format!("dlsym C_DeriveKeyPair: {e}")))?;
            *sym
        };
        Ok(self.ffi.get_or_init(|| Ffi {
            _lib: lib,
            generate_key_pair,
            derive_key_pair,
        }))
    }

    fn record_pair(&self, priv_h: CK_OBJECT_HANDLE, pub_h: CK_OBJECT_HANDLE) {
        if let Ok(mut m) = self.pub_of.lock()
            && m.map.insert(priv_h, pub_h).is_none()
        {
            m.order.push_back(priv_h);
            while m.order.len() > PUB_MAP_CAP {
                if let Some(old) = m.order.pop_front() {
                    m.map.remove(&old);
                }
            }
        }
    }

    /// Read the EC point (from the paired public key) + chain code (from the
    /// private key) and assemble a **normalized** account xpub (depth=0,
    /// parent-fp=0, child=0).
    ///
    /// Normalization is forced by whole-path derivation: `C_DeriveKeyPair`
    /// never materializes the intermediate parent, so the true BIP-32
    /// parent-fingerprint isn't available without an extra HSM round-trip. It is
    /// safe because those positional fields are **write-only** across emvault —
    /// descriptor keys carry an explicit origin `(master_fingerprint, path)` and
    /// derive from `public_key` + `chain_code` only; `sortedmulti` orders by
    /// derived pubkey (BIP-67); addresses and signatures are unaffected. The one
    /// place the fields surface is the *ranged* descriptor **string**, which
    /// therefore encodes `0`s for a Securosys key. That is purely cosmetic and
    /// self-consistent (this backend always normalizes), so re-deriving a stored
    /// descriptor yields the identical string — no false "drift".
    fn build_xpub(
        session: &Session,
        priv_h: ObjectHandle,
        pub_h: ObjectHandle,
    ) -> Result<Xpub, HsmBackendError> {
        let ec_point = get_ec_point(session, pub_h)?;
        let chain_code = get_vendor(session, priv_h, CKA_SLIP10_CHAIN_CODE)?;
        let public_key = parse_ec_point(&ec_point)?;
        let chain_code: [u8; 32] = chain_code
            .as_slice()
            .try_into()
            .map_err(|_| HsmBackendError::MetadataError("chain code != 32 bytes".into()))?;
        Ok(Xpub {
            network: NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Fingerprint::from([0u8; 4]),
            child_number: ChildNumber::Normal { index: 0 },
            public_key,
            chain_code: ChainCode::from(chain_code),
        })
    }

    /// Resolve the public-key handle paired with a private-key handle: the
    /// in-process map first, then (for a persisted master reloaded in a fresh
    /// process) a `CKA_LABEL`-based lookup of the `"<label>::pub"` sibling.
    fn pub_handle_for(
        &self,
        session: &Session,
        priv_h: ObjectHandle,
    ) -> Result<ObjectHandle, HsmBackendError> {
        if let Ok(m) = self.pub_of.lock()
            && let Some(&p) = m.map.get(&priv_h.handle())
        {
            return Ok(unsafe { ObjectHandle::new_from_raw(p) });
        }
        // Fallback: persisted master reloaded by label.
        let label = read_label(session, priv_h)?;
        let pub_label = pub_sibling_label(&label);
        let found = session.find_objects(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(pub_label.into_bytes()),
        ])?;
        found
            .into_iter()
            .next()
            .ok_or_else(|| HsmBackendError::MetadataError("no paired public key found".into()))
    }
}

// Securosys derives a whole path in one vendor `C_DeriveKeyPair` and doesn't
// expose the BIP-32 positional metadata as attributes, so it implements the
// signer-facing `HsmBackend` **directly** rather than `AttributeDerivation` —
// no dead accessor placeholders.
impl HsmBackend for SecurosysBackend {
    fn backend_name(&self) -> &'static str {
        "securosys"
    }

    /// SLIP-10 master keygen from `seed` (128–512 bits), persisted as a token.
    fn derive_master_key(
        &self,
        session: &Session,
        seed: &[u8],
        label: &str,
    ) -> Result<MasterKeyHandle, HsmBackendError> {
        if seed.is_empty() {
            return Err(HsmBackendError::Derivation(
                "Securosys SLIP-10 master gen needs a non-empty seed".into(),
            ));
        }
        let mut mech = CK_MECHANISM {
            mechanism: CKM_EC_SLIP10_KEY_PAIR_GEN,
            pParameter: seed.as_ptr() as *mut c_void,
            ulParameterLen: seed.len() as CK_ULONG,
        };

        let mut cls_pub: CK_OBJECT_CLASS = CKO_PUBLIC_KEY;
        let mut cls_priv: CK_OBJECT_CLASS = CKO_PRIVATE_KEY;
        let mut kt: CK_KEY_TYPE = CKK_EC_SLIP10;
        let mut oid = SECP256K1_OID;
        let (mut t, mut f): (CK_BBOOL, CK_BBOOL) = (CK_TRUE, CK_FALSE);
        let mut priv_label = label.as_bytes().to_vec();
        // Persist the paired public key under emvault's `/pub` sibling label
        // (the private key arrives as `emvault/v1/<name>/priv`), so a fresh
        // process can re-find it in `read_xpub` after `load()`.
        let mut pub_label = pub_sibling_label(label).into_bytes();

        let mut pub_tmpl = [
            attr(
                CKA_CLASS,
                addr_of_mut!(cls_pub).cast(),
                size_of::<CK_OBJECT_CLASS>(),
            ),
            attr(
                CKA_KEY_TYPE,
                addr_of_mut!(kt).cast(),
                size_of::<CK_KEY_TYPE>(),
            ),
            attr(CKA_TOKEN, addr_of_mut!(t).cast(), 1),
            attr(CKA_DERIVE, addr_of_mut!(t).cast(), 1),
            attr(CKA_VERIFY, addr_of_mut!(t).cast(), 1),
            attr(CKA_EC_PARAMS, oid.as_mut_ptr().cast(), oid.len()),
            attr(CKA_LABEL, pub_label.as_mut_ptr().cast(), pub_label.len()),
        ];
        let mut priv_tmpl = [
            attr(
                CKA_CLASS,
                addr_of_mut!(cls_priv).cast(),
                size_of::<CK_OBJECT_CLASS>(),
            ),
            attr(
                CKA_KEY_TYPE,
                addr_of_mut!(kt).cast(),
                size_of::<CK_KEY_TYPE>(),
            ),
            attr(CKA_TOKEN, addr_of_mut!(t).cast(), 1),
            attr(CKA_DERIVE, addr_of_mut!(t).cast(), 1),
            attr(CKA_SIGN, addr_of_mut!(t).cast(), 1),
            attr(CKA_SENSITIVE, addr_of_mut!(t).cast(), 1),
            attr(CKA_EXTRACTABLE, addr_of_mut!(f).cast(), 1),
            attr(CKA_LABEL, priv_label.as_mut_ptr().cast(), priv_label.len()),
        ];

        let ffi = self.ffi()?;
        let (mut m_pub, mut m_priv): (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) = (0, 0);
        let rv = unsafe {
            (ffi.generate_key_pair)(
                session.handle(),
                addr_of_mut!(mech),
                pub_tmpl.as_mut_ptr(),
                pub_tmpl.len() as CK_ULONG,
                priv_tmpl.as_mut_ptr(),
                priv_tmpl.len() as CK_ULONG,
                addr_of_mut!(m_pub),
                addr_of_mut!(m_priv),
            )
        };
        // Keep the attribute backing stores alive across the FFI call.
        drop((cls_pub, cls_priv, kt, oid, t, f, priv_label, pub_label));
        if rv != CKR_OK {
            return Err(HsmBackendError::Derivation(format!(
                "C_GenerateKeyPair failed: rv=0x{rv:x}"
            )));
        }

        let priv_h = unsafe { ObjectHandle::new_from_raw(m_priv) };
        let pub_h = unsafe { ObjectHandle::new_from_raw(m_pub) };
        self.record_pair(m_priv, m_pub);
        let xpub = Self::build_xpub(session, priv_h, pub_h)?;
        let fingerprint = fingerprint_of(&xpub.public_key);
        Ok(MasterKeyHandle {
            key_handle: priv_h,
            xpub,
            fingerprint,
        })
    }

    /// Derive the whole `path` from `parent_handle` in one `C_DeriveKeyPair` call.
    fn derive_path(
        &self,
        session: &Session,
        parent_handle: ObjectHandle,
        path: &DerivationPath,
    ) -> Result<ObjectHandle, HsmBackendError> {
        if path.as_ref().is_empty() {
            return Ok(parent_handle);
        }
        let mut indexes: Vec<CK_ULONG> = path
            .into_iter()
            .map(|c| CK_ULONG::from(u32::from(*c)))
            .collect();
        let mut params = CkSlip10ChildDeriveParams {
            pul_path_indexes: indexes.as_mut_ptr(),
            ul_index_count: indexes.len() as CK_ULONG,
        };
        let mut mech = CK_MECHANISM {
            mechanism: CKM_SLIP10_CHILD_DERIVE,
            pParameter: addr_of_mut!(params).cast::<c_void>(),
            ulParameterLen: size_of::<CkSlip10ChildDeriveParams>() as CK_ULONG,
        };

        // Child templates: session objects, usable as both parent and signer.
        let (mut t, mut f): (CK_BBOOL, CK_BBOOL) = (CK_TRUE, CK_FALSE);
        let mut pub_tmpl = [
            attr(CKA_TOKEN, addr_of_mut!(f).cast(), 1),
            attr(CKA_DERIVE, addr_of_mut!(t).cast(), 1),
            attr(CKA_VERIFY, addr_of_mut!(t).cast(), 1),
        ];
        let mut priv_tmpl = [
            attr(CKA_TOKEN, addr_of_mut!(f).cast(), 1),
            attr(CKA_DERIVE, addr_of_mut!(t).cast(), 1),
            attr(CKA_SIGN, addr_of_mut!(t).cast(), 1),
            attr(CKA_SENSITIVE, addr_of_mut!(t).cast(), 1),
            attr(CKA_EXTRACTABLE, addr_of_mut!(f).cast(), 1),
        ];

        let ffi = self.ffi()?;
        let (mut child_pub, mut child_priv): (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) = (0, 0);
        let rv = unsafe {
            (ffi.derive_key_pair)(
                session.handle(),
                addr_of_mut!(mech),
                parent_handle.handle(),
                pub_tmpl.as_mut_ptr(),
                pub_tmpl.len() as CK_ULONG,
                priv_tmpl.as_mut_ptr(),
                priv_tmpl.len() as CK_ULONG,
                addr_of_mut!(child_pub),
                addr_of_mut!(child_priv),
            )
        };
        // Keep the path buffer + bool backing alive across the FFI call.
        drop((indexes, t, f));
        if rv != CKR_OK {
            return Err(HsmBackendError::Derivation(format!(
                "C_DeriveKeyPair failed: rv=0x{rv:x}"
            )));
        }
        self.record_pair(child_priv, child_pub);
        Ok(unsafe { ObjectHandle::new_from_raw(child_priv) })
    }

    fn read_xpub(
        &self,
        session: &Session,
        key_handle: ObjectHandle,
    ) -> Result<Xpub, HsmBackendError> {
        let pub_h = self.pub_handle_for(session, key_handle)?;
        Self::build_xpub(session, key_handle, pub_h)
    }

    fn master_fingerprint(
        &self,
        session: &Session,
        key_handle: ObjectHandle,
    ) -> Result<Fingerprint, HsmBackendError> {
        let xpub = self.read_xpub(session, key_handle)?;
        Ok(fingerprint_of(&xpub.public_key))
    }

    fn segwit_signer(&self) -> Option<&dyn SegwitSigner> {
        // SegWit v0 on Securosys is stock PKCS#11 `CKM_ECDSA` (proven in
        // `securosys_live`) — identical to every other token backend.
        Some(&ECDSA_SIGNER)
    }

    // taproot_signer: default `None` for now — Taproot (BIP-340 over TSB REST)
    // lands in Phase 2.
}

// --- helpers ---

/// Map a private-key label (`emvault/v1/<name>/priv`) to its public sibling
/// (`.../pub`), matching `emvault_pkcs11::key_ops::pub_label`. Falls back to
/// appending `/pub` if the expected `/priv` suffix is absent.
fn pub_sibling_label(priv_label: &str) -> String {
    priv_label
        .strip_suffix("/priv")
        .map_or_else(|| format!("{priv_label}/pub"), |base| format!("{base}/pub"))
}

fn attr(t: CK_ATTRIBUTE_TYPE, p: *mut c_void, len: usize) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: t,
        pValue: p,
        ulValueLen: len as CK_ULONG,
    }
}

fn get_ec_point(session: &Session, h: ObjectHandle) -> Result<Vec<u8>, HsmBackendError> {
    session
        .get_attributes(h, &[AttributeType::EcPoint])?
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| HsmBackendError::MetadataError("missing CKA_EC_POINT".into()))
}

fn get_vendor(session: &Session, h: ObjectHandle, t: u64) -> Result<Vec<u8>, HsmBackendError> {
    session
        .get_attributes(h, &[AttributeType::VendorDefined(t)])?
        .into_iter()
        .find_map(|a| match a {
            Attribute::VendorDefined((ty, v)) if ty == AttributeType::VendorDefined(t) => Some(v),
            _ => None,
        })
        .ok_or_else(|| HsmBackendError::MetadataError(format!("missing vendor attr 0x{t:x}")))
}

fn read_label(session: &Session, h: ObjectHandle) -> Result<String, HsmBackendError> {
    let v = session
        .get_attributes(h, &[AttributeType::Label])?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Label(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| HsmBackendError::MetadataError("missing CKA_LABEL".into()))?;
    Ok(String::from_utf8_lossy(&v).into_owned())
}

/// Unwrap a DER OCTET STRING (`CKA_EC_POINT`) to the SEC point, then parse.
fn parse_ec_point(der: &[u8]) -> Result<PublicKey, HsmBackendError> {
    let inner = if der.first() == Some(&0x04) && der.len() >= 2 {
        let len_byte = der[1] as usize;
        if len_byte < 0x80 {
            &der[2..]
        } else {
            // long form: low 7 bits = number of length octets
            let n = len_byte & 0x7f;
            der.get(2 + n..).unwrap_or(&[])
        }
    } else {
        der
    };
    PublicKey::from_slice(inner)
        .map_err(|e| HsmBackendError::MetadataError(format!("invalid secp256k1 point: {e}")))
}

fn fingerprint_of(pk: &PublicKey) -> Fingerprint {
    let h = hash160::Hash::hash(&pk.serialize());
    let bytes = h.to_byte_array();
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&bytes[..4]);
    Fingerprint::from(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_constants() {
        let b = SecurosysBackend::new("/usr/lib/libprimusP11.so");
        assert_eq!(b.backend_name(), "securosys");
        assert_eq!(CKM_EC_SLIP10_KEY_PAIR_GEN, 0x8000_0E02);
        assert_eq!(CKM_SLIP10_CHILD_DERIVE, 0x8000_0E01);
        assert_eq!(CKK_EC_SLIP10, 0x8000_0014);
        assert_eq!(CKA_SLIP10_CHAIN_CODE, 0x8000_1100);
    }
}
