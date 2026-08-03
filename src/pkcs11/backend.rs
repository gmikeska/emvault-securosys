//! [`SecurosysBackend`] — the [`HsmBackend`] implementation for Securosys
//! Primus / `CloudHSM` over PKCS#11.
//!
//! ## Real SLIP-10 model (confirmed against the installed provider header + live HSM)
//!
//! Constants below are the **real** Securosys values, read from
//! `/usr/local/primus/include/pkcs11.h` and cross-checked against the live SBX01
//! HSM (`pkcs11-tool --list-mechanisms` shows `mechtype-0x80000E01` with the
//! derive flag). They are **not** placeholders anymore.
//!
//! Securosys does hierarchical-deterministic derivation like this:
//! - **Master:** `C_GenerateKeyPair` with [`CKM_EC_SLIP10_KEY_PAIR_GEN`] (key type
//!   [`CKK_EC_SLIP10`]), the BIP-39 seed passed as the mechanism parameter,
//!   `CKA_DERIVE = true`. Produces an EC **key pair** (secp256k1 for Bitcoin).
//! - **Child:** [`CKM_SLIP10_CHILD_DERIVE`] with `CK_SLIP10_CHILD_DERIVE_PARAMS`
//!   = the **whole derivation path at once** (a vector of `CK_ULONG` levels,
//!   hardened ≥ `0x80000000`). Securosys ships a `C_DeriveKeyPair` *vendor
//!   extension* for this; the same mechanism is also usable with standard
//!   `C_DeriveKey` (it carries the derive flag).
//! - **Chain code:** read back via [`CKA_SLIP10_CHAIN_CODE`].
//!
//! ## ⚠️ Why the trait's default derive path does NOT work as-is for Securosys
//!
//! `emvault-pkcs11::HsmBackend` models derivation as: seed → **master via
//! `C_DeriveKey`** (seed in `pParameter` + a base secret key), then children
//! **one BIP-32 level per call** (single 4-byte child index), with the default
//! [`HsmBackend::read_xpub`] reading vendor attributes for chain-code / depth /
//! parent-fingerprint / child-index. That fits the dev shim, not Securosys:
//!
//! 1. Securosys master is `C_GenerateKeyPair` (a *pair*), not `C_DeriveKey` on a
//!    secret. → `derive_master_key` must be **overridden**.
//! 2. Securosys derives the **whole path in one call** (not per-level), via
//!    `CK_SLIP10_CHILD_DERIVE_PARAMS`. → `derive_child_key` must be **overridden**.
//! 3. Securosys exposes only `CKA_SLIP10_CHAIN_CODE`; depth / parent-fp /
//!    child-index are not vendor attributes (compute host-side). → `read_xpub`
//!    must be **overridden**.
//!
//! So the mechanism/attribute accessors below are pinned to the real values, but
//! `SecurosysBackend` still needs the three overrides (Phase-1 follow-up; see the
//! crate README / integration plan). Until then the default derive path will not
//! produce correct results against Securosys — the accessors alone are not enough.

use cryptoki::mechanism::MechanismType;
use cryptoki::object::AttributeType;
use emvault_pkcs11::HsmBackend;

// --- Real Securosys constants (from /usr/local/primus/include/pkcs11.h) ---
/// `CKM_EC_SLIP10_KEY_PAIR_GEN` — master keypair generation (seed as mech param).
pub const CKM_EC_SLIP10_KEY_PAIR_GEN: u64 = 0x8000_0E02;
/// `CKM_SLIP10_CHILD_DERIVE` — child derivation (whole-path params).
pub const CKM_SLIP10_CHILD_DERIVE: u64 = 0x8000_0E01;
/// `CKK_EC_SLIP10` — key type for SLIP-10 EC keys (secp256k1 / secp256r1).
/// Consumed by the forthcoming `derive_master_key` override (the master-keypair
/// template sets this key type); referenced in tests until then.
#[allow(dead_code)]
pub const CKK_EC_SLIP10: u64 = 0x8000_0014;
/// `CKA_SLIP10_CHAIN_CODE` — vendor attribute carrying the 32-byte chain code.
pub const CKA_SLIP10_CHAIN_CODE: u64 = 0x8000_1100;

/// `HsmBackend` for Securosys Primus / `CloudHSM`.
///
/// Session open / login / key lookup / **ECDSA signing** / close inherit the
/// vendor-neutral defaults from [`HsmBackend`] and work as-is. The **derivation**
/// methods (`derive_master_key` / `derive_child_key` / `read_xpub`) still need
/// Securosys-native overrides — see the module docs' SLIP-10 model + mismatch
/// notes. The accessors here return the real Securosys mechanism/attribute IDs.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurosysBackend;

impl HsmBackend for SecurosysBackend {
    fn master_derive_mechanism(&self) -> MechanismType {
        // Real: CKM_EC_SLIP10_KEY_PAIR_GEN. Note Securosys uses this with
        // C_GenerateKeyPair, so the trait's default (C_DeriveKey) needs override.
        MechanismType::new_vendor_defined(CKM_EC_SLIP10_KEY_PAIR_GEN)
            .expect("CKM_EC_SLIP10_KEY_PAIR_GEN is in the vendor-defined range")
    }

    fn child_derive_mechanism(&self) -> MechanismType {
        // Real: CKM_SLIP10_CHILD_DERIVE (whole-path params, not per-level index).
        MechanismType::new_vendor_defined(CKM_SLIP10_CHILD_DERIVE)
            .expect("CKM_SLIP10_CHILD_DERIVE is in the vendor-defined range")
    }

    fn chain_code_attribute(&self) -> AttributeType {
        // Real: CKA_SLIP10_CHAIN_CODE.
        AttributeType::VendorDefined(CKA_SLIP10_CHAIN_CODE)
    }

    // --- Securosys does NOT expose these as vendor attributes; the read_xpub
    // --- override computes them host-side. Values here are inert (unused once
    // --- read_xpub is overridden) and must not be trusted as real Securosys IDs.
    fn depth_attribute(&self) -> AttributeType {
        // TODO(securosys, phase 1): not exposed by Securosys — remove once
        // read_xpub is overridden. Kept only to satisfy the trait.
        AttributeType::VendorDefined(0x8000_5F02)
    }

    fn parent_fingerprint_attribute(&self) -> AttributeType {
        // TODO(securosys, phase 1): not exposed by Securosys (compute host-side).
        AttributeType::VendorDefined(0x8000_5F03)
    }

    fn child_index_attribute(&self) -> AttributeType {
        // TODO(securosys, phase 1): not exposed by Securosys (compute host-side).
        AttributeType::VendorDefined(0x8000_5F04)
    }

    fn backend_name(&self) -> &'static str {
        "securosys"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_securosys() {
        assert_eq!(SecurosysBackend.backend_name(), "securosys");
    }

    #[test]
    fn real_slip10_constants_match_the_vendor_header() {
        // Guards the values read from /usr/local/primus/include/pkcs11.h.
        assert_eq!(CKM_EC_SLIP10_KEY_PAIR_GEN, 0x8000_0E02);
        assert_eq!(CKM_SLIP10_CHILD_DERIVE, 0x8000_0E01);
        assert_eq!(CKK_EC_SLIP10, 0x8000_0014);
        assert_eq!(CKA_SLIP10_CHAIN_CODE, 0x8000_1100);
        // And they're all in the vendor-defined range.
        assert!(MechanismType::new_vendor_defined(CKM_EC_SLIP10_KEY_PAIR_GEN).is_ok());
        assert!(MechanismType::new_vendor_defined(CKM_SLIP10_CHILD_DERIVE).is_ok());
    }
}
