//! Live Taproot (BIP-340) probe — the PKCS#11 ↔ TSB bridge, end to end.
//!
//! This is the load-bearing integration proof for Securosys Taproot: a SLIP-10
//! master **created over PKCS#11** (`SecurosysBackend::derive_master_key`, a
//! persisted token object) is addressable by the **TSB REST** transport under
//! the *same* on-token label, so TSB can derive a BIP-32 leaf and Schnorr-sign
//! with it. The two transports share one key store — this confirms it against
//! the live SBX01 HSM rather than assuming it.
//!
//! Flow:
//!   1. PKCS#11: create master `emvault.v1.taproot-probe.priv` from a 64-byte seed.
//!   2. TSB: fetch the leaf pubkey at `86'/1'/0'/0/0` (for verification).
//!   3. TSB (via the wired `TaprootSigner`): BIP-340 sign a 32-byte sighash.
//!   4. Host-side `secp256k1` Schnorr verify against the leaf x-only key.
//!
//! Script-path multisig ⇒ the leaf is **untweaked**, so the signature verifies
//! directly against the derived key (no taptweak).
//!
//! Run (as root for /etc/primus, TSB creds from env):
//!   sudo -E env \
//!     SECUROSYS_PKCS11_LIB=/usr/lib/libprimusP11.so \
//!     SECUROSYS_SLOT_LABEL=YHRXBOTJLQWT \
//!     SECUROSYS_PKCS11_PASSWORD=... \
//!     SECUROSYS_TSB_URL=https://sbx-rest-api.cloudshsm.com/v1 \
//!     SECUROSYS_TSB_JWT=... \
//!     cargo run --example taproot_probe --features tsb

// Domain acronyms (PKCS#11/TSB/BIP-340/SLIP-10/SBX01) read fine unquoted in an
// example's prose; the crate's own clippy.toml doesn't apply to examples.
#![allow(clippy::doc_markdown)]

use std::str::FromStr;

use emvault_pkcs11::bitcoin::bip32::DerivationPath;
use emvault_pkcs11::bitcoin::hashes::Hash;
use emvault_pkcs11::bitcoin::secp256k1::{Message, Secp256k1};
use emvault_pkcs11::cryptoki::object::Attribute;
use emvault_pkcs11::{HsmBackend, Pkcs11Config, Pkcs11Session, SlotIdentifier, key_ops};
use emvault_securosys::SecurosysBackend;

/// Deterministic 64-byte BIP-32 seed (stable keys across runs).
const SEED: [u8; 64] = [0x2Au8; 64];
/// Bare EmVault label; the master token is `emvault.v1.taproot-probe.priv`.
const NAME: &str = "taproot-probe";
/// Leaf path (BIP-86 account 0, external chain, index 0).
const LEAF_PATH: &str = "m/86'/1'/0'/0/0";
/// TSB derivation-path form (no `m/`, apostrophe-hardened).
const LEAF_PATH_TSB: &str = "86'/1'/0'/0/0";

fn main() {
    match run() {
        Ok(()) => println!(
            "\n✅ Taproot probe PASSED — PKCS#11 master + TSB derive + BIP-340 sign + verify all green."
        ),
        Err(e) => {
            eprintln!("\n❌ Taproot probe FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let lib = std::env::var("SECUROSYS_PKCS11_LIB").map_err(|_| "SECUROSYS_PKCS11_LIB not set")?;
    let slot = std::env::var("SECUROSYS_SLOT_LABEL").map_err(|_| "SECUROSYS_SLOT_LABEL not set")?;
    let pin = std::env::var("SECUROSYS_PKCS11_PASSWORD")
        .map_err(|_| "SECUROSYS_PKCS11_PASSWORD not set")?;
    // TSB env is read by SecurosysBackend::new; fail early with a clear message.
    if std::env::var("SECUROSYS_TSB_URL").is_err() || std::env::var("SECUROSYS_TSB_JWT").is_err() {
        return Err("SECUROSYS_TSB_URL and SECUROSYS_TSB_JWT must be set".into());
    }

    let account_path = DerivationPath::from_str("m/86'/1'/0'").map_err(|e| e.to_string())?;
    let leaf_path = DerivationPath::from_str(LEAF_PATH).map_err(|e| e.to_string())?;

    let cfg = Pkcs11Config::new(
        &lib,
        SlotIdentifier::label(&slot),
        pin.clone(),
        account_path,
    );
    let session = Pkcs11Session::open(&cfg, &SlotIdentifier::label(&slot), &pin)
        .map_err(|e| format!("open session: {e}"))?;

    let priv_label = key_ops::priv_label(NAME);
    println!("master on-token label: {priv_label}");

    // Clean any prior master so the run is deterministic.
    for lbl in [key_ops::priv_label(NAME), key_ops::pub_label(NAME)] {
        if let Ok(handles) = session
            .session()
            .find_objects(&[Attribute::Label(lbl.into_bytes())])
        {
            for h in handles {
                let _ = session.session().destroy_object(h);
            }
        }
    }

    // 1) PKCS#11: create the persisted SLIP-10 master.
    let backend = SecurosysBackend::new(&lib);
    let master = backend
        .derive_master_key(session.session(), &SEED, &priv_label)
        .map_err(|e| format!("derive_master_key: {e}"))?;
    println!("PKCS#11 master created; fingerprint {}", master.fingerprint);

    // The TSB taproot signer must be present (env-configured).
    let taproot = backend
        .taproot_signer()
        .ok_or("backend has no taproot signer (TSB env not picked up?)")?;

    // 2) TSB: fetch the leaf pubkey for verification (via the same client).
    //    We reach the client through a fresh SecurosysTaprootSigner built from
    //    env so the probe can call `derived_public_key` (not on the trait).
    let tsb_signer = emvault_securosys::SecurosysTaprootSigner::from_env()
        .map_err(|e| format!("TSB from_env: {e}"))?
        .ok_or("TSB env not configured")?;
    let leaf_pub = tsb_signer
        .client()
        .derived_public_key(&priv_label, LEAF_PATH_TSB)
        .map_err(|e| format!("derived_public_key: {e}"))?;
    let (xonly, _parity) = leaf_pub.x_only_public_key();
    println!("leaf x-only pubkey: {xonly}");

    // 3) TSB: BIP-340 sign a 32-byte sighash through the wired TaprootSigner.
    let sighash: [u8; 32] =
        *emvault_pkcs11::bitcoin::hashes::sha256::Hash::hash(b"emvault taproot probe")
            .as_byte_array();
    println!("sighash: {}", hex::encode(sighash));
    let sig = taproot
        .sign_schnorr(
            session.session(),
            master.key_handle,
            NAME,
            &leaf_path,
            &sighash,
        )
        .map_err(|e| format!("sign_schnorr: {e}"))?;
    println!("BIP-340 signature: {sig}");

    // 4) Host-side Schnorr verify against the untweaked leaf key.
    let msg = Message::from_digest(sighash);
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &xonly)
        .map_err(|e| format!("schnorr verify: {e}"))?;
    println!("secp256k1 Schnorr verify: OK");

    // Tidy: destroy the persisted master (best-effort).
    for lbl in [key_ops::priv_label(NAME), key_ops::pub_label(NAME)] {
        if let Ok(handles) = session
            .session()
            .find_objects(&[Attribute::Label(lbl.into_bytes())])
        {
            for h in handles {
                let _ = session.session().destroy_object(h);
            }
        }
    }
    Ok(())
}
