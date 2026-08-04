//! Live end-to-end tests of [`SecurosysBackend`] against a real Securosys
//! `CloudHSM` (SBX01), driven through the actual `emvault_pkcs11::Pkcs11Signer`
//! lifecycle + BDK signer path — the same surface production uses.
//!
//! **Skipped unless the HSM env is present** (so `cargo test` is green without
//! hardware). Requires:
//! - `SECUROSYS_PKCS11_LIB`   — path to `libprimusP11.so`
//! - `SECUROSYS_SLOT_LABEL`   — partition/token label (e.g. `YHRXBOTJLQWT`)
//! - `SECUROSYS_PKCS11_PASSWORD` — PKCS#11 PIN
//!
//! Run (must be root / in the `primus` group to read `/etc/primus`):
//! ```bash
//! sudo -E env SECUROSYS_PKCS11_LIB=/usr/lib/libprimusP11.so \
//!   SECUROSYS_SLOT_LABEL=YHRXBOTJLQWT SECUROSYS_PKCS11_PASSWORD=<pin> \
//!   cargo test -p emvault-securosys --test securosys_live -- --nocapture
//! ```
#![cfg(feature = "pkcs11")]

use std::str::FromStr;

use bdk_wallet::SignOptions;
use bdk_wallet::signer::TransactionSigner;
use emvault_pkcs11::bitcoin::bip32::{ChildNumber, DerivationPath};
use emvault_pkcs11::bitcoin::hashes::Hash;
use emvault_pkcs11::bitcoin::secp256k1::{Message, Secp256k1};
use emvault_pkcs11::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use emvault_pkcs11::bitcoin::{
    Amount, Network, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness, absolute, opcodes, transaction,
};
use emvault_pkcs11::cryptoki::object::Attribute;
use emvault_pkcs11::emvault_core::Signer;
use emvault_pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};
use emvault_securosys::pkcs11::SecurosysBackend;
use serial_test::serial;

/// A fixed 64-byte BIP-32 seed (deterministic keys across runs).
const SEED: [u8; 64] = [0x2Au8; 64];

fn hsm_env() -> Option<(String, String, String)> {
    let lib = std::env::var("SECUROSYS_PKCS11_LIB").ok()?;
    let slot = std::env::var("SECUROSYS_SLOT_LABEL").ok()?;
    let pin = std::env::var("SECUROSYS_PKCS11_PASSWORD").ok()?;
    Some((lib, slot, pin))
}

fn backend(lib: &str) -> Box<dyn emvault_pkcs11::HsmBackend> {
    Box::new(SecurosysBackend::new(lib))
}

fn open(lib: &str, slot: &str, pin: &str, path: &DerivationPath) -> Pkcs11Session {
    let cfg = Pkcs11Config::new(
        lib,
        SlotIdentifier::label(slot),
        pin.to_string(),
        path.clone(),
    );
    Pkcs11Session::open(&cfg, &SlotIdentifier::label(slot), pin).expect("open Securosys session")
}

/// Wipe both the private key and its `/pub` sibling for `name` so a re-run
/// starts clean (master keys are persisted token objects).
fn reset(session: &Pkcs11Session, name: &str) {
    for lbl in [key_ops::priv_label(name), key_ops::pub_label(name)] {
        if let Ok(handles) = session
            .session()
            .find_objects(&[Attribute::Label(lbl.into_bytes())])
        {
            for h in handles {
                let _ = session.session().destroy_object(h);
            }
        }
    }
}

/// A dummy P2WSH input funded at `amount` spending to a burn output, ready to
/// be signed. Returns `(psbt, witness_script, amount)`.
fn spend_psbt(witness_script: &ScriptBuf, amount: Amount) -> Psbt {
    let script_pubkey = witness_script.to_p2wsh();
    let burn: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            .parse()
            .unwrap();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: amount - Amount::from_sat(1_000),
            script_pubkey: burn.assume_checked().script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: amount,
        script_pubkey,
    });
    psbt.inputs[0].witness_script = Some(witness_script.clone());
    psbt
}

fn p2wsh_sighash(psbt: &Psbt, witness_script: &ScriptBuf, amount: Amount) -> Message {
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .p2wsh_signature_hash(0, witness_script, amount, EcdsaSighashType::All)
        .expect("p2wsh sighash");
    Message::from_digest(sighash.to_byte_array())
}

/// Test 1 — validate the three overrides through the real signer: derive a
/// master + account from a seed, read the account xpub, and sign an
/// account-level P2WSH input (relative path empty). Proves
/// `derive_master_key` + `derive_path` + `read_xpub` + ECDSA sign integrate.
#[test]
#[serial]
fn securosys_derive_and_account_level_sign() {
    let Some((lib, slot, pin)) = hsm_env() else {
        eprintln!("SECUROSYS_* env not set; skipping securosys_derive_and_account_level_sign.");
        return;
    };
    let secp = Secp256k1::new();
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();

    let session = open(&lib, &slot, &pin, &path);
    reset(&session, "sec-single");
    let signer = Pkcs11Signer::derive_from_seed(
        session,
        "sec-single",
        &path,
        Network::Testnet,
        backend(&lib),
        &SEED,
    )
    .expect("derive_from_seed");

    let account_pk = signer.xpub().public_key;
    assert!(
        account_pk.serialize().len() == 33,
        "account xpub carries a valid compressed secp256k1 point"
    );

    // 1-of-1 multisig witness script over the account key.
    let pk = PublicKey::new(account_pk);
    let witness_script = ScriptBuf::builder()
        .push_int(1)
        .push_key(&pk)
        .push_int(1)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script();
    let amount = Amount::from_sat(50_000);
    let mut psbt = spend_psbt(&witness_script, amount);
    psbt.inputs[0]
        .bip32_derivation
        .insert(account_pk, (signer.fingerprint(), path.clone()));

    signer
        .sign_transaction(&mut psbt, &SignOptions::default(), &secp)
        .expect("sign_transaction");

    assert_eq!(
        psbt.inputs[0].partial_sigs.len(),
        1,
        "exactly one partial signature inserted"
    );
    let msg = p2wsh_sighash(&psbt, &witness_script, amount);
    let (spk, sig) = psbt.inputs[0].partial_sigs.iter().next().unwrap();
    assert_eq!(spk.inner, account_pk, "signed under the account key");
    secp.verify_ecdsa(&msg, &sig.signature, &account_pk)
        .expect("account-level ECDSA signature verifies against the sighash");
    println!("Test 1 OK: account-level derive + sign + verify green on the live HSM.");
}

/// Test 2 — the crux: sign at the `/0/0` **leaf** of an account key. This
/// exercises **chained** derivation (account → leaf: a second `C_DeriveKeyPair`
/// from an already-derived key, which the probe never covered) and proves the
/// HSM's leaf matches software BIP-32 from the account xpub — the signature is
/// produced by the HSM at `path/0/0` yet verifies against the *software*-derived
/// leaf pubkey, and the partial sig is keyed under exactly that pubkey.
///
/// One session only: a single-partition multi-signer fleet would need multiple
/// concurrent sessions to the *same* token, which the Primus provider rejects
/// (it invalidates the earlier session handle). Real N-of-M security uses
/// distinct partitions — one session per token — so that contention doesn't
/// arise there; the descriptor-construction side is covered in Test 3.
#[test]
#[serial]
fn securosys_chained_leaf_sign() {
    let Some((lib, slot, pin)) = hsm_env() else {
        eprintln!("SECUROSYS_* env not set; skipping securosys_chained_leaf_sign.");
        return;
    };
    let secp = Secp256k1::new();
    let leaf: [ChildNumber; 2] = [
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ];
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();

    let session = open(&lib, &slot, &pin, &path);
    reset(&session, "sec-leaf");
    let signer = Pkcs11Signer::derive_from_seed(
        session,
        "sec-leaf",
        &path,
        Network::Testnet,
        backend(&lib),
        &SEED,
    )
    .expect("derive_from_seed");

    // Software-derive the /0/0 leaf pubkey from the account xpub.
    let leaf_pk = signer
        .xpub()
        .derive_pub(&secp, &leaf)
        .expect("derive leaf")
        .public_key;

    // 1-of-1 multisig at the leaf key.
    let pk = PublicKey::new(leaf_pk);
    let witness_script = ScriptBuf::builder()
        .push_int(1)
        .push_key(&pk)
        .push_int(1)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script();
    let amount = Amount::from_sat(80_000);
    let mut psbt = spend_psbt(&witness_script, amount);
    let full: DerivationPath = path.extend(leaf);
    psbt.inputs[0]
        .bip32_derivation
        .insert(leaf_pk, (signer.fingerprint(), full));

    signer
        .sign_transaction(&mut psbt, &SignOptions::default(), &secp)
        .expect("sign at leaf");

    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1, "one leaf signature");
    let (spk, sig) = psbt.inputs[0].partial_sigs.iter().next().unwrap();
    assert_eq!(
        spk.inner, leaf_pk,
        "HSM chained leaf pubkey == software BIP-32 leaf"
    );
    let msg = p2wsh_sighash(&psbt, &witness_script, amount);
    secp.verify_ecdsa(&msg, &sig.signature, &leaf_pk)
        .expect("chained-leaf ECDSA signature verifies");
    println!("Test 2 OK: chained account→leaf derivation + sign + verify green on the live HSM.");
}

/// Test 3 — a 3-of-3 built from three distinct account keys off the one
/// partition (distinct account paths ⇒ distinct keys). Proves the fleet forms a
/// valid sorted-multisig descriptor that round-trips through miniscript.
///
/// Sessions are opened **one at a time and dropped** before the next (see the
/// same-token contention note on Test 2), so only the descriptor keys — already
/// cached on each signer — outlive their session.
#[test]
#[serial]
fn securosys_three_account_multisig_descriptor() {
    let Some((lib, slot, pin)) = hsm_env() else {
        eprintln!("SECUROSYS_* env not set; skipping securosys_three_account_multisig_descriptor.");
        return;
    };
    let mut account_pks: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();

    for i in 0..3u32 {
        let path = DerivationPath::from_str(&format!("m/48'/1'/0'/{i}'")).unwrap();
        let name = format!("sec-d{i}");
        let session = open(&lib, &slot, &pin, &path);
        reset(&session, &name);
        let signer = Pkcs11Signer::derive_from_seed(
            session,
            &name,
            &path,
            Network::Testnet,
            backend(&lib),
            &SEED,
        )
        .expect("derive cosigner");
        account_pks.push(signer.xpub().public_key);
        // signer (and its session) drops here, before the next open().
    }

    assert_eq!(
        account_pks
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3,
        "three distinct account keys off one partition"
    );

    // Build wsh(sortedmulti(3, <3 account keys>)) and round-trip it through
    // miniscript to confirm the fleet forms a valid multisig descriptor.
    let keys: Vec<String> = account_pks
        .iter()
        .map(|apk| PublicKey::new(*apk).to_string())
        .collect();
    let descriptor = format!("wsh(sortedmulti(3,{}))", keys.join(","));
    emvault_pkcs11::miniscript::Descriptor::<
        emvault_pkcs11::miniscript::DescriptorPublicKey,
    >::from_str(&descriptor)
    .unwrap_or_else(|e| panic!("3-of-3 descriptor must round-trip ({descriptor}): {e}"));
    println!("Test 3 OK: 3 distinct account keys → valid 3-of-3 descriptor.");
}
