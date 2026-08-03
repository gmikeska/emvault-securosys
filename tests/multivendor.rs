//! Mixed-vendor federation e2e — the whole point of vendor-neutral fleets.
//!
//! A **Securosys HSM** cosigner and a **dev `SoftHSM`** cosigner in ONE fleet,
//! configured entirely from `EMVAULT_FLEET_*` env (a `.env` in the dev
//! environment), signing an n-of-n multisig. Because the two vendors live on
//! different tokens, concurrent signing "just works" (no single-partition
//! session contention).
//!
//! **Skipped unless `EMVAULT_FLEET_*` is present.** A ready-to-fill template is
//! in `emvault-securosys/.env.example`. Because the Securosys PIN + the `SoftHSM`
//! secret live in `/etc/primus` / the `SoftHSM` store, run as root:
//! ```bash
//! sudo -E cargo test -p emvault-securosys --test multivendor -- --nocapture
//! ```
#![cfg(feature = "pkcs11")]

use bdk_wallet::SignOptions;
use bdk_wallet::signer::TransactionSigner;
use emvault_pkcs11::bitcoin::bip32::{ChildNumber, DerivationPath};
use emvault_pkcs11::bitcoin::hashes::Hash;
use emvault_pkcs11::bitcoin::secp256k1::{Message, Secp256k1};
use emvault_pkcs11::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use emvault_pkcs11::bitcoin::{
    Amount, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute, opcodes, transaction,
};
use emvault_pkcs11::emvault_core::Signer;
use emvault_pkcs11::{BackendRegistry, Fleet};
use serial_test::serial;

/// Load the crate-root `.env` (fleet config + dev-shim `SOFTHSM2_*` /
/// `DEV_HSM_CONFIG`). Path is resolved from `CARGO_MANIFEST_DIR`, so cwd/sudo
/// don't matter.
fn load_env() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let _ = dotenvy::from_path(root.join(".env"));
}

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

#[test]
#[serial]
fn mixed_vendor_multisig_signs() {
    load_env();
    if std::env::var("EMVAULT_FLEET_0_VENDOR").is_err() {
        eprintln!(
            "EMVAULT_FLEET_* not set (see .env.example); skipping mixed_vendor_multisig_signs."
        );
        return;
    }
    let secp = Secp256k1::new();

    // Register both vendors, then build the fleet purely from env.
    let mut registry = BackendRegistry::new();
    let (tag, registrar) = emvault_securosys::pkcs11::securosys_registrar();
    registry.register(tag, registrar);
    let (tag, registrar) = emvault_dev_signer::dev_registrar();
    registry.register(tag, registrar);

    let members = Fleet::from_env(&registry).expect("Fleet::from_env");
    assert!(members.len() >= 2, "need >= 2 cosigners");
    let vendors: Vec<String> = members.iter().map(|m| m.vendor.clone()).collect();
    assert!(
        vendors.iter().any(|v| v == "securosys"),
        "fleet includes a Securosys cosigner"
    );
    assert!(
        vendors.iter().any(|v| v == "dev"),
        "fleet includes a dev cosigner"
    );
    let paths: Vec<DerivationPath> = members.iter().map(|m| m.derivation_path.clone()).collect();

    let signers = Fleet::build_signers(members).expect("Fleet::build_signers");
    let n = signers.len();

    // Concrete /0/0 leaf per cosigner (software-derived from each account xpub).
    let leaf: [ChildNumber; 2] = [
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ];
    let leaf_pks: Vec<bitcoin::secp256k1::PublicKey> = signers
        .iter()
        .map(|s| {
            s.xpub()
                .derive_pub(&secp, &leaf)
                .expect("derive leaf")
                .public_key
        })
        .collect();
    for (i, s) in signers.iter().enumerate() {
        eprintln!(
            "cosigner {i}: vendor={} fp={} leaf={}",
            vendors[i],
            s.fingerprint(),
            leaf_pks[i]
        );
    }
    assert_eq!(
        leaf_pks
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        n,
        "distinct leaf keys across vendors"
    );

    // BIP-67 sorted n-of-n over the leaves.
    let mut sorted: Vec<PublicKey> = leaf_pks.iter().map(|p| PublicKey::new(*p)).collect();
    sorted.sort_by_key(|p| p.inner.serialize());
    let mut b = ScriptBuf::builder().push_int(i64::try_from(n).unwrap());
    for p in &sorted {
        b = b.push_key(p);
    }
    let witness_script = b
        .push_int(i64::try_from(n).unwrap())
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script();

    let amount = Amount::from_sat(100_000);
    let mut psbt = spend_psbt(&witness_script, amount);
    for (i, s) in signers.iter().enumerate() {
        let full: DerivationPath = paths[i].extend(leaf);
        psbt.inputs[0]
            .bip32_derivation
            .insert(leaf_pks[i], (s.fingerprint(), full));
    }

    for s in &signers {
        s.sign_transaction(&mut psbt, &SignOptions::default(), &secp)
            .expect("cosigner sign_transaction");
    }

    assert_eq!(
        psbt.inputs[0].partial_sigs.len(),
        n,
        "every cosigner (both vendors) produced a signature"
    );
    let msg = p2wsh_sighash(&psbt, &witness_script, amount);
    for leaf in &leaf_pks {
        let spk = PublicKey::new(*leaf);
        let sig = psbt.inputs[0]
            .partial_sigs
            .get(&spk)
            .unwrap_or_else(|| panic!("no partial sig for leaf {spk}"));
        secp.verify_ecdsa(&msg, &sig.signature, leaf)
            .expect("leaf ECDSA signature verifies");
    }
    println!(
        "Mixed-vendor {n}-of-{n} OK: vendors={vendors:?} — all leaf signatures verify (Securosys + dev in one federation)."
    );
}
