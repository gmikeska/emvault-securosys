//! Phase 6 — mixed-vendor **Taproot vault spend on regtest**, end to end.
//!
//! Builds a 2-of-3 `tr(NUMS, multi_a(2, …))` federation whose cosigners are
//! **2 dev SoftHSM keys + 1 live Securosys CloudHSM key** (the topology forced
//! by Securosys single-session contention), funds its P2TR address on a local
//! regtest node, then spends it with a threshold that **requires the Securosys
//! signature** ({Securosys + 1 SoftHSM}, the 3rd SoftHSM withheld) — proving
//! the live TSB taproot-spend gate in concert with the SoftHSM signers.
//!
//! Flow: Fleet::from_env (3 cosigners) → taproot-Fixed descriptor → fund via
//! regtest RPC → build spend PSBT → sign {Securosys, dev#1} → finalize →
//! `sendrawtransaction` → mine 1 → confirm.
//!
//! Driven entirely by env (see `run_mixed_taproot_spend_regtest.sh`):
//!   EMVAULT_FLEET_* (3 cosigners, network=regtest), the dev shim's
//!   SOFTHSM2_*/DEV_HSM_CONFIG, the Securosys SECUROSYS_TSB_URL/JWT, and
//!   REGTEST_CLI + REGTEST_DATADIR + REGTEST_MINER_WALLET.

#![allow(clippy::doc_markdown)]
#![allow(clippy::too_many_lines)]

use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use emvault_core::bdk_wallet::signer::SignerOrdering;
use emvault_core::bdk_wallet::{KeychainKind, SignOptions, Wallet};
use emvault_core::{DescriptorBuilder, NetworkType, ScriptType, Signer};
use emvault_pkcs11::bitcoin::consensus::encode::deserialize_hex;
use emvault_pkcs11::bitcoin::hashes::Hash;
use emvault_pkcs11::bitcoin::secp256k1::{Message, Secp256k1};
use emvault_pkcs11::bitcoin::sighash::{Prevouts, SighashCache};
use emvault_pkcs11::bitcoin::{Amount, Network, OutPoint, Transaction, TxOut, Txid};
use emvault_pkcs11::{BackendRegistry, Fleet, NetworkPatchedSigner, Pkcs11Signer};

const NETWORK: Network = Network::Regtest;
const THRESHOLD: u32 = 2;
const FUND_BTC: &str = "0.50000000";

fn main() {
    match run() {
        Ok(txid) => println!(
            "\n✅ Mixed-vendor Taproot regtest spend PASSED — 2-of-3 tr(NUMS,multi_a) vault \
             spent by {{Securosys + 1 SoftHSM}}, confirmed on regtest. spend txid {txid}"
        ),
        Err(e) => {
            eprintln!("\n❌ Mixed-vendor Taproot regtest spend FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<Txid, String> {
    // 1. Build the 3 cosigners from EMVAULT_FLEET_* (2 dev + 1 securosys).
    let mut registry = BackendRegistry::new();
    let (tag, reg) = emvault_securosys::pkcs11::securosys_registrar();
    registry.register(tag, reg);
    let (tag, reg) = emvault_dev_signer::dev_registrar();
    registry.register(tag, reg);

    let members = Fleet::from_env(&registry).map_err(|e| format!("Fleet::from_env: {e}"))?;
    if members.len() != 3 {
        return Err(format!("expected 3 cosigners, got {}", members.len()));
    }
    let vendors: Vec<String> = members.iter().map(|m| m.vendor.clone()).collect();
    let securosys_idx = vendors
        .iter()
        .position(|v| v == "securosys")
        .ok_or("no securosys cosigner in fleet")?;
    let dev_idx = vendors
        .iter()
        .position(|v| v == "dev")
        .ok_or("no dev cosigner in fleet")?;
    println!("fleet vendors: {vendors:?}; securosys=#{securosys_idx} dev=#{dev_idx}");

    let signers = Fleet::build_signers(members).map_err(|e| format!("build_signers: {e}"))?;

    // 2. Taproot-Fixed 2-of-3 descriptor. Patch signer network kind to Regtest
    //    (keys report Mainnet kind; x-only bytes are unchanged).
    let patched: Vec<NetworkPatchedSigner> = signers
        .iter()
        .map(|s| NetworkPatchedSigner::new(s.clone(), NETWORK))
        .collect();
    let mut builder = DescriptorBuilder::new(THRESHOLD, NetworkType::Bitcoin(NETWORK))
        .script_type(ScriptType::Tr);
    for s in &patched {
        builder
            .add_signer(s as &dyn Signer)
            .map_err(|e| e.to_string())?;
    }
    let descriptor = builder.build().map_err(|e| e.to_string())?;
    println!("descriptor: {descriptor}");

    let mut wallet = Wallet::create_single(descriptor.to_string())
        .network(NETWORK)
        .create_wallet_no_persist()
        .map_err(|e| format!("wallet: {e}"))?;
    let address = wallet.reveal_next_address(KeychainKind::External).address;
    println!("vault P2TR address: {address}");
    if !address.script_pubkey().is_p2tr() {
        return Err("vault address is not P2TR".into());
    }

    // 3. Fund the vault on regtest and confirm it.
    let fund_txid = cli(&[
        "-rpcwallet=miner",
        "sendtoaddress",
        &address.to_string(),
        FUND_BTC,
    ])?;
    let fund_txid = fund_txid.trim();
    mine(1)?;
    println!("funded vault: {fund_txid} ({FUND_BTC} BTC), confirmed");

    // Pull the funding tx and locate our vout.
    let raw_hex = cli(&["getrawtransaction", fund_txid])?;
    let funding: Transaction =
        deserialize_hex(raw_hex.trim()).map_err(|e| format!("decode funding tx: {e}"))?;
    let vout = funding
        .output
        .iter()
        .position(|o| o.script_pubkey == address.script_pubkey())
        .ok_or("funding tx has no output to the vault address")?;
    let fund_value = funding.output[vout].value;
    let vout = u32::try_from(vout).map_err(|e| format!("vout index too large: {e}"))?;
    let funded_op = OutPoint::new(funding.compute_txid(), vout);

    // Make the wallet aware of the UTXO.
    wallet.apply_unconfirmed_txs(vec![(funding.clone(), 0)]);
    if wallet.get_utxo(funded_op).is_none() {
        return Err("wallet did not register the funding UTXO".into());
    }

    // 4. Register ONLY {Securosys + 1 dev} so the spend REQUIRES the Securosys
    //    signature (the 3rd cosigner is withheld — a real threshold gate).
    for idx in [securosys_idx, dev_idx] {
        let s: &Pkcs11Signer = &signers[idx];
        wallet.add_signer(
            KeychainKind::External,
            SignerOrdering::default(),
            Arc::new(s.clone()),
        );
    }

    // Spend everything (minus fee) to a fresh regtest address.
    let dest = cli(&["-rpcwallet=miner", "getnewaddress"])?;
    let dest_addr = emvault_pkcs11::bitcoin::Address::from_str(dest.trim())
        .map_err(|e| format!("dest addr: {e}"))?
        .assume_checked();

    let mut psbt = {
        let mut b = wallet.build_tx();
        b.drain_wallet()
            .drain_to(dest_addr.script_pubkey())
            .fee_absolute(Amount::from_sat(2_000));
        b.finish().map_err(|e| format!("build_tx: {e}"))?
    };

    // 5. Sign with the HSMs (hold finalization to inspect the raw sigs).
    let opts = SignOptions {
        trust_witness_utxo: true,
        try_finalize: false,
        ..Default::default()
    };
    wallet
        .sign(&mut psbt, opts)
        .map_err(|e| format!("sign: {e}"))?;

    // Verify exactly THRESHOLD valid BIP-340 tap-script sigs.
    let tap_sigs = psbt.inputs[0].tap_script_sigs.clone();
    println!("tap_script_sigs produced: {}", tap_sigs.len());
    if tap_sigs.len() != THRESHOLD as usize {
        return Err(format!(
            "expected {THRESHOLD} tap_script_sigs, got {}",
            tap_sigs.len()
        ));
    }
    let secp = Secp256k1::verification_only();
    let prevouts = [TxOut {
        value: fund_value,
        script_pubkey: address.script_pubkey(),
    }];
    for ((xonly, leaf_hash), sig) in &tap_sigs {
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                *leaf_hash,
                sig.sighash_type,
            )
            .map_err(|e| format!("recompute sighash: {e}"))?;
        let msg = Message::from_digest(sighash.to_byte_array());
        secp.verify_schnorr(&sig.signature, &msg, xonly)
            .map_err(|e| format!("BIP-340 verify failed for {xonly}: {e}"))?;
        println!("  ✓ Schnorr sig verifies for cosigner {xonly}");
    }

    // 6. Finalize, broadcast to regtest, confirm.
    let finalized = wallet
        .finalize_psbt(&mut psbt, SignOptions::default())
        .map_err(|e| format!("finalize: {e}"))?;
    if !finalized {
        return Err("PSBT did not finalize with the threshold sigs".into());
    }
    let tx = psbt.extract_tx().map_err(|e| format!("extract_tx: {e}"))?;
    let tx_hex = emvault_pkcs11::bitcoin::consensus::encode::serialize_hex(&tx);
    let spend_txid = cli(&["sendrawtransaction", &tx_hex])?;
    let spend_txid = spend_txid.trim().to_string();
    mine(1)?;

    // Confirm it landed.
    let confirmations = cli(&["getrawtransaction", &spend_txid, "1"])
        .and_then(|j| extract_confirmations(&j))
        .unwrap_or(0);
    println!("broadcast spend {spend_txid}; confirmations={confirmations}");
    if confirmations < 1 {
        return Err("spend tx not confirmed on regtest".into());
    }

    Txid::from_str(&spend_txid).map_err(|e| format!("bad spend txid: {e}"))
}

// ---- regtest RPC via bitcoin-cli ----------------------------------------

fn cli(args: &[&str]) -> Result<String, String> {
    let bin = std::env::var("REGTEST_CLI").unwrap_or_else(|_| "/home/agent/bin/bitcoin-cli".into());
    let datadir =
        std::env::var("REGTEST_DATADIR").unwrap_or_else(|_| "/home/agent/.regtest-taproot".into());
    let out = Command::new(&bin)
        .arg(format!("-datadir={datadir}"))
        .args(args)
        .output()
        .map_err(|e| format!("spawn {bin}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "bitcoin-cli {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn mine(n: u32) -> Result<(), String> {
    let addr = cli(&["-rpcwallet=miner", "getnewaddress"])?;
    cli(&[
        "-rpcwallet=miner",
        "generatetoaddress",
        &n.to_string(),
        addr.trim(),
    ])?;
    Ok(())
}

/// Extract `confirmations` from `getrawtransaction … 1` JSON without a JSON dep.
fn extract_confirmations(json: &str) -> Result<u32, String> {
    json.split("\"confirmations\":")
        .nth(1)
        .and_then(|rest| rest.trim_start().split([',', '\n', '}']).next())
        .and_then(|n| n.trim().parse::<u32>().ok())
        .ok_or_else(|| "no confirmations field".into())
}
