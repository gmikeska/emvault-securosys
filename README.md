# emvault-securosys

Securosys CloudHSM connector for the [emvault](https://github.com/gmikeska/emvault) suite.

Keeps everything Securosys-specific out of `emvault-pkcs11` (which stays a
vendor-neutral PKCS#11 consumer) by hosting **two transports** behind one facade:

| Transport | Module | Use | Status |
|-----------|--------|-----|--------|
| **Native PKCS#11** (Primus provider, port 2310) | `pkcs11` (default) | ECDSA multisig + BIP-32/SLIP-10 derivation — the existing emvault signer surface | scaffold |
| **TSB REST** (`/v1/sign`, BIP-0340) | `tsb` (feature) | Schnorr / Taproot (BIP-340/341) | Phase 3 stub |

Securosys splits our needs across the two: BIP-32 derivation + ECDSA are available
over PKCS#11, but **Schnorr is only on the TSB REST API** — so Taproot must be a
second transport.

## Usage (PKCS#11, once `libprimusP11.so` is installed)

```rust,ignore
use emvault_securosys::{SecurosysConfig, pkcs11_config};

let cfg = SecurosysConfig::from_env()?;       // reads SECUROSYS_* env, no secrets in code
let pkcs11 = pkcs11_config(cfg)?;             // -> emvault_pkcs11::Pkcs11Config (backend = Securosys)
// hand `pkcs11` to emvault_pkcs11::Pkcs11Signer exactly like the dev shim.
```

Config comes from the environment (see `src/config.rs`): `SECUROSYS_PKCS11_LIB`
(path to `libprimusP11.so`), `SECUROSYS_SLOT_LABEL`/`SECUROSYS_SLOT_ID`,
`SECUROSYS_PKCS11_PASSWORD`, `SECUROSYS_DERIVATION_PATH`, plus optional
`SECUROSYS_ENDPOINT` / `SECUROSYS_PKCS11_PORT`. **No secret is compiled in.** The
permanent secret is fetched by the Primus provider on first connection.

## Known open items (Phase 1)

- **Derivation seam:** Securosys derives via `C_DeriveKey` **attributes**
  (`slip10=true`), not a dedicated `CKM_BIP32` mechanism. The vendor mechanism/
  attribute constants in `src/pkcs11/backend.rs` are **placeholders** — confirm
  against the installed `libprimusP11` (`pkcs11-tool --list-mechanisms`) and the
  Securosys docs, and decide whether to map an EC-derive mechanism + a `slip10`
  derive template or extend `HsmBackend` with an attribute-driven derive hook.
- **Provider config file:** point the Primus provider at the cloud endpoint
  (`ch0x-api.cloudshsm.com:2310`) + partition; wire that from `SecurosysConfig`
  in `pkcs11::pkcs11_config` once the package layout is known.
- **Onboard within the setup-password window:** the setup password expires 7 days
  after first use; fetch the permanent secret with **every** provider (PKCS#11 and,
  for Taproot later, REST/TSB) on this host inside that window — re-issuing costs
  money + manual Securosys SO interaction.

## Runtime prerequisite (not distributed with this crate)

This crate links **nothing** at build time. The Securosys **Primus PKCS#11 provider**
(`libprimusP11.so`) is loaded at *runtime* via `cryptoki`'s `dlopen`, from the path in
`SECUROSYS_PKCS11_LIB`. The provider is Securosys proprietary software under their EULA
— **obtain it from Securosys and install it yourself**; it is never vendored, linked, or
redistributed here. Likewise the deployment-specific `primus.cfg`, `.secrets.cfg`
(permanent secret), and credentials are operator-supplied and must not be committed
(see `.gitignore`). This crate is therefore freely publishable/distributable as source.

## License
MIT OR Apache-2.0. (Applies to this crate's source only — not to the Securosys Primus
provider, which is licensed separately by Securosys.)
