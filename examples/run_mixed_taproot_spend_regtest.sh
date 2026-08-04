#!/usr/bin/env bash
# Phase 6 runner: mixed-vendor (2 dev SoftHSM + 1 live Securosys) Taproot vault
# spend on a local regtest node. Sets up throwaway dev tokens, pulls the
# Securosys PIN/JWT from the shared creds file, and runs the example under the
# `primus` group so libprimusP11 can read /etc/primus/.secrets.cfg.
#
# Prereqs: regtest bitcoind up (REGTEST_DATADIR) with a funded `miner` wallet;
# agent in the `primus` group.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"            # emvault-securosys
ASTER="$HERE/.."
SHIM_DIR="$ASTER/libemvault_dev_hsm"
CREDS="/shared/Emerald-Foundation_SBX01_YHRXBOTJLQWT-credentials_20260803.txt"

REGTEST_DATADIR="${REGTEST_DATADIR:-/home/agent/.regtest-taproot}"
REGTEST_CLI="${REGTEST_CLI:-/home/agent/bin/bitcoin-cli}"

# --- build shim + example ---
( cd "$SHIM_DIR" && cargo build --quiet )
SHIM_SO="$SHIM_DIR/target/debug/libemvault_dev_hsm.so"
( cd "$HERE" && cargo build --quiet --example mixed_taproot_spend_regtest --features tsb )

# --- regtest preflight: node up + miner wallet funded ---
"$REGTEST_CLI" -datadir="$REGTEST_DATADIR" getblockchaininfo >/dev/null
"$REGTEST_CLI" -datadir="$REGTEST_DATADIR" loadwallet miner >/dev/null 2>&1 || true
BAL=$("$REGTEST_CLI" -datadir="$REGTEST_DATADIR" -rpcwallet=miner getbalance 2>/dev/null || echo 0)
if [ "$(printf '%.0f' "$BAL")" -lt 1 ]; then
  A=$("$REGTEST_CLI" -datadir="$REGTEST_DATADIR" -rpcwallet=miner getnewaddress)
  "$REGTEST_CLI" -datadir="$REGTEST_DATADIR" -rpcwallet=miner generatetoaddress 101 "$A" >/dev/null
fi

# --- throwaway SoftHSM store + 2 dev tokens ---
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/tokens"
cat > "$TMP/softhsm2.conf" <<EOF
directories.tokendir = $TMP/tokens
objectstore.backend = file
log.level = ERROR
EOF
SOFTHSM2_LIB="${SOFTHSM2_LIB:-/usr/lib/softhsm/libsofthsm2.so}"
export SOFTHSM2_CONF="$TMP/softhsm2.conf"
softhsm2-util --init-token --free --label dev-tap-1 --so-pin 123456 --pin 1234 >/dev/null
softhsm2-util --init-token --free --label dev-tap-2 --so-pin 123456 --pin 1234 >/dev/null
cat > "$TMP/dev-hsm.toml" <<EOF
[[slots]]
label = "dev-tap-1"
mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"

[[slots]]
label = "dev-tap-2"
mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
EOF

# --- Securosys secrets from the creds file ---
SEC_PIN="$(grep -oP 'PKCS#11 PIN:\s*\K\S+' "$CREDS")"
SEC_JWT="$(grep -oP 'JWT Token:\s*\K\S+' "$CREDS")"
[ -n "$SEC_PIN" ] && [ -n "$SEC_JWT" ] || { echo "could not read Securosys PIN/JWT from $CREDS" >&2; exit 1; }

# --- fleet: cosigner 0 = Securosys, 1+2 = dev, all at BIP-86 m/86'/1'/0' ---
SEED64="2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"

export SOFTHSM2_LIB
export DEV_HSM_CONFIG="$TMP/dev-hsm.toml"
export EMVAULT_FLEET_NETWORK="regtest"

export EMVAULT_FLEET_0_VENDOR="securosys"
export EMVAULT_FLEET_0_LABEL="mtsr-sec"
export EMVAULT_FLEET_0_LIB="/usr/lib/libprimusP11.so"
export EMVAULT_FLEET_0_SLOT="YHRXBOTJLQWT"
export EMVAULT_FLEET_0_PIN="$SEC_PIN"
export EMVAULT_FLEET_0_PATH="m/86'/1'/0'"
export EMVAULT_FLEET_0_KEY="seed:$SEED64"

export EMVAULT_FLEET_1_VENDOR="dev"
export EMVAULT_FLEET_1_LABEL="mtsr-dev1"
export EMVAULT_FLEET_1_LIB="$SHIM_SO"
export EMVAULT_FLEET_1_SLOT="dev-tap-1"
export EMVAULT_FLEET_1_PIN="1234"
export EMVAULT_FLEET_1_PATH="m/86'/1'/0'"
export EMVAULT_FLEET_1_KEY="shim"

export EMVAULT_FLEET_2_VENDOR="dev"
export EMVAULT_FLEET_2_LABEL="mtsr-dev2"
export EMVAULT_FLEET_2_LIB="$SHIM_SO"
export EMVAULT_FLEET_2_SLOT="dev-tap-2"
export EMVAULT_FLEET_2_PIN="1234"
export EMVAULT_FLEET_2_PATH="m/86'/1'/0'"
export EMVAULT_FLEET_2_KEY="shim"

# Securosys TSB (Schnorr) transport
export SECUROSYS_TSB_URL="https://sbx-rest-api.cloudshsm.com/v1"
export SECUROSYS_TSB_JWT="$SEC_JWT"

export REGTEST_CLI REGTEST_DATADIR

# Run under the primus group so libprimusP11 can read /etc/primus/.secrets.cfg.
# (No outer exec, so the temp-store cleanup trap still runs afterwards.)
# sg's -c does not honor the trailing-arg->$0 convention, so embed the path.
sg primus -c "exec '$HERE/target/debug/examples/mixed_taproot_spend_regtest'"
