#!/usr/bin/env bash
# =============================================================================
# AEVOR — Verification Suite
#
# The canonical pre-release gate: run before tagging a devnet/testnet build or
# promoting to beta-mainnet. Verifies the finalized workspace the way CI should.
#
#   bash test_aevor.sh            # full suite
#   bash test_aevor.sh --quick    # skip clippy
#   bash test_aevor.sh --bench    # include throughput benchmarks
#
# Exit code is non-zero if any gate fails.
# =============================================================================
set -uo pipefail

AEVOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$AEVOR_DIR" || exit 1
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

QUICK=0; BENCH=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --bench) BENCH=1 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

PASS=0; FAIL=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
banner() { echo -e "\n${BLU}[$1] $2${NC}"; printf '%.0s-' {1..64}; echo; }
ok()   { echo -e "  ${GREEN}PASS${NC}  $1"; PASS=$((PASS+1)); }
bad()  { echo -e "  ${RED}FAIL${NC}  $1"; FAIL=$((FAIL+1)); }
note() { echo -e "  ${YEL}note${NC}  $1"; }

# The workspace is verified on stable.
CARGO="cargo +stable"

echo "============================================================"
echo "  AEVOR Verification Suite — $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "============================================================"

banner 1 "Environment"
if $CARGO --version >/dev/null 2>&1; then ok "$($CARGO --version)"; else bad "cargo +stable unavailable"; exit 1; fi
DISK=$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9')
if [ "${DISK:-0}" -ge 3 ]; then ok "disk headroom ${DISK}G"; else note "low disk (${DISK}G) — run 'cargo clean' if builds fail"; fi

banner 2 "Build"
if $CARGO build -p node >/dev/null 2>&1; then ok "node builds"; else bad "node build"; $CARGO build -p node 2>&1 | grep -E '^error' | head -5; fi

# Per crate, not whole-workspace: a workspace run is slow and hides which crate broke.
banner 3 "Library tests"
TOTAL_TESTS=0
for crate in aevor-core aevor-crypto aevor-storage aevor-dag aevor-execution aevor-consensus aevor-network aevor-tee aevor-wallet aevor-cli node; do
  OUT=$($CARGO test -p "$crate" --lib 2>&1)
  if echo "$OUT" | grep -q "test result: ok"; then
    N=$(echo "$OUT" | grep -oE '[0-9]+ passed' | head -1 | grep -oE '[0-9]+')
    TOTAL_TESTS=$((TOTAL_TESTS + ${N:-0}))
    ok "$crate — ${N:-0} tests"
  else
    bad "$crate library tests"
    echo "$OUT" | grep -E "^(error|FAILED|failures)" | head -5
  fi
done
ok "library tests total: $TOTAL_TESTS"

# The consensus contract: settlement, multi-lane rounds, double-spend defenses,
# attestation binding, sharding, and the live network round.
banner 4 "End-to-end (consensus contract)"
OUT=$($CARGO test -p node --test end_to_end 2>&1)
if echo "$OUT" | grep -q "test result: ok"; then
  N=$(echo "$OUT" | grep -oE '[0-9]+ passed' | head -1 | grep -oE '[0-9]+')
  ok "end-to-end — ${N:-0} tests"
else
  bad "end-to-end suite"; echo "$OUT" | grep -E "FAILED|panicked" | head -10
fi

# Named explicitly so a regression in any of them is unmistakable in the log.
banner 5 "Security invariants"
for t in \
  cross_lane_object_double_spend_is_rejected \
  cross_lane_same_account_settlement_is_rejected \
  duplicate_transaction_set_across_lanes_is_rejected \
  lane_not_forking_from_round_base_is_rejected \
  tampered_lane_balance_delta_is_rejected \
  lane_cannot_be_attributed_to_a_victim_validator \
  corruption_detection_produces_slashing_evidence
do
  if $CARGO test -p node --test end_to_end "$t" 2>&1 | grep -q "test result: ok"; then
    ok "$t"
  else
    bad "$t — SECURITY REGRESSION"
  fi
done

banner 6 "TEE attestation (all platforms)"
OUT=$($CARGO test -p aevor-tee 2>&1)
if echo "$OUT" | grep -q "test result: ok"; then
  N=$(echo "$OUT" | grep -oE '[0-9]+ passed' | head -1 | grep -oE '[0-9]+')
  ok "aevor-tee — ${N:-0} tests (Nitro / SGX / SEV-SNP / TrustZone / Keystone)"
else
  bad "aevor-tee"; echo "$OUT" | grep -E "FAILED|panicked" | head -5
fi

banner 6b "Wallet and key-management end-to-end"
BIN="target/release/aevor"
if [ ! -x "$BIN" ]; then $CARGO build -p aevor-cli --release >/dev/null 2>&1; fi
if [ -x "$BIN" ]; then
  TMPKS=$(mktemp -d)
  export AEVOR_KEYSTORE_PASSPHRASE="verification-suite-passphrase"
  if $BIN keys generate --keystore-out "$TMPKS/k.json" >/dev/null 2>&1 && [ -f "$TMPKS/k.json" ]; then
    ok "keys generate writes a keystore"
  else
    bad "keys generate"
  fi
  if grep -q argon2id "$TMPKS/k.json" 2>/dev/null; then ok "keystore is encrypted (argon2id)"; else bad "keystore encryption"; fi
  A1=$($BIN keys export --keystore "$TMPKS/k.json" 2>/dev/null)
  if [ -n "$A1" ]; then ok "keys export recovers the identity"; else bad "keys export"; fi
  if AEVOR_KEYSTORE_PASSPHRASE=wrong-passphrase $BIN keys export --keystore "$TMPKS/k.json" >/dev/null 2>&1; then
    bad "wrong passphrase was ACCEPTED — security regression"
  else
    ok "wrong passphrase rejected"
  fi
  rm -rf "$TMPKS"
else
  bad "aevor binary unavailable"
fi

if [ "$QUICK" -eq 0 ]; then
  banner 7 "Clippy (lib + tests must be zero-warning)"
  for pkg in node aevor-tee; do
    OUT=$($CARGO clippy -p "$pkg" --lib --tests 2>&1 | grep -E "^(warning|error)" | grep -v "generated .* warning")
    if [ -z "$OUT" ]; then ok "$pkg — clippy clean"; else bad "$pkg — clippy"; echo "$OUT" | head -5; fi
  done
else
  note "clippy skipped (--quick)"
fi

if [ "$BENCH" -eq 1 ]; then
  banner 8 "Throughput"
  note "wall-clock varies on shared cores; economics are deterministic and must not move"
  $CARGO test -p node --test benchmarks bench_full_pipeline -- --ignored --nocapture 2>&1 \
    | grep -E "PRODUCE|VERIFY|base fee|fee/tx" | sed 's/^/  /'
  $CARGO test -p node --test benchmarks bench_state_sharding_scaling -- --ignored --nocapture 2>&1 \
    | grep -E "^[[:space:]]+[0-9]+ \|" | sed 's/^/  /'
else
  note "benchmarks skipped (use --bench)"
fi

echo
echo "============================================================"
if [ "$FAIL" -eq 0 ]; then
  echo -e "  ${GREEN}ALL GATES PASSED${NC}  ($PASS checks)"
  echo "  Build is eligible for devnet/testnet promotion."
else
  echo -e "  ${RED}$FAIL GATE(S) FAILED${NC}  ($PASS passed)"
  echo "  Do NOT promote this build."
fi
echo "============================================================"
exit $((FAIL > 0))
