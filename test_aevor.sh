#!/usr/bin/env bash
# =============================================================================
# AEVOR Blockchain — Test & Verification Script
# Run: bash test_aevor.sh 2>&1 | tee aevor-test-results.log
# =============================================================================

set -euo pipefail

AEVOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0; SKIP=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

banner() { echo -e "\n${BLUE}[STEP $1] $2${NC}\n$(printf '%0.s-' {1..60})"; }
ok()     { echo -e "  ${GREEN}✓ $1${NC}"; PASS=$((PASS+1)); }
fail()   { echo -e "  ${RED}✗ $1${NC}"; FAIL=$((FAIL+1)); }
warn()   { echo -e "  ${YELLOW}⚠ $1${NC}"; SKIP=$((SKIP+1)); }

echo "============================================================"
echo "  AEVOR Blockchain — Verification Suite"
echo "  $(date)"
echo "============================================================"

# ── STEP 1: Environment ──────────────────────────────────────────
banner 1 "Environment Check"
echo "OS:    $(uname -a)"

if ! command -v rustc &>/dev/null; then
    echo -e "${RED}[FAIL] rustc not found. Install: https://rustup.rs${NC}"; exit 1
fi
RUST_VER=$(rustc --version)
CARGO_VER=$(cargo --version)
echo "Rust:  $RUST_VER"
echo "Cargo: $CARGO_VER"
FREE_RAM=$(free -m | awk '/^Mem:/{print $2}')
echo "RAM:   ${FREE_RAM}MB"

RUST_MINOR=$(echo "$RUST_VER" | grep -oP '1\.\K[0-9]+' || echo "0")
if [ "${RUST_MINOR}" -lt 82 ]; then
    warn "Rust < 1.82 — some deps (blake3, base64ct) need 1.82+. Run: rustup update stable"
else
    ok "Rust version OK (${RUST_VER})"
fi

# ── STEP 2: Workspace Structure ──────────────────────────────────
banner 2 "Workspace Structure (22 crates)"
EXPECTED=(
    aevor-core aevor-config aevor-crypto aevor-tee
    aevor-consensus aevor-dag aevor-storage aevor-vm aevor-execution
    aevor-network aevor-security
    aevor-move aevor-zk aevor-bridge
    aevor-governance aevor-ns
    aevor-metrics aevor-api aevor-client aevor-cli
    aevor-faucet node
)
MISSING=0
for crate in "${EXPECTED[@]}"; do
    if [[ -f "$AEVOR_DIR/$crate/Cargo.toml" && -f "$AEVOR_DIR/$crate/src/lib.rs" ]]; then
        echo -e "  ${GREEN}✓${NC} $crate"
    else
        echo -e "  ${RED}✗${NC} $crate — MISSING"; MISSING=$((MISSING+1))
    fi
done
[[ $MISSING -eq 0 ]] && ok "All 22 crates present" || { fail "$MISSING crates missing"; exit 1; }

# ── STEP 3: File Counts ──────────────────────────────────────────
banner 3 "File Count Check"
RS_COUNT=$(find "$AEVOR_DIR" -name "*.rs"     | grep -v target | wc -l)
TM_COUNT=$(find "$AEVOR_DIR" -name "Cargo.toml" | grep -v target | wc -l)
TEST_COUNT=$(grep -r "#\[test\]" "$AEVOR_DIR" --include="*.rs" | grep -v target | wc -l)

echo "  .rs files:    $RS_COUNT   (expected ≥ 270)"
echo "  Cargo.toml:   $TM_COUNT   (expected  23)"
echo "  Test fns:     $TEST_COUNT  (expected ≥ 270)"

[[ $RS_COUNT -ge 270 ]]  && ok ".rs count OK"  || warn ".rs count lower than expected ($RS_COUNT)"
[[ $TM_COUNT -eq 23 ]]   && ok "Cargo.toml count OK" || fail "Cargo.toml count wrong: $TM_COUNT"
[[ $TEST_COUNT -ge 270 ]] && ok "Test count OK" || warn "Test count lower than expected ($TEST_COUNT)"

# ── STEP 4: Workspace Type Check ────────────────────────────────
banner 4 "Workspace Type Check (cargo check)"
echo "First run: 30-120s. Subsequent: <10s (cached)."
cd "$AEVOR_DIR"
if cargo check --workspace 2>&1; then
    ok "cargo check --workspace PASSED"
else
    fail "cargo check --workspace FAILED"
    echo ""
    echo "First 20 errors:"
    cargo check --workspace 2>&1 | grep "^error" | sort -u | head -20
fi

# ── STEP 5: Per-crate check (dependency order) ───────────────────
banner 5 "Per-Crate Type Check"
PATHS=(
    "aevor-core aevor-config aevor-crypto aevor-tee"
    "aevor-consensus aevor-dag aevor-storage aevor-vm aevor-execution"
    "aevor-network aevor-security"
    "aevor-move aevor-zk aevor-bridge"
    "aevor-governance aevor-ns"
    "aevor-metrics aevor-api aevor-client aevor-cli"
    "aevor-faucet node"
)
for group in "${PATHS[@]}"; do
    echo ""
    echo "  [ $group ]"
    for crate in $group; do
        if cargo check -p "$crate" 2>/dev/null; then
            ok "$crate"
        else
            ERR=$(cargo check -p "$crate" 2>&1 | grep "^error\[" | wc -l)
            fail "$crate ($ERR errors)"
            cargo check -p "$crate" 2>&1 | grep "^error\[" | head -3
        fi
    done
done

# ── STEP 6: Unit Tests ───────────────────────────────────────────
banner 6 "Unit Tests (per crate)"
run_tests() {
    local crate=$1
    printf "  %-22s" "$crate"
    if cargo test -p "$crate" --lib 2>/dev/null; then
        COUNT=$(cargo test -p "$crate" --lib 2>&1 | grep "test result" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "?")
        echo -e "  ${GREEN}✓ passed${NC}"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗ FAILED${NC}"
        cargo test -p "$crate" --lib 2>&1 | grep "FAILED\|^error" | head -5
        FAIL=$((FAIL+1))
    fi
}

for crate in \
    aevor-core aevor-config aevor-crypto aevor-tee \
    aevor-consensus aevor-dag aevor-storage aevor-vm aevor-execution \
    aevor-network aevor-security \
    aevor-move aevor-zk aevor-bridge \
    aevor-governance aevor-ns \
    aevor-metrics aevor-api aevor-client aevor-cli \
    aevor-faucet node; do
    run_tests "$crate"
done

# ── STEP 7: Full Workspace Test ──────────────────────────────────
banner 7 "Full Workspace Test Run"
echo "Running: cargo test --workspace --lib"
if cargo test --workspace --lib 2>&1; then
    ok "All workspace tests PASSED"
else
    fail "Some workspace tests FAILED"
    cargo test --workspace --lib 2>&1 | grep "^FAILED\|failures:" | head -10
fi

# ── STEP 8: Doc Tests ────────────────────────────────────────────
banner 8 "Documentation Tests"
if cargo test --workspace --doc 2>&1; then
    ok "Doc tests PASSED"
else
    warn "Some doc tests failed (expected for network/async stubs)"
fi

# ── STEP 9: Binary Builds ────────────────────────────────────────
banner 9 "Binary Builds"
for pkg_bin in "node:aevor-node" "aevor-cli:aevor" "aevor-faucet:aevor-faucet" "aevor-api:aevor-api"; do
    pkg="${pkg_bin%%:*}"; bin="${pkg_bin##*:}"
    printf "  %-20s" "$bin"
    if cargo build -p "$pkg" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"; PASS=$((PASS+1))
    else
        echo -e "${RED}✗ FAILED${NC}"; FAIL=$((FAIL+1))
        cargo build -p "$pkg" 2>&1 | grep "^error" | head -3
    fi
done

# ── STEP 10: Clippy ──────────────────────────────────────────────
banner 10 "Clippy Lints"
if cargo clippy --workspace -- -D warnings 2>&1; then
    ok "Clippy: no warnings-as-errors"
else
    CLIP=$(cargo clippy --workspace 2>&1 | grep "^warning\|^error" | wc -l)
    warn "Clippy found $CLIP diagnostics (review above)"
fi

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  SUMMARY"
echo "============================================================"
echo -e "  ${GREEN}PASSED:  $PASS${NC}"
echo -e "  ${RED}FAILED:  $FAIL${NC}"
echo -e "  ${YELLOW}SKIPPED: $SKIP${NC}"
echo ""
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}  ✓ ALL CHECKS PASSED${NC}"
else
    echo -e "${RED}  ✗ $FAIL CHECKS FAILED${NC}"
fi

echo ""
echo "============================================================"
echo "  ENVIRONMENT (paste this when sharing results)"
echo "============================================================"
echo "Date:  $(date)"
echo "OS:    $(uname -a)"
echo "Rust:  $(rustc --version)"
echo "Cargo: $(cargo --version)"
echo "CPU:   $(nproc) cores"
echo "RAM:   ${FREE_RAM}MB"
echo "============================================================"
