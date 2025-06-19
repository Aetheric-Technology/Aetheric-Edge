#!/bin/bash
# CI Debug script - runs exactly what CI runs with same environment

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}[CI-DEBUG]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

# Exact CI environment variables
export CARGO_INCREMENTAL=0
export CARGO_NET_RETRY=10
export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=short
export RUSTUP_MAX_RETRIES=10

# Exact CI RUSTFLAGS  
export RUSTFLAGS="-A dead_code -A unused_variables -A unused_imports -A clippy::needless_borrows_for_generic_args -A clippy::redundant_pattern_matching -A clippy::too_many_arguments -A clippy::unnecessary_cast -A clippy::derivable_impls -A clippy::redundant_closure -A clippy::manual_strip -A clippy::needless_borrow -A clippy::useless_vec -A clippy::field_reassign_with_default -A clippy::println_empty_string -A clippy::manual_flatten -A clippy::single_component_path_imports -A clippy::empty_line_after_doc_comments -A clippy::manual_range_contains -A clippy::bool_assert_comparison -A clippy::new_without_default -A clippy::absurd_extreme_comparisons -A clippy::assertions_on_constants -A unused_comparisons"

echo "🔍 CI Debug Mode - Exact CI Environment"
echo "======================================="

TARGET=${1:-x86_64-unknown-linux-gnu}
print_step "Testing build for target: $TARGET"

# Add target
rustup target add $TARGET 2>/dev/null || true

# Exact CI build command
print_step "Running exact CI build command..."
if cargo build --locked --release --target $TARGET; then
    print_success "CI build would succeed ✨"
else
    print_error "CI build would fail ❌"
    echo
    echo "Debugging tips:"
    echo "- Check if cross-compilation tools are needed"
    echo "- Try: sudo apt-get install gcc-multilib"
    echo "- For ARM: sudo apt-get install gcc-aarch64-linux-gnu"
    exit 1
fi