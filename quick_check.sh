#!/bin/bash
# Quick check script - runs essential checks only

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

export RUSTFLAGS="-A dead_code -A unused_variables -A unused_imports"

echo "🚀 Quick Pipeline Check"
echo "======================"

print_step "1. Format check..."
if cargo fmt --all -- --check >/dev/null 2>&1; then
    print_success "Format OK"
else
    print_error "Format issues - run 'cargo fmt --all'"
    exit 1
fi

print_step "2. Compile check..."
if cargo check --all-targets --all-features >/dev/null 2>&1; then
    print_success "Compile OK"
else
    print_error "Compile failed"
    exit 1
fi

print_step "3. Release build..."
if cargo build --locked --release >/dev/null 2>&1; then
    print_success "Build OK"
else
    print_error "Build failed"
    exit 1
fi

echo
print_success "All checks passed! ✨"
print_success "Ready for commit and push"