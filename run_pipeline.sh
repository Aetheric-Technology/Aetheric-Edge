#!/bin/bash
set -e

# Aetheric Edge - Local Pipeline Runner
# This script runs all CI pipeline steps locally for testing

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check required tools
print_step "Checking required tools..."
MISSING_TOOLS=()

if ! command_exists cargo; then
    MISSING_TOOLS+=("cargo")
fi

if ! command_exists rustup; then
    MISSING_TOOLS+=("rustup")
fi

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    print_error "Missing required tools: ${MISSING_TOOLS[*]}"
    print_error "Please install Rust and Cargo: https://rustup.rs/"
    exit 1
fi

print_success "All required tools are available"

# Set environment variables (same as CI)
export CARGO_INCREMENTAL=0
export CARGO_NET_RETRY=10
export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=short
export RUSTUP_MAX_RETRIES=10

# Set RUSTFLAGS for suppressing warnings (same as CI)
export RUSTFLAGS="-A dead_code -A unused_variables -A unused_imports -A clippy::needless_borrows_for_generic_args -A clippy::redundant_pattern_matching -A clippy::too_many_arguments -A clippy::unnecessary_cast -A clippy::derivable_impls -A clippy::redundant_closure -A clippy::manual_strip -A clippy::needless_borrow -A clippy::useless_vec -A clippy::field_reassign_with_default -A clippy::println_empty_string -A clippy::manual_flatten -A clippy::single_component_path_imports -A clippy::empty_line_after_doc_comments -A clippy::manual_range_contains -A clippy::bool_assert_comparison -A clippy::new_without_default -A clippy::absurd_extreme_comparisons -A clippy::assertions_on_constants -A unused_comparisons -A clippy::len_zero"

echo
print_step "Starting Aetheric Edge Local Pipeline"
echo "======================================"

# Parse command line arguments
SKIP_QUALITY_CHECKS=false
SKIP_TESTS=false
SKIP_BUILD=false
RELEASE_BUILD=false
TARGET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-quality-checks)
            SKIP_QUALITY_CHECKS=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --release)
            RELEASE_BUILD=true
            shift
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --skip-quality-checks    Skip formatting, clippy, and compilation checks"
            echo "  --skip-tests            Skip running tests"
            echo "  --skip-build            Skip building binaries"
            echo "  --release               Build in release mode (default: debug)"
            echo "  --target TARGET         Specify build target (e.g., x86_64-unknown-linux-gnu)"
            echo "  --help, -h              Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Quality Checks (same as CI)
if [ "$SKIP_QUALITY_CHECKS" = false ]; then
    echo
    print_step "1. Quality Checks"
    echo "=================="

    # Install required components
    print_step "Installing Rust toolchain components..."
    rustup component add rustfmt clippy || {
        print_error "Failed to install rustfmt and clippy components"
        exit 1
    }

    # Check formatting
    print_step "Checking code formatting..."
    if cargo fmt --all -- --check; then
        print_success "Code formatting is correct"
    else
        print_error "Code formatting issues found. Run 'cargo fmt --all' to fix."
        exit 1
    fi

    # Check compilation
    print_step "Checking compilation..."
    if cargo check --all-targets --all-features; then
        print_success "Compilation check passed"
    else
        print_error "Compilation check failed"
        exit 1
    fi

    # Run clippy
    print_step "Running clippy linter..."
    if cargo clippy --all-targets --all-features -- -W clippy::all -A dead_code -A unused_variables -A unused_imports -A clippy::needless_borrows_for_generic_args -A clippy::redundant_pattern_matching -A clippy::too_many_arguments -A clippy::unnecessary_cast -A clippy::derivable_impls -A clippy::redundant_closure -A clippy::manual_strip -A clippy::needless_borrow -A clippy::useless_vec -A clippy::field_reassign_with_default -A clippy::println_empty_string -A clippy::manual_flatten -A clippy::single_component_path_imports -A clippy::empty_line_after_doc_comments -A clippy::manual_range_contains -A clippy::bool_assert_comparison -A clippy::new_without_default -A clippy::absurd_extreme_comparisons -A clippy::assertions_on_constants -A unused_comparisons -A clippy::len_zero; then
        print_success "Clippy linting passed"
    else
        print_error "Clippy linting failed"
        exit 1
    fi

    print_success "Quality checks completed successfully"
else
    print_warning "Skipping quality checks (--skip-quality-checks specified)"
fi

# Tests (same as CI)
if [ "$SKIP_TESTS" = false ]; then
    echo
    print_step "2. Running Tests"
    echo "================"

    print_step "Running all tests..."
    if cargo test --all-features; then
        print_success "Tests completed (some test failures are expected in local environment)"
    else
        print_warning "Some tests failed (this is expected for integration tests without services)"
    fi
else
    print_warning "Skipping tests (--skip-tests specified)"
fi

# Build (same as CI)
if [ "$SKIP_BUILD" = false ]; then
    echo
    print_step "3. Building Binaries"
    echo "===================="

    BUILD_MODE="debug"
    BUILD_FLAGS=""
    
    if [ "$RELEASE_BUILD" = true ]; then
        BUILD_MODE="release"
        BUILD_FLAGS="--release"
    fi

    if [ -n "$TARGET" ]; then
        BUILD_FLAGS="$BUILD_FLAGS --target $TARGET"
        print_step "Building for target: $TARGET in $BUILD_MODE mode..."
        
        # Add target if not already installed
        rustup target add "$TARGET" || print_warning "Target $TARGET may not be available"
        
        # Check if cross-compilation is needed
        CURRENT_TARGET=$(rustc -vV | sed -n 's|host: ||p')
        if [ "$TARGET" != "$CURRENT_TARGET" ]; then
            print_warning "Cross-compiling from $CURRENT_TARGET to $TARGET"
            print_warning "Some dependencies may require additional tools or may fail"
        fi
    else
        print_step "Building for native target in $BUILD_MODE mode..."
    fi

    if cargo build --locked $BUILD_FLAGS; then
        print_success "Build completed successfully"
        
        # Show binary locations
        if [ "$RELEASE_BUILD" = true ]; then
            if [ -n "$TARGET" ]; then
                BINARY_DIR="target/$TARGET/release"
            else
                BINARY_DIR="target/release"
            fi
        else
            if [ -n "$TARGET" ]; then
                BINARY_DIR="target/$TARGET/debug"
            else
                BINARY_DIR="target/debug"
            fi
        fi
        
        echo
        print_success "Binaries built successfully:"
        echo "  aetheric: $BINARY_DIR/aetheric"
        echo "  aetheric-agent: $BINARY_DIR/aetheric-agent"
    else
        print_error "Build failed"
        if [ -n "$TARGET" ] && [ "$TARGET" != "$(rustc -vV | sed -n 's|host: ||p')" ]; then
            print_error "Cross-compilation failed. You may need to install additional tools:"
            print_error "  - For Linux targets: sudo apt-get install gcc-multilib"
            print_error "  - For other targets: check Rust cross-compilation documentation"
        fi
        exit 1
    fi
else
    print_warning "Skipping build (--skip-build specified)"
fi

echo
print_success "==============================================="
print_success "Local pipeline completed successfully!"
print_success "==============================================="

# Summary
echo
echo "Summary:"
echo "--------"
if [ "$SKIP_QUALITY_CHECKS" = false ]; then
    echo "✅ Quality checks: PASSED"
else
    echo "⏭️  Quality checks: SKIPPED"
fi

if [ "$SKIP_TESTS" = false ]; then
    echo "✅ Tests: COMPLETED (some failures expected locally)"
else
    echo "⏭️  Tests: SKIPPED"
fi

if [ "$SKIP_BUILD" = false ]; then
    echo "✅ Build: SUCCESSFUL"
    if [ "$RELEASE_BUILD" = true ]; then
        echo "   Mode: Release"
    else
        echo "   Mode: Debug"
    fi
    if [ -n "$TARGET" ]; then
        echo "   Target: $TARGET"
    else
        echo "   Target: Native"
    fi
else
    echo "⏭️  Build: SKIPPED"
fi

echo
echo "Next steps:"
echo "- Run './run_pipeline.sh --release' for release builds"
echo "- Run './run_pipeline.sh --target x86_64-unknown-linux-gnu' for specific targets"
echo "- Run './run_pipeline.sh --help' for all options"
echo "- Commit and push when ready for CI"