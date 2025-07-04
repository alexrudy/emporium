#!/usr/bin/env just --justfile


nightly := "nightly"
msrv := "1.85"
rust := env("RUSTUP_TOOLCHAIN", "stable")

# Run all checks
all: fmt check-all deny clippy examples docs test machete udeps msrv
    @echo "All checks passed 🍻"

# Check for unused dependencies
udeps:
    #!/usr/bin/env sh
    export CARGO_TARGET_DIR="target/hack/"
    cargo +{{nightly}} udeps --all --all-features
    cargo +{{nightly}} hack udeps --all --each-feature

# Use machete to check for unused dependencies
machete:
    cargo +{{rust}} machete

alias c := check
# Check compilation
check:
    cargo +{{rust}} check --all-targets --all-features

# Check compilation across all features
check-all:
    cargo +{{rust}} check --all --all-targets --all-features
    cargo +{{rust}} hack check --all --target-dir target/hack/ --no-private --each-feature --no-dev-deps

# Run clippy
clippy:
    cargo +{{rust}} clippy --all-targets --all-features -- -D warnings

# Check examples
examples:
    cargo +{{rust}} check --examples --all-features

alias d := docs
alias doc := docs
# Build documentation
docs:
    cargo +{{rust}} doc --all-features --no-deps

# Build and read documentation
read: docs
    cargo +{{rust}} doc --all-features --no-deps --open

# Check support for MSRV
msrv:
    cargo +{{msrv}} check --target-dir target/msrv/ --all-targets --all-features
    cargo +{{msrv}} doc --target-dir target/msrv/ --all-features --no-deps


alias t := test
# Run cargo tests
test:
    cargo +{{rust}} test --all-features --no-run
    cargo +{{rust}} test --all-features

# Run coverage tests
coverage:
    cargo +{{rust}} tarpaulin -o html --all-features

alias timing := timings
# Compile with timing checks
timings:
    cargo +{{rust}} build --all-features --timings

# Run deny checks
deny:
    cargo +{{rust}} deny check

# Run fmt checks
fmt:
    cargo +{{rust}} fmt --all --check
