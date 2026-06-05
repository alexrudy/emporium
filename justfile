#!/usr/bin/env just --justfile

nightly := "nightly"
msrv := "1.90"
rust := env("RUSTUP_TOOLCHAIN", "stable")

# TLS crypto backend to select when *running* tests. Many crates pull in rustls
# via hyperdriver, which needs exactly one backend: with none selected chateau
# fails to compile, and with both (as `--all-features` enables) rustls panics at
# runtime because it cannot pick a CryptoProvider. Override per run, e.g.
# `just tls=tls-aws-lc test`.

tls := env("EMPORIUM_TLS", "tls-ring")

# Run all checks
all: fmt check-all deny clippy examples docs test machete udeps msrv
    @echo "All checks passed 🍻"

# Check for unused dependencies
udeps:
    #!/usr/bin/env sh
    export CARGO_TARGET_DIR="target/hack/"
    cargo +{{ nightly }} udeps --all --all-features
    cargo +{{ nightly }} hack udeps --all --each-feature

# Use machete to check for unused dependencies
machete:
    cargo +{{ rust }} machete

alias c := check

# Check compilation
check:
    cargo +{{ rust }} check --all-targets --all-features

# Check compilation across all features
check-all:
    cargo +{{ rust }} check --all --all-targets --all-features
    cargo +{{ rust }} hack check --all --target-dir target/hack/ --no-private --each-feature --no-dev-deps

# Run clippy
clippy:
    cargo +{{ rust }} clippy --all-targets --all-features -- -D warnings

# Check examples
examples:
    cargo +{{ rust }} check --examples --all-features

alias d := docs
alias doc := docs

# Build documentation
docs:
    cargo +{{ rust }} doc --all-features --no-deps

# Build and read documentation
read: docs
    cargo +{{ rust }} doc --all-features --no-deps --open

# Check support for MSRV
msrv:
    cargo +{{ msrv }} check --target-dir target/msrv/ --all-targets --all-features
    cargo +{{ msrv }} doc --target-dir target/msrv/ --all-features --no-deps

alias t := test

# Run the test suite with one TLS backend (see `tls`); args filter by test name.
test *args:
    just test-build {{ args }}
    just test-run {{ args }}

test-run *args:
    cargo +{{ rust }} test --workspace --features {{ tls }} {{ args }}

test-build *args:
    cargo +{{ rust }} test --workspace --features {{ tls }} --no-run {{ args }}

# Test a single TLS-dependent crate, e.g. `just test-crate oath`.
test-crate crate *args:
    cargo +{{ rust }} test -p {{ crate }} --features {{ tls }} {{ args }}

# Run coverage tests (single TLS backend, see `tls`)
coverage:
    cargo +{{ rust }} tarpaulin -o html --workspace --features {{ tls }}

alias timing := timings

# Compile with timing checks
timings:
    cargo +{{ rust }} build --all-features --timings

# Run deny checks
deny:
    cargo +{{ rust }} deny check

# Run fmt checks
fmt:
    cargo +{{ rust }} fmt --all --check
