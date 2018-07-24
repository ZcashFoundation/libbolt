# libbolt

A pure-Rust library implementation of BOLT: Blind Off-chain Lightweight Transactions.

BOLT is a system for conducting privacy-preserving off-chain payments between pairs of individual parties. BOLT is designed to provide a Layer 2 payment protocol for privacy-preserving cryptocurrencies such as Zcash, by allowing individuals to establish and use payment channels for instantaneous payments that do not require an on-chain transaction.

# WARNING

The libbolt library relies on experimental libraries and dependencies at the moment. It should not be deployed in production software yet and has not undergone a security review.

# Dependencies

* secp256k1
* libsodium
* bn
* bulletproofs

# Compile and Install

To compile the library, run `make` 

# Tests

To run libbolt tests, run `cargo test` or `make test`

# Benchmarks

To run libbolt benchmarks, run `cargo bench` or `make bench`

# Usage

To use the libbolt library, add the `libbolt` crate to your dependency file in `Cargo.toml` as follows:

```toml
[dependencies]
libbolt = "0.1.0"
```

Then add an extern declaration at the root of your crate as follows:
```rust
extern crate libbolt;
```

# API

The libbolt library provides APIs for three types of privacy-preserving payment channels:

* unidirectional payment channels (not done)
* bidirectional payment channels (done)
* third-party payments (not done) 

# Crypto Design

To build the design docs, run `make doc`.
