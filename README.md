# Parser for Xbox Executables (XBE)

[![crates.io](https://img.shields.io/crates/v/xbe.svg)](https://crates.io/crates/xbe)
[![docs.rs](https://docs.rs/xbe/badge.svg)](https://docs.rs/xbe/)
![CI](https://github.com/jonas-schievink/xbe/workflows/CI/badge.svg)

This crate provides a parser for `.xbe` files, which were used by the original
Xbox to store executable files. It aims to provide a simple and well-documented
interface.

Please refer to the [changelog](CHANGELOG.md) to see what changed in the last
releases.

## Usage

Start by adding an entry to your `Cargo.toml`:

```toml
[dependencies]
xbe = "0.1.1"
```

Then import the crate into your Rust code:

```rust
extern crate xbe;
```
