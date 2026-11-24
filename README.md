# rawtx-rs

A [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) based crate making information about Bitcoin transactions accessible.

This includes, for example:
- Detecting input and output types
- SegWit and MulitSig spending
- Explicit BIP-125 Opt In RBF signaling
- BIP-69 compliant
- and more..

In its current state, this crate should be considerd as 'unfinished' and 'under development'.

## Testing

Run the unit and integration tests with `cargo test`. The optional
Counterparty detection code and its tests are only compiled with the
`counterparty` feature enabled, so please also run
`cargo test --features counterparty`.

Fuzzing harnesses live in the separate [`fuzz/`](fuzz/README.md) crate. They
check that the library never panics on arbitrary transactions, inputs, outputs,
signatures and scripts. The harnesses and their seed-data smoke tests run on
stable with `cd fuzz && cargo test`; actually fuzzing needs a nightly toolchain
and `cargo fuzz`. See [`fuzz/README.md`](fuzz/README.md) for details.

Mutation tests are run with [cargo-mutants](https://mutants.rs)
(`cargo install cargo-mutants`, then `cargo mutants`). The checked-in
`.cargo/mutants.toml` turns on the `counterparty` feature.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.