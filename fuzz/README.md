# Fuzzing rawtx-rs

This is a [cargo-fuzz](https://rust-fuzzing.github.io/book/cargo-fuzz.html)
crate with libFuzzer harnesses for rawtx-rs. The harnesses check that the
library never panics, no matter what input it is given. Returning an `Err` is
always fine, panicking never is.

The crate is its own workspace, so the parent crate is unaffected by it.

## Targets

| target            | input                                                      |
|-------------------|------------------------------------------------------------|
| `tx_info`         | a consensus encoded `bitcoin::Transaction`                 |
| `tx_in`           | a `bitcoin::TxIn` (see the encoding below)                 |
| `tx_out`          | a `bitcoin::TxOut` (see the encoding below)                |
| `signature`       | raw bytes passed to the signature and pubkey parsers       |
| `multisig_script` | raw bytes interpreted as a `bitcoin::Script`               |

The actual harness code lives in `src/lib.rs` as `fuzz_<target>()` functions.
The files in `fuzz_targets/` are one-liners handing the fuzzer bytes to them.
Each `fuzz_<target>()` function decodes the bytes and then calls a typed
`check_*()` function, which is what the unit tests in `src/lib.rs` call
directly on the transactions from `rawtx_rs::testdata`.

`tx_in` and `tx_out` use a hand rolled encoding (and not `arbitrary`s internal
one) so that seed files are easy to write and to read:

```text
tx_in:  [flags: 1 byte][vout: u32 LE][sequence: u32 LE]
        [script_sig length: u16 LE][script_sig]
        then witness elements as [length: u16 LE][element] until the end
tx_out: [value in sat: u64 LE][script_pubkey]
```

Bit 0 of the `tx_in` flags byte turns the input into a coinbase input. Lengths
are clamped to the data that is left and missing trailing bytes default to
zero, so every byte string is a valid input.

## Running the harnesses on stable

The fuzz target binaries are behind the `libfuzzer` Cargo feature, so the
harness logic (and the smoke tests over the test transactions) build and run on
a stable toolchain without compiling libFuzzer:

```console
cd fuzz
cargo test
```

This is also what the `fuzz-smoke` CI job runs. It's a quick regression check,
not a replacement for actually fuzzing.

## Seeding the corpus

Fuzzing should start from real transactions. An ignored test writes a seed
corpus derived from `rawtx_rs::testdata` into `fuzz/corpus/<target>/`:

```console
cd fuzz
cargo test -- --ignored write_seed_corpus
```

## Fuzzing

Fuzzing needs a nightly toolchain and `cargo fuzz`
(`cargo install cargo-fuzz`). As the targets are behind a Cargo feature, all
`cargo fuzz` invocations need `--features libfuzzer`:

```console
cargo +nightly fuzz run --features libfuzzer tx_info
cargo +nightly fuzz run --features libfuzzer tx_in
cargo +nightly fuzz run --features libfuzzer tx_out
cargo +nightly fuzz run --features libfuzzer signature
cargo +nightly fuzz run --features libfuzzer multisig_script
```

Run these from the repository root (that's where `cargo fuzz` looks for the
`fuzz/` directory). They run until stopped or until they find a crash. Pass a
time limit on to libFuzzer with `-- -max_total_time=180`.

On NixOS, `nix-shell -p cargo-fuzz` with a nightly toolchain on the `PATH`
gives you everything that's needed.

## Reproducing and fixing a crash

A crashing input is written to `fuzz/artifacts/<target>/crash-<hash>`. Run it
again and shrink it with:

```console
cargo +nightly fuzz run --features libfuzzer tx_info fuzz/artifacts/tx_info/crash-<hash>
cargo +nightly fuzz tmin --features libfuzzer tx_info fuzz/artifacts/tx_info/crash-<hash>
```

Crashes are turned into regression tests in the main crate, not in this crate:
find out which function panics, then add a test to the `mod tests` of the
module it lives in (`src/tx.rs`, `src/input.rs`, `src/output.rs` or
`src/script.rs`) that builds the panicking value by hand. The artifact file
itself isn't checked in: a hand built `TxOut`, script or signature says much
more about the bug than a few hundred bytes of fuzzer output. Then fix the
library and make sure `cargo test` and `cargo test --features counterparty`
pass in the repository root.
