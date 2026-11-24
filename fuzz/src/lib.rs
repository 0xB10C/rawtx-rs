//! Fuzzing harnesses for rawtx-rs.
//!
//! Every `fuzz_*` function takes raw fuzzer bytes, turns them into something
//! the library accepts and then calls the library. None of them may ever
//! panic: where the library returns a `Result`, both `Ok` and `Err` are fine.
//!
//! Each `fuzz_*` function is a thin wrapper around a typed `check_*` function
//! so that the same checks can be run from ordinary stable-toolchain tests
//! (see the `tests` module at the bottom of this file) on real transactions.

use std::fs;
use std::path::Path;

use arbitrary::Unstructured;
use rawtx_rs::bitcoin::hashes::Hash;
use rawtx_rs::bitcoin::{
    consensus, Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use rawtx_rs::input::{
    InputInfo, InputInscriptionDetection, InputMultisigDetection, InputSigops, InputTypeDetection,
    ScriptHashInput,
};
use rawtx_rs::output::{OutputInfo, OutputSigops, OutputTypeDetection};
use rawtx_rs::script::{
    instructions_as_vec, is_strict_der_encoded_ecdsa_sig, Multisig, PubKeyInfo, PublicKey,
    Signature, SignatureInfo,
};
use rawtx_rs::tx::{TransactionSigops, TxInfo};

/// Asserts that two `Result`s with (possibly) different error types carry the
/// same `Ok` value or are both an error. The error types of rawtx-rs don't
/// implement `PartialEq`, so only the `Ok` side is compared.
fn assert_same_ok<T, E1, E2>(a: Result<T, E1>, b: Result<T, E2>)
where
    T: PartialEq + std::fmt::Debug,
{
    assert_eq!(a.is_ok(), b.is_ok());
    assert_eq!(a.ok(), b.ok());
}

// ---------------------------------------------------------------------------
// tx_info: a consensus encoded transaction
// ---------------------------------------------------------------------------

/// Deserializes the bytes as a transaction and runs all transaction level
/// checks on it. Bytes that aren't a valid transaction are dropped.
pub fn fuzz_tx_info(data: &[u8]) {
    if let Ok(tx) = consensus::deserialize::<Transaction>(data) {
        check_tx(&tx);
    }
}

/// Calls every public function of [TxInfo] and the transaction level helpers.
pub fn check_tx(tx: &Transaction) {
    let tx_info = TxInfo::new(tx);
    let tx_sigops = tx.sigops();

    // The Counterparty detectors work on the raw transaction.
    let _ = rawtx_rs::tx::is_opreturn_counterparty(tx);
    let _ = rawtx_rs::tx::is_p2ms_counterparty(tx);
    let _ = rawtx_rs::tx::is_p2sh_counterparty(tx);

    // If the TxInfo could be built, all inputs and outputs must be parsable
    // too, as TxInfo::new builds an InputInfo and OutputInfo for each of them.
    for input in tx.input.iter() {
        let input_info = InputInfo::new(input);
        if tx_info.is_ok() {
            assert!(input_info.is_ok());
        }
    }
    for output in tx.output.iter() {
        let output_info = OutputInfo::new(output);
        if tx_info.is_ok() {
            assert!(output_info.is_ok());
        }
    }

    let info = match tx_info {
        Ok(info) => info,
        Err(_) => return,
    };

    let sigops = info.sigops();
    if let Ok(tx_sigops) = tx_sigops {
        assert_eq!(sigops, tx_sigops);
    }

    let _ = info.payments();
    let _ = info.is_signaling_explicit_rbf_replicability();
    let _ = info.is_spending_segwit();
    let _ = info.is_spending_taproot();
    let _ = info.is_spending_nested_segwit();
    let _ = info.is_spending_native_segwit();
    let _ = info.is_only_spending_segwit();
    let _ = info.is_only_spending_legacy();
    let _ = info.is_only_spending_taproot();
    let _ = info.is_only_spending_nested_segwit();
    let _ = info.is_only_spending_native_segwit();
    let _ = info.is_spending_segwit_and_legacy();
    let _ = info.is_spending_multisig();
    let _ = info.is_bip69_compliant();
    let _ = info.has_opreturn_output();
    let _ = info.potentially_coinjoin();
    let _ = info.potentially_consolidation();
    let _ = info.has_non_opretrun_output_smaller_than(Amount::from_sat(1000));
    let _ = info.has_output_larger_than(Amount::from_sat(1000));
    let _ = info.output_value_sum();
}

// ---------------------------------------------------------------------------
// tx_in: a hand rolled encoding of a transaction input
// ---------------------------------------------------------------------------

/// Reads up to `n` bytes, returning fewer bytes when the data is exhausted.
fn take_bytes<'a>(u: &mut Unstructured<'a>, n: usize) -> &'a [u8] {
    let n = n.min(u.len());
    u.bytes(n).unwrap_or(&[])
}

/// Reads a little endian `u16`, zero padded when the data is exhausted.
fn take_u16(u: &mut Unstructured) -> u16 {
    let bytes = take_bytes(u, 2);
    let mut buf = [0u8; 2];
    buf[..bytes.len()].copy_from_slice(bytes);
    u16::from_le_bytes(buf)
}

/// Reads a little endian `u32`, zero padded when the data is exhausted.
fn take_u32(u: &mut Unstructured) -> u32 {
    let bytes = take_bytes(u, 4);
    let mut buf = [0u8; 4];
    buf[..bytes.len()].copy_from_slice(bytes);
    u32::from_le_bytes(buf)
}

/// Reads a little endian `u64`, zero padded when the data is exhausted.
fn take_u64(u: &mut Unstructured) -> u64 {
    let bytes = take_bytes(u, 8);
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(buf)
}

/// Builds a [TxIn] from fuzzer bytes. The encoding is hand rolled (and not
/// `arbitrary`s internal format) so that seed files can be written by hand:
///
/// ```text
/// [0]        flags: bit 0 set makes the input a coinbase input
/// [1..5]     vout (little endian u32, ignored for coinbase inputs)
/// [5..9]     sequence (little endian u32)
/// [9..11]    script_sig length (little endian u16, clamped to what's left)
/// [11..]     script_sig
/// then, until the data is exhausted, witness elements as
/// [n..n+2]   element length (little endian u16, clamped to what's left)
/// [n+2..]    element
/// ```
///
/// Missing bytes at the end default to zero or to an empty script/witness.
pub fn tx_in_from_bytes(data: &[u8]) -> TxIn {
    let mut u = Unstructured::new(data);

    let flags = take_bytes(&mut u, 1).first().copied().unwrap_or(0);
    let coinbase = flags & 1 == 1;
    let vout = take_u32(&mut u);
    let sequence = take_u32(&mut u);

    let script_sig_len = take_u16(&mut u) as usize;
    let script_sig = ScriptBuf::from_bytes(take_bytes(&mut u, script_sig_len).to_vec());

    let mut witness_elements: Vec<Vec<u8>> = Vec::new();
    while !u.is_empty() {
        let len = take_u16(&mut u) as usize;
        witness_elements.push(take_bytes(&mut u, len).to_vec());
    }

    let previous_output = if coinbase {
        // a null outpoint with a vout of 0xffffffff
        OutPoint::null()
    } else {
        OutPoint {
            txid: Txid::from_byte_array([0x11; 32]),
            vout,
        }
    };

    TxIn {
        previous_output,
        script_sig,
        sequence: Sequence::from_consensus(sequence),
        witness: Witness::from_slice(&witness_elements),
    }
}

pub fn fuzz_tx_in(data: &[u8]) {
    check_tx_in(&tx_in_from_bytes(data));
}

/// Calls every public function working on a [TxIn].
pub fn check_tx_in(input: &TxIn) {
    let in_type = input.get_type();
    let _ = input.has_witness();
    let _ = input.is_scripthash_input();
    let _ = input.is_p2ms(true);
    let _ = input.is_p2ms(false);
    let _ = input.is_p2pk(true);
    let _ = input.is_p2pk(false);
    let _ = input.is_p2pkh(true);
    let _ = input.is_p2pkh(false);
    let _ = input.is_p2sh();
    let _ = input.is_nested_p2wpkh();
    let _ = input.is_nested_p2wsh();
    let _ = input.is_p2wpkh();
    let _ = input.is_p2wsh();
    let _ = input.is_p2trkp();
    let _ = input.is_p2trsp();
    let _ = input.is_p2a();
    let _ = input.is_coinbase();
    let _ = input.is_coinbase_witness();
    let _ = input.reveals_inscription();

    let multisig_info = input.multisig_info();
    let sigops = input.sigops();
    let redeem_script = input.redeem_script();
    let signature_infos = SignatureInfo::all_from(input);
    let pubkey_infos = PubKeyInfo::from_input(input);

    if let Ok(in_type) = in_type {
        // The `_with_type` variants are just a short cut around the input type
        // detection and have to return the same values.
        assert_same_ok(multisig_info, input.multisig_info_with_type(in_type));
        assert_same_ok(sigops, input.sigops_with_type(in_type));
        assert_same_ok(redeem_script, input.redeem_script_with_type(in_type));
        assert_same_ok(
            signature_infos,
            SignatureInfo::all_from_with_type(input, in_type),
        );
        assert_same_ok(
            pubkey_infos,
            PubKeyInfo::from_input_with_type(input, in_type),
        );
    }

    if let Ok(signature_infos) = SignatureInfo::all_from(input) {
        for signature_info in signature_infos.iter() {
            let _ = signature_info.low_r();
            let _ = signature_info.low_s();
        }
    }

    if let Ok(info) = InputInfo::new(input) {
        assert_eq!(
            info.is_spending_nested_segwit() || info.is_spending_native_segwit(),
            info.is_spending_segwit()
        );
        assert!(!info.is_spending_taproot() || info.is_spending_native_segwit());
        let _ = info.is_spending_legacy();
        let _ = info.is_spending_multisig();
    }
}

// ---------------------------------------------------------------------------
// tx_out: a hand rolled encoding of a transaction output
// ---------------------------------------------------------------------------

/// Builds a [TxOut] from fuzzer bytes. As for [tx_in_from_bytes] the encoding
/// is hand rolled to keep seed files simple:
///
/// ```text
/// [0..8]  value in satoshi (little endian u64)
/// [8..]   script_pubkey
/// ```
pub fn tx_out_from_bytes(data: &[u8]) -> TxOut {
    let mut u = Unstructured::new(data);
    let value = take_u64(&mut u);
    let remaining = u.len();
    let script_pubkey = ScriptBuf::from_bytes(take_bytes(&mut u, remaining).to_vec());
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey,
    }
}

pub fn fuzz_tx_out(data: &[u8]) {
    check_tx_out(&tx_out_from_bytes(data));
}

/// Calls every public function working on a [TxOut].
pub fn check_tx_out(output: &TxOut) {
    let out_type = output.get_type();
    let _ = output.is_p2ms();
    let _ = output.is_p2tr();
    let _ = output.is_p2a();
    let _ = output.is_witness_commitment();
    let _ = output.is_opreturn_omni();
    let _ = output.is_opreturn_stacks_blockcommit();
    let _ = output.is_opreturn_bip47_payment_code();
    let _ = output.is_opreturn_rsk_block();
    let _ = output.is_opreturn_coredao();
    let _ = output.is_opreturn_exsat();
    let _ = output.is_opreturn_hathor();
    let _ = output.is_opreturn_runestone();
    for length in 0..=90 {
        let _ = output.is_opreturn_with_len(length);
    }

    assert_eq!(output.sigops(), output.sigops_with_type(out_type));
    assert_same_ok(
        PubKeyInfo::from_output(output),
        PubKeyInfo::from_output_with_type(output, out_type),
    );

    let info = OutputInfo::new(output).unwrap();
    assert_eq!(info.out_type, out_type);
    let _ = info.is_opreturn();
}

// ---------------------------------------------------------------------------
// signature: raw bytes interpreted as a signature or public key
// ---------------------------------------------------------------------------

pub fn fuzz_signature(data: &[u8]) {
    check_signature(data);
}

/// Calls every public function parsing signature or public key bytes.
pub fn check_signature(data: &[u8]) {
    let _ = is_strict_der_encoded_ecdsa_sig(data);

    let ecdsa = SignatureInfo::from_u8_slice_ecdsa(data);
    let schnorr = SignatureInfo::from_u8_slice_schnorr(data);

    let is_ecdsa_strict = data.is_ecdsa_signature(true);
    let is_ecdsa_lax = data.is_ecdsa_signature(false);
    let is_schnorr = data.is_schnorr_signature();
    let _ = data.is_signature();
    let _ = data.is_ecdsa_pubkey();
    let _ = data.is_schnorr_pubkey();
    let _ = data.is_pubkey();
    let _ = PubKeyInfo::from_u8_slice_ecdsa(data);

    // The `is_*_signature` predicates and the parsers have to agree.
    assert_eq!(ecdsa.is_some(), is_ecdsa_lax);
    assert_eq!(schnorr.is_some(), is_schnorr);
    if is_ecdsa_strict {
        assert!(ecdsa.is_some());
    }

    if let Some(info) = ecdsa {
        let _ = info.low_r();
        let _ = info.low_s();
        assert_eq!(info.length, data.len());
        assert_eq!(info.sig_hash, *data.last().unwrap());
    }

    if let Some(info) = schnorr {
        let _ = info.low_r();
        let _ = info.low_s();
        assert_eq!(info.length, data.len());
        if data.len() == 64 {
            assert_eq!(info.sig_hash, 0x01);
        } else {
            assert_eq!(info.sig_hash, *data.last().unwrap());
        }
    }
}

// ---------------------------------------------------------------------------
// multisig_script: raw bytes interpreted as a script
// ---------------------------------------------------------------------------

pub fn fuzz_multisig_script(data: &[u8]) {
    check_script(Script::from_bytes(data));
}

/// Calls the multisig detection and the script parsing helper on a script.
pub fn check_script(script: &Script) {
    let n_m = script.get_opcheckmultisig_n_m();
    let is_opcheckmultisig = script.is_opcheckmultisig();
    let _ = instructions_as_vec(script);

    assert_eq!(is_opcheckmultisig, matches!(n_m, Ok(Some(_))));
    if let Ok(Some((n, m))) = n_m {
        assert!(n >= 1, "n must be at least 1, is {}", n);
        assert!(n <= m, "n ({}) must not be larger than m ({})", n, m);
        assert!(m <= 16, "m must be at most 16, is {}", m);
    }
}

// ---------------------------------------------------------------------------
// seed corpus
// ---------------------------------------------------------------------------

fn write_seed(dir: &Path, name: &str, data: &[u8]) {
    fs::create_dir_all(dir).expect("should be able to create the seed corpus directory");
    fs::write(dir.join(name), data).expect("should be able to write a seed corpus file");
}

/// Writes a seed corpus for all fuzz targets into `dir/<target>/`. The seeds
/// are derived from the transactions in `rawtx_rs::testdata` so that fuzzing
/// starts out from real world data.
pub fn write_seed_corpus(dir: &Path) {
    for (i, raw) in rawtx_rs::testdata::ALL_TRANSACTIONS.iter().enumerate() {
        let tx_bytes = hex::decode(raw).expect("test transactions should be valid hex");
        let tx: Transaction =
            consensus::deserialize(&tx_bytes).expect("test transactions should deserialize");

        write_seed(&dir.join("tx_info"), &format!("tx-{i}"), &tx_bytes);

        for (j, input) in tx.input.iter().enumerate() {
            write_seed(
                &dir.join("tx_in"),
                &format!("tx-{i}-in-{j}"),
                &encode_tx_in(input),
            );
            for (k, element) in input.witness.iter().enumerate() {
                write_seed(
                    &dir.join("signature"),
                    &format!("tx-{i}-in-{j}-witness-{k}"),
                    element,
                );
                write_seed(
                    &dir.join("multisig_script"),
                    &format!("tx-{i}-in-{j}-witness-{k}"),
                    element,
                );
            }
            if let Ok(instructions) = instructions_as_vec(&input.script_sig) {
                for (k, instruction) in instructions.iter().enumerate() {
                    if let Some(bytes) = instruction.push_bytes() {
                        write_seed(
                            &dir.join("signature"),
                            &format!("tx-{i}-in-{j}-push-{k}"),
                            bytes.as_bytes(),
                        );
                        write_seed(
                            &dir.join("multisig_script"),
                            &format!("tx-{i}-in-{j}-push-{k}"),
                            bytes.as_bytes(),
                        );
                    }
                }
            }
        }

        for (j, output) in tx.output.iter().enumerate() {
            write_seed(
                &dir.join("tx_out"),
                &format!("tx-{i}-out-{j}"),
                &encode_tx_out(output),
            );
            write_seed(
                &dir.join("multisig_script"),
                &format!("tx-{i}-out-{j}"),
                output.script_pubkey.as_bytes(),
            );
        }
    }
}

/// Encodes a [TxIn] in the format [tx_in_from_bytes] reads.
fn encode_tx_in(input: &TxIn) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(if input.previous_output.is_null() {
        1
    } else {
        0
    });
    bytes.extend_from_slice(&input.previous_output.vout.to_le_bytes());
    bytes.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
    let script_sig = input.script_sig.as_bytes();
    bytes.extend_from_slice(&(script_sig.len() as u16).to_le_bytes());
    bytes.extend_from_slice(script_sig);
    for element in input.witness.iter() {
        bytes.extend_from_slice(&(element.len() as u16).to_le_bytes());
        bytes.extend_from_slice(element);
    }
    bytes
}

/// Encodes a [TxOut] in the format [tx_out_from_bytes] reads.
fn encode_tx_out(output: &TxOut) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&output.value.to_sat().to_le_bytes());
    bytes.extend_from_slice(output.script_pubkey.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A few byte strings that aren't derived from real transactions.
    const EDGE_CASES: &[&[u8]] = &[&[], &[0x00], &[0xff; 200], &[0x00; 83], &[0x6a, 0x4c, 0x50]];

    fn test_transactions() -> Vec<Transaction> {
        rawtx_rs::testdata::ALL_TRANSACTIONS
            .iter()
            .map(|raw| {
                let bytes = hex::decode(raw).expect("test transactions should be valid hex");
                consensus::deserialize(&bytes).expect("test transactions should deserialize")
            })
            .collect()
    }

    #[test]
    fn check_test_transactions() {
        for tx in test_transactions().iter() {
            check_tx(tx);
        }
    }

    #[test]
    fn check_test_transaction_inputs_and_outputs() {
        for tx in test_transactions().iter() {
            for input in tx.input.iter() {
                check_tx_in(input);
                // the input encoding has to round trip through the harness
                let encoded = encode_tx_in(input);
                let decoded = tx_in_from_bytes(&encoded);
                assert_eq!(decoded.script_sig, input.script_sig);
                assert_eq!(decoded.witness, input.witness);
                assert_eq!(decoded.sequence, input.sequence);
                check_tx_in(&decoded);
            }
            for output in tx.output.iter() {
                check_tx_out(output);
                let encoded = encode_tx_out(output);
                let decoded = tx_out_from_bytes(&encoded);
                assert_eq!(&decoded, output);
                check_tx_out(&decoded);
            }
        }
    }

    #[test]
    fn check_test_transaction_scripts_and_signatures() {
        for tx in test_transactions().iter() {
            for input in tx.input.iter() {
                for element in input.witness.iter() {
                    check_signature(element);
                    check_script(Script::from_bytes(element));
                }
                if let Ok(instructions) = instructions_as_vec(&input.script_sig) {
                    for instruction in instructions.iter() {
                        if let Some(bytes) = instruction.push_bytes() {
                            check_signature(bytes.as_bytes());
                            check_script(Script::from_bytes(bytes.as_bytes()));
                        }
                    }
                }
                check_script(&input.script_sig);
            }
            for output in tx.output.iter() {
                check_signature(output.script_pubkey.as_bytes());
                check_script(&output.script_pubkey);
            }
        }
    }

    #[test]
    fn check_edge_cases() {
        for bytes in EDGE_CASES {
            check_signature(bytes);
            check_script(Script::from_bytes(bytes));
            check_tx_in(&tx_in_from_bytes(bytes));
            check_tx_out(&tx_out_from_bytes(bytes));
        }
    }

    /// Feeds the byte level harnesses, which is what libFuzzer calls, with
    /// empty and random-ish inputs.
    #[test]
    fn fuzz_functions_on_short_inputs() {
        let mut inputs: Vec<Vec<u8>> = EDGE_CASES.iter().map(|b| b.to_vec()).collect();
        inputs.push(Vec::new());
        // a tiny xorshift to get some reproducible pseudo random byte strings
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for length in 1..64 {
            let mut bytes = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                bytes.push((state & 0xff) as u8);
            }
            inputs.push(bytes);
        }
        for tx in rawtx_rs::testdata::ALL_TRANSACTIONS.iter() {
            inputs.push(hex::decode(tx).expect("test transactions should be valid hex"));
        }

        for bytes in inputs.iter() {
            fuzz_tx_info(bytes);
            fuzz_tx_in(bytes);
            fuzz_tx_out(bytes);
            fuzz_signature(bytes);
            fuzz_multisig_script(bytes);
        }
    }

    #[test]
    #[ignore = "writes the seed corpus into fuzz/corpus/, run it before fuzzing"]
    fn write_seed_corpus() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
        super::write_seed_corpus(&dir);
        assert!(dir.join("tx_info").is_dir());
    }
}
