//! Tests for the public transaction information API.

use rawtx_rs::bitcoin::Transaction;
use rawtx_rs::testdata;
use rawtx_rs::tx::{TransactionSigops, TxInfo};

fn decode_tx(hex: &str) -> Transaction {
    rawtx_rs::bitcoin::consensus::deserialize(&hex::decode(hex).unwrap()).unwrap()
}

fn tx_info(hex: &str) -> TxInfo {
    TxInfo::new(&decode_tx(hex)).unwrap()
}

/// A named check on a [TxInfo] returning either true or false.
type SpendingCheck = (&'static str, fn(&TxInfo) -> bool);

/// All checks run by [spending_type_checks].
const SPENDING_CHECKS: [SpendingCheck; 12] = [
    ("spending_segwit", TxInfo::is_spending_segwit),
    ("spending_taproot", TxInfo::is_spending_taproot),
    ("spending_nested_segwit", TxInfo::is_spending_nested_segwit),
    ("spending_native_segwit", TxInfo::is_spending_native_segwit),
    ("only_spending_segwit", TxInfo::is_only_spending_segwit),
    ("only_spending_legacy", TxInfo::is_only_spending_legacy),
    ("only_spending_taproot", TxInfo::is_only_spending_taproot),
    (
        "only_spending_nested_segwit",
        TxInfo::is_only_spending_nested_segwit,
    ),
    (
        "only_spending_native_segwit",
        TxInfo::is_only_spending_native_segwit,
    ),
    (
        "spending_segwit_and_legacy",
        TxInfo::is_spending_segwit_and_legacy,
    ),
    ("spending_multisig", TxInfo::is_spending_multisig),
    ("has_opreturn_output", TxInfo::has_opreturn_output),
];

/// For every transaction the [SPENDING_CHECKS] expected to return true. All
/// checks not named for a transaction have to return false. The input types of
/// each transaction are named in the comment above it.
const SPENDING_TYPE_EXPECTATIONS: &[(&str, &str, &[&str])] = &[
    // P2PK
    ("TX_P2PK", testdata::TX_P2PK, &["only_spending_legacy"]),
    // P2PKH
    ("TX_P2PKH", testdata::TX_P2PKH, &["only_spending_legacy"]),
    // P2SH wrapping a 1-of-2 multisig
    (
        "TX_P2SH",
        testdata::TX_P2SH,
        &["only_spending_legacy", "spending_multisig"],
    ),
    // three P2SH inputs, one of them with a script too short to be classified
    (
        "TX_UNKNOWN_INPUT",
        testdata::TX_UNKNOWN_INPUT,
        &["only_spending_legacy"],
    ),
    // bare 1-of-2 multisig
    (
        "TX_P2MS_1OF2",
        testdata::TX_P2MS_1OF2,
        &["only_spending_legacy", "spending_multisig"],
    ),
    // bare 2-of-3 multisig
    (
        "TX_P2MS_2OF3",
        testdata::TX_P2MS_2OF3,
        &["only_spending_legacy", "spending_multisig"],
    ),
    // P2SH-P2WPKH
    (
        "TX_P2SH_P2WPKH",
        testdata::TX_P2SH_P2WPKH,
        &[
            "spending_segwit",
            "spending_nested_segwit",
            "only_spending_segwit",
            "only_spending_nested_segwit",
        ],
    ),
    // P2SH-P2WSH wrapping a multisig
    (
        "TX_P2SH_P2WSH",
        testdata::TX_P2SH_P2WSH,
        &[
            "spending_segwit",
            "spending_nested_segwit",
            "only_spending_segwit",
            "only_spending_nested_segwit",
            "spending_multisig",
        ],
    ),
    // P2WPKH
    (
        "TX_P2WPKH",
        testdata::TX_P2WPKH,
        &[
            "spending_segwit",
            "spending_native_segwit",
            "only_spending_segwit",
            "only_spending_native_segwit",
        ],
    ),
    // P2WSH wrapping a multisig
    (
        "TX_P2WSH",
        testdata::TX_P2WSH,
        &[
            "spending_segwit",
            "spending_native_segwit",
            "only_spending_segwit",
            "only_spending_native_segwit",
            "spending_multisig",
        ],
    ),
    // P2WSH not wrapping a multisig
    (
        "TX_P2WSH_NON_MULTISIG",
        testdata::TX_P2WSH_NON_MULTISIG,
        &[
            "spending_segwit",
            "spending_native_segwit",
            "only_spending_segwit",
            "only_spending_native_segwit",
        ],
    ),
    // P2TR key-path and P2WPKH
    (
        "TX_P2TRKP",
        testdata::TX_P2TRKP,
        &[
            "spending_segwit",
            "spending_taproot",
            "spending_native_segwit",
            "only_spending_segwit",
            "only_spending_native_segwit",
        ],
    ),
    // P2TR script-path
    (
        "TX_P2TRSP",
        testdata::TX_P2TRSP,
        &[
            "spending_segwit",
            "spending_taproot",
            "spending_native_segwit",
            "only_spending_segwit",
            "only_spending_taproot",
            "only_spending_native_segwit",
        ],
    ),
    // P2A, paying to an OP_RETURN output
    (
        "TX_P2A",
        testdata::TX_P2A,
        &[
            "spending_segwit",
            "spending_native_segwit",
            "only_spending_segwit",
            "only_spending_native_segwit",
            "has_opreturn_output",
        ],
    ),
    // P2WSH and P2SH-P2WSH, so both native and nested SegWit, but neither
    // only native nor only nested SegWit
    (
        "TX_SIGOPS_86",
        testdata::TX_SIGOPS_86,
        &[
            "spending_segwit",
            "spending_nested_segwit",
            "spending_native_segwit",
            "only_spending_segwit",
            "spending_multisig",
        ],
    ),
    // a coinbase input is neither SegWit nor legacy
    ("TX_COINBASE", testdata::TX_COINBASE, &[]),
    // a coinbase input and a witness commitment OP_RETURN output
    (
        "TX_COINBASE_WITNESS",
        testdata::TX_COINBASE_WITNESS,
        &["has_opreturn_output"],
    ),
];

/// A transaction spending both SegWit and legacy inputs: the two SegWit inputs
/// of TX_P2TRKP (P2TR key-path and P2WPKH) plus the P2PKH input of TX_P2PKH.
fn tx_spending_segwit_and_legacy() -> Transaction {
    let mut tx = decode_tx(testdata::TX_P2TRKP);
    tx.input
        .push(decode_tx(testdata::TX_P2PKH).input[0].clone());
    tx
}

#[test]
fn spending_type_checks() {
    let mut cases: Vec<(&str, TxInfo, Vec<&str>)> = SPENDING_TYPE_EXPECTATIONS
        .iter()
        .map(|(name, rawtx, expected_true)| (*name, tx_info(rawtx), expected_true.to_vec()))
        .collect();

    // No test transaction spends SegWit and legacy inputs at the same time.
    cases.push((
        "segwit and legacy",
        TxInfo::new(&tx_spending_segwit_and_legacy()).unwrap(),
        vec![
            "spending_segwit",
            "spending_taproot",
            "spending_native_segwit",
            "spending_segwit_and_legacy",
        ],
    ));

    for (name, info, expected_true) in cases.iter() {
        for expected in expected_true.iter() {
            assert!(
                SPENDING_CHECKS.iter().any(|(check, _)| check == expected),
                "{}: {} is not a known check",
                name,
                expected
            );
        }

        for (check_name, check) in SPENDING_CHECKS.iter() {
            let expected = expected_true.contains(check_name);
            assert_eq!(
                check(info),
                expected,
                "{}: {} should be {}",
                name,
                check_name,
                expected
            );
        }
    }

    // Every check needs a transaction returning true and one returning false,
    // otherwise the check isn't really tested.
    for (check_name, _) in SPENDING_CHECKS.iter() {
        assert!(
            cases
                .iter()
                .any(|(_, _, expected)| expected.contains(check_name)),
            "no transaction expects {} to be true",
            check_name
        );
        assert!(
            cases
                .iter()
                .any(|(_, _, expected)| !expected.contains(check_name)),
            "no transaction expects {} to be false",
            check_name
        );
    }
}

/// A transaction spends SegWit and legacy if at least one input spends SegWit
/// and at least one other input spends legacy, no matter in which order.
#[test]
fn spending_segwit_and_legacy_needs_both() {
    // only SegWit inputs
    assert!(!tx_info(testdata::TX_P2TRKP).is_spending_segwit_and_legacy());
    // only legacy inputs
    assert!(!tx_info(testdata::TX_BIP69_3IN_4OUT).is_spending_segwit_and_legacy());
    // only a coinbase input, which is neither
    assert!(!tx_info(testdata::TX_COINBASE).is_spending_segwit_and_legacy());

    // the legacy input last
    let tx = tx_spending_segwit_and_legacy();
    assert!(TxInfo::new(&tx).unwrap().is_spending_segwit_and_legacy());

    // the legacy input first
    let mut reversed = tx.clone();
    reversed.input.reverse();
    assert!(TxInfo::new(&reversed)
        .unwrap()
        .is_spending_segwit_and_legacy());
}

/// The sigops counted while building the [TxInfo] agree with the sigops
/// counted on the [Transaction] itself.
#[test]
fn sigops_of_transaction_and_tx_info_agree() {
    for rawtx in testdata::ALL_TRANSACTIONS.iter() {
        let tx = decode_tx(rawtx);
        assert_eq!(tx.sigops().unwrap(), TxInfo::new(&tx).unwrap().sigops());
    }
}
