//! Tests for the public transaction information API.

use rawtx_rs::bitcoin::{Amount, Transaction};
use rawtx_rs::testdata;
use rawtx_rs::tx::{TransactionSigops, TxInfo};

fn decode_tx(hex: &str) -> Transaction {
    rawtx_rs::bitcoin::consensus::deserialize(&hex::decode(hex).unwrap()).unwrap()
}

fn tx_info(hex: &str) -> TxInfo {
    TxInfo::new(&decode_tx(hex)).unwrap()
}

/// Builds a transaction with `inputs` inputs and one output per entry in
/// `output_values`. The inputs and outputs are copies of the inputs and
/// outputs of a real transaction.
fn tx_with(inputs: usize, output_values: &[u64]) -> Transaction {
    let base = decode_tx(testdata::TX_2IN_4OUT);
    let mut tx = base.clone();

    tx.input = (0..inputs)
        .map(|i| {
            let mut input = base.input[i % base.input.len()].clone();
            // keep the outpoints distinct
            input.previous_output.vout = i as u32;
            input
        })
        .collect();
    tx.output = output_values
        .iter()
        .map(|value| {
            let mut output = base.output[0].clone();
            output.value = Amount::from_sat(*value);
            output
        })
        .collect();

    tx
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
    // three identical P2SH inputs, each with a short, unusual script_sig
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

/// A transaction is a potential equal-output-value coinjoin if it has at least
/// two inputs, at least two outputs, more than two outputs sharing the same
/// value and at least a third of the outputs sharing that value.
#[test]
fn potentially_coinjoin_boundaries() {
    // three equal-value outputs and two inputs are enough
    assert!(TxInfo::new(&tx_with(2, &[100, 100, 100]))
        .unwrap()
        .potentially_coinjoin());
    assert!(TxInfo::new(&tx_with(3, &[100, 100, 100]))
        .unwrap()
        .potentially_coinjoin());

    // a single input is not enough
    assert!(!TxInfo::new(&tx_with(1, &[100, 100, 100, 100]))
        .unwrap()
        .potentially_coinjoin());

    // fewer than two outputs are not enough
    assert!(!TxInfo::new(&tx_with(2, &[]))
        .unwrap()
        .potentially_coinjoin());
    assert!(!TxInfo::new(&tx_with(2, &[100]))
        .unwrap()
        .potentially_coinjoin());

    // two equal-value outputs are not enough
    assert!(!TxInfo::new(&tx_with(2, &[100, 100]))
        .unwrap()
        .potentially_coinjoin());
    assert!(!TxInfo::new(&tx_with(2, &[100, 100, 200, 300]))
        .unwrap()
        .potentially_coinjoin());

    // no equal-value outputs at all
    assert!(!TxInfo::new(&tx_with(2, &[100, 200, 300, 400]))
        .unwrap()
        .potentially_coinjoin());

    // three of nine outputs share a value, which is exactly a third
    assert!(TxInfo::new(&tx_with(2, &[100, 100, 100, 1, 2, 3, 4, 5, 6]))
        .unwrap()
        .potentially_coinjoin());

    // three of twelve outputs share a value, which is less than a third
    assert!(
        !TxInfo::new(&tx_with(2, &[100, 100, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9]))
            .unwrap()
            .potentially_coinjoin()
    );
}

/// Of all test transactions only TX_P2TR_OUTPUT, which pays the same amount to
/// three of its four outputs, looks like a coinjoin.
#[test]
fn potentially_coinjoin_on_test_transactions() {
    assert!(tx_info(testdata::TX_P2TR_OUTPUT).potentially_coinjoin());

    for rawtx in testdata::ALL_TRANSACTIONS.iter() {
        if *rawtx == testdata::TX_P2TR_OUTPUT {
            continue;
        }
        let info = tx_info(rawtx);
        assert!(
            !info.potentially_coinjoin(),
            "{} should not look like a coinjoin",
            info.txid
        );
    }
}

/// A transaction is a potential consolidation if it has at least ten inputs
/// and at most two outputs.
#[test]
fn potentially_consolidation_boundaries() {
    assert!(TxInfo::new(&tx_with(10, &[100, 200]))
        .unwrap()
        .potentially_consolidation());
    assert!(TxInfo::new(&tx_with(10, &[100]))
        .unwrap()
        .potentially_consolidation());
    assert!(TxInfo::new(&tx_with(11, &[100, 200]))
        .unwrap()
        .potentially_consolidation());

    // too few inputs
    assert!(!TxInfo::new(&tx_with(9, &[100, 200]))
        .unwrap()
        .potentially_consolidation());
    // too many outputs
    assert!(!TxInfo::new(&tx_with(10, &[100, 200, 300]))
        .unwrap()
        .potentially_consolidation());
    // neither enough inputs nor few enough outputs
    assert!(!TxInfo::new(&tx_with(9, &[100, 200, 300]))
        .unwrap()
        .potentially_consolidation());
    // a plain one-input one-output transaction
    assert!(!tx_info(testdata::TX_1IN_1OUT).potentially_consolidation());
}

/// TX_P2PKH has a single 62600 sat output. TX_P2A has a single OP_RETURN
/// output with a value of zero.
#[test]
fn has_non_opreturn_output_smaller_than() {
    let p2pkh = tx_info(testdata::TX_P2PKH);
    assert!(p2pkh.has_non_opretrun_output_smaller_than(Amount::from_sat(62601)));
    assert!(p2pkh.has_non_opretrun_output_smaller_than(Amount::from_sat(100_000)));
    // the value itself is not smaller than itself
    assert!(!p2pkh.has_non_opretrun_output_smaller_than(Amount::from_sat(62600)));
    assert!(!p2pkh.has_non_opretrun_output_smaller_than(Amount::from_sat(1)));

    // OP_RETURN outputs don't count, even though their value is smaller
    let p2a = tx_info(testdata::TX_P2A);
    assert!(!p2a.has_non_opretrun_output_smaller_than(Amount::from_sat(1)));
    assert!(!p2a.has_non_opretrun_output_smaller_than(Amount::from_sat(100_000)));

    // the 0 sat output is an OP_RETURN output, the 546 sat output isn't
    let mixed = tx_info(testdata::TX_1IN_3OUT_OPRETURN);
    assert!(!mixed.has_non_opretrun_output_smaller_than(Amount::from_sat(1)));
    assert!(mixed.has_non_opretrun_output_smaller_than(Amount::from_sat(547)));
}

/// TX_P2PKH has a single 62600 sat output. TX_P2A has a single output with a
/// value of zero.
#[test]
fn has_output_larger_than() {
    let p2pkh = tx_info(testdata::TX_P2PKH);
    assert!(p2pkh.has_output_larger_than(Amount::from_sat(1)));
    assert!(p2pkh.has_output_larger_than(Amount::from_sat(62599)));
    // the value itself is not larger than itself
    assert!(!p2pkh.has_output_larger_than(Amount::from_sat(62600)));
    assert!(!p2pkh.has_output_larger_than(Amount::from_sat(100_000)));

    // OP_RETURN outputs do count here
    let opreturn = tx_info(testdata::TX_1IN_3OUT_OPRETURN);
    assert!(opreturn.has_output_larger_than(Amount::from_sat(545)));
    assert!(!tx_info(testdata::TX_P2A).has_output_larger_than(Amount::from_sat(0)));
}

#[test]
fn output_value_sum() {
    assert_eq!(
        tx_info(testdata::TX_P2PKH).output_value_sum(),
        Amount::from_sat(62600)
    );
    // 83110 + 110000 + 641774 + 373495
    assert_eq!(
        tx_info(testdata::TX_2IN_4OUT).output_value_sum(),
        Amount::from_sat(1_208_379)
    );
    // OP_RETURN outputs with a value of zero contribute nothing
    assert_eq!(
        tx_info(testdata::TX_P2A).output_value_sum(),
        Amount::from_sat(0)
    );
    // 546 + 0 + 19062
    assert_eq!(
        tx_info(testdata::TX_1IN_3OUT_OPRETURN).output_value_sum(),
        Amount::from_sat(19608)
    );
    // a transaction without outputs
    assert_eq!(
        TxInfo::new(&tx_with(2, &[])).unwrap().output_value_sum(),
        Amount::from_sat(0)
    );
}

#[test]
fn payments() {
    // a transaction with only OP_RETURN outputs makes no payment
    assert_eq!(tx_info(testdata::TX_P2A).payments(), 0);
    assert_eq!(TxInfo::new(&tx_with(1, &[])).unwrap().payments(), 0);
    // a single output is counted as a payment, there is no change output
    assert_eq!(tx_info(testdata::TX_1IN_1OUT).payments(), 1);
    // one of the outputs is assumed to be a change output
    assert_eq!(tx_info(testdata::TX_1IN_2OUT).payments(), 1);
    assert_eq!(tx_info(testdata::TX_2IN_4OUT).payments(), 3);
    // the OP_RETURN outputs don't count as payments
    assert_eq!(tx_info(testdata::TX_1IN_6OUT_5OPRETURN).payments(), 1);
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
