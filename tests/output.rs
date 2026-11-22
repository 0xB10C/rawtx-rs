//! Integration tests for the output module using only the public API.

use rawtx_rs::bitcoin::consensus::deserialize;
use rawtx_rs::bitcoin::Transaction;
use rawtx_rs::output::{OpReturnFlavor, OutputInfo, OutputSigops, OutputType, OutputTypeDetection};
use rawtx_rs::testdata;
use rawtx_rs::tx::TxInfo;

fn decode_tx(tx_hex: &str) -> Transaction {
    deserialize(&hex::decode(tx_hex).unwrap()).unwrap()
}

/// The expected output type, the expected number of sigops and the expected
/// number of public keys for each output of a transaction.
type ExpectedOutputs = &'static [(OutputType, usize, usize)];

/// The test transactions with the expected values for each of their outputs.
/// The values were derived by decoding the transactions once.
fn test_cases() -> Vec<(&'static str, &'static str, ExpectedOutputs)> {
    vec![
        ("TX_P2PK", testdata::TX_P2PK, &[(OutputType::P2pkh, 4, 0)]),
        ("TX_P2PKH", testdata::TX_P2PKH, &[(OutputType::P2pkh, 4, 0)]),
        (
            "TX_P2SH",
            testdata::TX_P2SH,
            &[(OutputType::P2pkh, 4, 0), (OutputType::P2sh, 0, 0)],
        ),
        (
            "TX_P2WPKH",
            testdata::TX_P2WPKH,
            &[(OutputType::P2wpkhV0, 0, 0)],
        ),
        (
            "TX_P2WSH",
            testdata::TX_P2WSH,
            &[(OutputType::P2sh, 0, 0), (OutputType::P2wshV0, 0, 0)],
        ),
        (
            "TX_P2MS_OUTPUT",
            testdata::TX_P2MS_OUTPUT,
            &[
                (OutputType::P2ms, 80, 1),
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2pkh, 4, 0),
            ],
        ),
        (
            "TX_P2MS_OUTPUT_2",
            testdata::TX_P2MS_OUTPUT_2,
            &[(OutputType::P2ms, 80, 1), (OutputType::P2pkh, 4, 0)],
        ),
        (
            "TX_P2TR_OUTPUT",
            testdata::TX_P2TR_OUTPUT,
            &[
                (OutputType::P2tr, 0, 1),
                (OutputType::P2tr, 0, 1),
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::P2tr, 0, 1),
            ],
        ),
        (
            "TX_P2A_OUTPUT",
            testdata::TX_P2A_OUTPUT,
            &[(OutputType::P2a, 0, 0), (OutputType::P2tr, 0, 1)],
        ),
        (
            "TX_WITNESS_COMMITMENT",
            testdata::TX_WITNESS_COMMITMENT,
            &[
                (OutputType::P2pkh, 4, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
            ],
        ),
        (
            "TX_OPRETURN_OMNI",
            testdata::TX_OPRETURN_OMNI,
            &[
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2pkh, 4, 0),
                (OutputType::OpReturn(OpReturnFlavor::Omni), 0, 0),
            ],
        ),
        (
            "TX_OPRETURN_STACKS",
            testdata::TX_OPRETURN_STACKS,
            &[
                (
                    OutputType::OpReturn(OpReturnFlavor::StacksBlockCommit),
                    0,
                    0,
                ),
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2pkh, 4, 0),
            ],
        ),
        (
            "TX_BIP47_1",
            testdata::TX_BIP47_1,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
        (
            "TX_BIP47_2",
            testdata::TX_BIP47_2,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
        (
            "TX_BIP47_3",
            testdata::TX_BIP47_3,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
        (
            "TX_BIP47_4",
            testdata::TX_BIP47_4,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::P2pkh, 4, 0),
            ],
        ),
        (
            "TX_BIP47_5",
            testdata::TX_BIP47_5,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::P2pkh, 4, 0),
            ],
        ),
        (
            "TX_BIP47_6",
            testdata::TX_BIP47_6,
            &[
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2pkh, 4, 0),
            ],
        ),
        (
            "TX_BIP47_7",
            testdata::TX_BIP47_7,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::P2pkh, 4, 0),
            ],
        ),
        (
            "TX_BIP47_8",
            testdata::TX_BIP47_8,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
        (
            "TX_BIP47_9",
            testdata::TX_BIP47_9,
            &[
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2pkh, 4, 0),
            ],
        ),
        (
            "TX_BIP47_10",
            testdata::TX_BIP47_10,
            &[
                (OutputType::P2pkh, 4, 0),
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
        (
            "TX_BIP47_11",
            testdata::TX_BIP47_11,
            &[
                (OutputType::P2pkh, 4, 0),
                (OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode), 0, 0),
            ],
        ),
        (
            "TX_BIP47_FAILURE",
            testdata::TX_BIP47_FAILURE,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Len1Byte), 0, 0),
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2wshV0, 0, 0),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_1",
            testdata::TX_COINBASE_OPRETURN_1,
            &[
                (OutputType::P2sh, 0, 0),
                (OutputType::P2sh, 0, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
                (OutputType::OpReturn(OpReturnFlavor::CoreDao), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::ExSat), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::RSKBlock), 0, 0),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_2",
            testdata::TX_COINBASE_OPRETURN_2,
            &[
                (OutputType::P2sh, 0, 0),
                (OutputType::P2sh, 0, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
                (OutputType::OpReturn(OpReturnFlavor::CoreDao), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::ExSat), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::RSKBlock), 0, 0),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_3",
            testdata::TX_COINBASE_OPRETURN_3,
            &[
                (OutputType::P2sh, 0, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
                (OutputType::OpReturn(OpReturnFlavor::CoreDao), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::RSKBlock), 0, 0),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_4",
            testdata::TX_COINBASE_OPRETURN_4,
            &[
                (OutputType::P2pkh, 4, 0),
                (OutputType::OpReturn(OpReturnFlavor::RSKBlock), 0, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_5",
            testdata::TX_COINBASE_OPRETURN_5,
            &[
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2pkh, 4, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
                (OutputType::OpReturn(OpReturnFlavor::CoreDao), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::HathorNetwork), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::RSKBlock), 0, 0),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_6",
            testdata::TX_COINBASE_OPRETURN_6,
            &[
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2pkh, 4, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
                (OutputType::OpReturn(OpReturnFlavor::CoreDao), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::ExSat), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::HathorNetwork), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::RSKBlock), 0, 0),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_7",
            testdata::TX_COINBASE_OPRETURN_7,
            &[
                (OutputType::P2sh, 0, 0),
                (OutputType::P2sh, 0, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
                (OutputType::OpReturn(OpReturnFlavor::CoreDao), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::RSKBlock), 0, 0),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_8",
            testdata::TX_COINBASE_OPRETURN_8,
            &[
                (OutputType::P2tr, 0, 1),
                (OutputType::P2wshV0, 0, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
                (OutputType::OpReturn(OpReturnFlavor::CoreDao), 0, 0),
            ],
        ),
        (
            "TX_COINBASE_OPRETURN_9",
            testdata::TX_COINBASE_OPRETURN_9,
            &[
                (OutputType::P2pkh, 4, 0),
                (OutputType::P2pkh, 4, 0),
                (
                    OutputType::OpReturn(OpReturnFlavor::WitnessCommitment),
                    0,
                    0,
                ),
                (OutputType::OpReturn(OpReturnFlavor::CoreDao), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::ExSat), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::HathorNetwork), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::RSKBlock), 0, 0),
            ],
        ),
        (
            "TX_RUNESTONE_1",
            testdata::TX_RUNESTONE_1,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Runestone), 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
        (
            "TX_RUNESTONE_2",
            testdata::TX_RUNESTONE_2,
            &[
                (OutputType::P2tr, 0, 1),
                (OutputType::OpReturn(OpReturnFlavor::Runestone), 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
        (
            "TX_RUNESTONE_3",
            testdata::TX_RUNESTONE_3,
            &[
                (OutputType::P2tr, 0, 1),
                (OutputType::OpReturn(OpReturnFlavor::Runestone), 0, 0),
            ],
        ),
        (
            "TX_RUNESTONE_4",
            testdata::TX_RUNESTONE_4,
            &[
                (OutputType::P2tr, 0, 1),
                (OutputType::OpReturn(OpReturnFlavor::Runestone), 0, 0),
            ],
        ),
        (
            "TX_1IN_3OUT_OPRETURN",
            testdata::TX_1IN_3OUT_OPRETURN,
            &[
                (OutputType::P2tr, 0, 1),
                (OutputType::OpReturn(OpReturnFlavor::Runestone), 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
        (
            "TX_1IN_6OUT_5OPRETURN",
            testdata::TX_1IN_6OUT_5OPRETURN,
            &[
                (OutputType::OpReturn(OpReturnFlavor::Unspecified), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::Unspecified), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::Unspecified), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::Unspecified), 0, 0),
                (OutputType::OpReturn(OpReturnFlavor::Unspecified), 0, 0),
                (OutputType::P2wpkhV0, 0, 0),
            ],
        ),
    ]
}

#[test]
fn output_infos_of_test_transactions() {
    for (name, tx_hex, expected) in test_cases() {
        let tx = decode_tx(tx_hex);
        let tx_info = TxInfo::new(&tx).unwrap();
        assert_eq!(
            tx_info.output_infos.len(),
            expected.len(),
            "{}: number of outputs",
            name
        );

        for (index, (out_type, sigops, pubkeys)) in expected.iter().enumerate() {
            let info = &tx_info.output_infos[index];
            assert_eq!(info.out_type, *out_type, "{} output {}: type", name, index);
            assert_eq!(info.sigops, *sigops, "{} output {}: sigops", name, index);
            assert_eq!(
                info.pubkey_stats.len(),
                *pubkeys,
                "{} output {}: public keys",
                name,
                index
            );
            assert_eq!(
                info.value, tx.output[index].value,
                "{} output {}: value",
                name, index
            );
            assert_eq!(
                info.is_opreturn(),
                matches!(out_type, OutputType::OpReturn(_)),
                "{} output {}: is_opreturn",
                name,
                index
            );
        }
    }
}

#[test]
fn output_info_agrees_with_the_txout_traits() {
    for (name, tx_hex, expected) in test_cases() {
        let tx = decode_tx(tx_hex);
        for (index, (out_type, sigops, pubkeys)) in expected.iter().enumerate() {
            let output = &tx.output[index];
            let info = OutputInfo::new(output).unwrap();
            assert_eq!(info.out_type, *out_type, "{} output {}: type", name, index);
            assert_eq!(
                output.get_type(),
                *out_type,
                "{} output {}: get_type",
                name,
                index
            );
            assert_eq!(
                output.sigops(),
                *sigops,
                "{} output {}: sigops",
                name,
                index
            );
            assert_eq!(
                output.sigops_with_type(*out_type),
                *sigops,
                "{} output {}: sigops_with_type",
                name,
                index
            );
            assert_eq!(
                info.pubkey_stats.len(),
                *pubkeys,
                "{} output {}: public keys",
                name,
                index
            );
        }
    }
}

/// Every detection method has to agree with the detected output type. None of
/// the test transaction outputs matches more than one of them.
#[test]
fn detection_methods_agree_with_the_output_type() {
    for (name, tx_hex, expected) in test_cases() {
        let tx = decode_tx(tx_hex);
        for (index, (out_type, _, _)) in expected.iter().enumerate() {
            let output = &tx.output[index];
            let opreturn = |flavor| OutputType::OpReturn(flavor) == *out_type;
            let checks: Vec<(&str, bool, bool)> = vec![
                ("is_p2ms", output.is_p2ms(), *out_type == OutputType::P2ms),
                ("is_p2tr", output.is_p2tr(), *out_type == OutputType::P2tr),
                ("is_p2a", output.is_p2a(), *out_type == OutputType::P2a),
                (
                    "is_witness_commitment",
                    output.is_witness_commitment(),
                    opreturn(OpReturnFlavor::WitnessCommitment),
                ),
                (
                    "is_opreturn_omni",
                    output.is_opreturn_omni(),
                    opreturn(OpReturnFlavor::Omni),
                ),
                (
                    "is_opreturn_stacks_blockcommit",
                    output.is_opreturn_stacks_blockcommit(),
                    opreturn(OpReturnFlavor::StacksBlockCommit),
                ),
                (
                    "is_opreturn_bip47_payment_code",
                    output.is_opreturn_bip47_payment_code(),
                    opreturn(OpReturnFlavor::Bip47PaymentCode),
                ),
                (
                    "is_opreturn_rsk_block",
                    output.is_opreturn_rsk_block(),
                    opreturn(OpReturnFlavor::RSKBlock),
                ),
                (
                    "is_opreturn_coredao",
                    output.is_opreturn_coredao(),
                    opreturn(OpReturnFlavor::CoreDao),
                ),
                (
                    "is_opreturn_exsat",
                    output.is_opreturn_exsat(),
                    opreturn(OpReturnFlavor::ExSat),
                ),
                (
                    "is_opreturn_hathor",
                    output.is_opreturn_hathor(),
                    opreturn(OpReturnFlavor::HathorNetwork),
                ),
                (
                    "is_opreturn_runestone",
                    output.is_opreturn_runestone(),
                    opreturn(OpReturnFlavor::Runestone),
                ),
            ];

            for (method, detected, expected) in checks.iter() {
                assert_eq!(
                    detected, expected,
                    "{} output {}: {} of a {}",
                    name, index, method, out_type
                );
            }
        }
    }
}

/// The OP_RETURN data length flavors have to match the data pushed by the
/// OP_RETURN outputs of the test transactions.
#[test]
fn opreturn_data_length_flavors() {
    // (name, transaction, output index, expected flavor, pushed data length)
    let cases: Vec<(&str, &str, usize, OpReturnFlavor, usize)> = vec![
        (
            "TX_BIP47_FAILURE",
            testdata::TX_BIP47_FAILURE,
            0,
            OpReturnFlavor::Len1Byte,
            1,
        ),
        (
            "TX_OPRETURN_STACKS",
            testdata::TX_OPRETURN_STACKS,
            0,
            OpReturnFlavor::StacksBlockCommit,
            80,
        ),
        (
            "TX_OPRETURN_OMNI",
            testdata::TX_OPRETURN_OMNI,
            2,
            OpReturnFlavor::Omni,
            20,
        ),
        (
            "TX_BIP47_1",
            testdata::TX_BIP47_1,
            0,
            OpReturnFlavor::Bip47PaymentCode,
            80,
        ),
    ];

    for (name, tx_hex, index, flavor, data_length) in cases.iter() {
        let tx = decode_tx(tx_hex);
        let output = &tx.output[*index];
        assert_eq!(output.get_type(), OutputType::OpReturn(*flavor), "{}", name);
        assert!(
            output.is_opreturn_with_len(*data_length),
            "{} output {} should push {} bytes",
            name,
            index,
            data_length
        );
        assert!(
            !output.is_opreturn_with_len(*data_length + 1),
            "{} output {} shouldn't push {} bytes",
            name,
            index,
            data_length + 1
        );
    }
}
