//! Tests for the public input API of rawtx-rs.

use rawtx_rs::bitcoin::{self, Transaction};
use rawtx_rs::input::{
    InputInfo, InputInscriptionDetection, InputMultisigDetection, InputSigops, InputType,
    InputTypeDetection, MultisigInputInfo,
};
use rawtx_rs::testdata;
use std::collections::HashSet;

fn decode_tx(hex: &str) -> Transaction {
    bitcoin::consensus::deserialize(&hex::decode(hex).unwrap()).unwrap()
}

/// What the first input of a test transaction is expected to look like.
struct Expected {
    name: &'static str,
    tx: &'static str,
    in_type: InputType,
    segwit: bool,
    taproot: bool,
    nested_segwit: bool,
    native_segwit: bool,
    legacy: bool,
    multisig: bool,
    scripthash: bool,
    inscription: bool,
    sigops: usize,
    signatures: usize,
    pubkeys: usize,
    /// `(m, n, unknown_n)` of the detected multisig, if any.
    m_of_n: Option<(u8, u8, bool)>,
}

const EXPECTED: &[Expected] = &[
    Expected {
        name: "P2PK",
        tx: testdata::TX_P2PK,
        in_type: InputType::P2pk,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: true,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 1,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "P2PKH",
        tx: testdata::TX_P2PKH,
        in_type: InputType::P2pkh,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: true,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 1,
        pubkeys: 1,
        m_of_n: None,
    },
    Expected {
        name: "P2PKH with a lax DER signature",
        tx: testdata::TX_P2PKH_LAX_DER,
        in_type: InputType::P2pkhLaxDer,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: true,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 1,
        pubkeys: 1,
        m_of_n: None,
    },
    Expected {
        name: "P2SH wrapping a 1-of-2 multisig",
        tx: testdata::TX_P2SH,
        in_type: InputType::P2sh,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: true,
        multisig: true,
        scripthash: true,
        inscription: false,
        sigops: 8,
        signatures: 1,
        pubkeys: 2,
        m_of_n: Some((1, 2, false)),
    },
    Expected {
        name: "P2SH with a non-standard redeem script",
        tx: testdata::TX_P2SH_RSK,
        in_type: InputType::P2sh,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: true,
        multisig: false,
        scripthash: true,
        inscription: false,
        sigops: 80,
        signatures: 5,
        pubkeys: 13,
        m_of_n: None,
    },
    Expected {
        name: "P2SH nested P2WPKH",
        tx: testdata::TX_P2SH_P2WPKH,
        in_type: InputType::P2shP2wpkh,
        segwit: true,
        taproot: false,
        nested_segwit: true,
        native_segwit: false,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 1,
        signatures: 1,
        pubkeys: 1,
        m_of_n: None,
    },
    Expected {
        name: "P2SH nested P2WSH",
        tx: testdata::TX_P2SH_P2WSH,
        in_type: InputType::P2shP2wsh,
        segwit: true,
        taproot: false,
        nested_segwit: true,
        native_segwit: false,
        legacy: false,
        multisig: true,
        scripthash: true,
        inscription: false,
        sigops: 3,
        signatures: 2,
        pubkeys: 3,
        m_of_n: Some((2, 3, false)),
    },
    Expected {
        name: "P2WPKH",
        tx: testdata::TX_P2WPKH,
        in_type: InputType::P2wpkh,
        segwit: true,
        taproot: false,
        nested_segwit: false,
        native_segwit: true,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 1,
        signatures: 1,
        pubkeys: 1,
        m_of_n: None,
    },
    Expected {
        name: "P2WSH wrapping a 2-of-2 multisig",
        tx: testdata::TX_P2WSH,
        in_type: InputType::P2wsh,
        segwit: true,
        taproot: false,
        nested_segwit: false,
        native_segwit: true,
        legacy: false,
        multisig: true,
        scripthash: true,
        inscription: false,
        sigops: 2,
        signatures: 2,
        pubkeys: 2,
        m_of_n: Some((2, 2, false)),
    },
    Expected {
        name: "P2WSH without a multisig",
        tx: testdata::TX_P2WSH_NON_MULTISIG,
        in_type: InputType::P2wsh,
        segwit: true,
        taproot: false,
        nested_segwit: false,
        native_segwit: true,
        legacy: false,
        multisig: false,
        scripthash: true,
        inscription: false,
        sigops: 2,
        signatures: 1,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "P2TR key-path",
        tx: testdata::TX_P2TRKP,
        in_type: InputType::P2trkp,
        segwit: true,
        taproot: true,
        nested_segwit: false,
        native_segwit: true,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 1,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "P2TR script-path",
        tx: testdata::TX_P2TRSP,
        in_type: InputType::P2trsp,
        segwit: true,
        taproot: true,
        nested_segwit: false,
        native_segwit: true,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 1,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "P2A",
        tx: testdata::TX_P2A,
        in_type: InputType::P2a,
        segwit: true,
        taproot: false,
        nested_segwit: false,
        native_segwit: true,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 0,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "P2MS 1-of-2",
        tx: testdata::TX_P2MS_1OF2,
        in_type: InputType::P2ms,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: true,
        multisig: true,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 1,
        pubkeys: 0,
        m_of_n: Some((1, 0, true)),
    },
    Expected {
        name: "P2MS 2-of-3",
        tx: testdata::TX_P2MS_2OF3,
        in_type: InputType::P2ms,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: true,
        multisig: true,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 2,
        pubkeys: 0,
        m_of_n: Some((2, 0, true)),
    },
    Expected {
        name: "coinbase",
        tx: testdata::TX_COINBASE,
        in_type: InputType::Coinbase,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 0,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "coinbase with a signature operation in its script_sig",
        tx: testdata::TX_COINBASE_2,
        in_type: InputType::Coinbase,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 4,
        signatures: 0,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "coinbase with a witness",
        tx: testdata::TX_COINBASE_WITNESS,
        in_type: InputType::CoinbaseWitness,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: false,
        sigops: 0,
        signatures: 0,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "a short, unusual script_sig",
        tx: testdata::TX_UNKNOWN_INPUT,
        in_type: InputType::P2sh,
        segwit: false,
        taproot: false,
        nested_segwit: false,
        native_segwit: false,
        legacy: true,
        multisig: false,
        scripthash: true,
        inscription: false,
        sigops: 0,
        signatures: 0,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "inscription reveal",
        tx: testdata::TX_INSCRIPTION,
        in_type: InputType::P2trsp,
        segwit: true,
        taproot: true,
        nested_segwit: false,
        native_segwit: true,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: true,
        sigops: 0,
        signatures: 1,
        pubkeys: 0,
        m_of_n: None,
    },
    Expected {
        name: "second inscription reveal",
        tx: testdata::TX_INSCRIPTION_2,
        in_type: InputType::P2trsp,
        segwit: true,
        taproot: true,
        nested_segwit: false,
        native_segwit: true,
        legacy: false,
        multisig: false,
        scripthash: false,
        inscription: true,
        sigops: 0,
        signatures: 1,
        pubkeys: 0,
        m_of_n: None,
    },
];

#[test]
fn input_info_of_every_input_type() {
    for case in EXPECTED {
        let tx = decode_tx(case.tx);
        let input = &tx.input[0];
        let info = InputInfo::new(input).unwrap();
        let name = case.name;

        assert_eq!(info.in_type, case.in_type, "in_type of the {name} input");
        assert_eq!(input.get_type().unwrap(), case.in_type, "{name}");
        assert_eq!(
            info.sequence, input.sequence,
            "sequence of the {name} input"
        );

        assert_eq!(
            info.is_spending_segwit(),
            case.segwit,
            "is_spending_segwit of the {name} input"
        );
        assert_eq!(
            info.is_spending_taproot(),
            case.taproot,
            "is_spending_taproot of the {name} input"
        );
        assert_eq!(
            info.is_spending_nested_segwit(),
            case.nested_segwit,
            "is_spending_nested_segwit of the {name} input"
        );
        assert_eq!(
            info.is_spending_native_segwit(),
            case.native_segwit,
            "is_spending_native_segwit of the {name} input"
        );
        assert_eq!(
            info.is_spending_legacy(),
            case.legacy,
            "is_spending_legacy of the {name} input"
        );
        assert_eq!(
            info.is_spending_multisig(),
            case.multisig,
            "is_spending_multisig of the {name} input"
        );

        assert_eq!(
            input.is_scripthash_input().unwrap(),
            case.scripthash,
            "is_scripthash_input of the {name} input"
        );
        assert_eq!(
            input.reveals_inscription().unwrap(),
            case.inscription,
            "reveals_inscription of the {name} input"
        );

        assert_eq!(info.sigops, case.sigops, "sigops of the {name} input");
        assert_eq!(
            input.sigops().unwrap(),
            case.sigops,
            "sigops of the {name} input"
        );
        assert_eq!(
            info.signature_info.len(),
            case.signatures,
            "signature count of the {name} input"
        );
        assert_eq!(
            info.pubkey_stats.len(),
            case.pubkeys,
            "pubkey count of the {name} input"
        );

        let expected_multisig = case.m_of_n.map(|(m, n, unknown_n)| MultisigInputInfo {
            m_of_n: (m, n),
            unknown_n,
        });
        assert_eq!(
            info.multisig_info, expected_multisig,
            "multisig_info of the {name} input"
        );
        assert_eq!(
            input.multisig_info().unwrap(),
            expected_multisig,
            "multisig_info of the {name} input"
        );
    }
}

/// Every variant of [InputType].
///
/// [`expected_in_table`] matches on all of them without a wildcard arm, so
/// adding a variant to the enum stops this test from compiling until the new
/// variant is classified there and listed here.
const ALL_INPUT_TYPES: [InputType; 17] = [
    InputType::P2pk,
    InputType::P2pkLaxDer,
    InputType::P2pkh,
    InputType::P2pkhLaxDer,
    InputType::P2shP2wpkh,
    InputType::P2wpkh,
    InputType::P2ms,
    InputType::P2msLaxDer,
    InputType::P2sh,
    InputType::P2shP2wsh,
    InputType::P2wsh,
    InputType::P2trkp,
    InputType::P2trsp,
    InputType::P2a,
    InputType::Coinbase,
    InputType::CoinbaseWitness,
    InputType::Unknown,
];

/// Whether [EXPECTED] is supposed to hold a row for an input of this type.
fn expected_in_table(in_type: InputType) -> bool {
    match in_type {
        // none of the test transactions has an input of these types
        InputType::P2pkLaxDer | InputType::P2msLaxDer | InputType::Unknown => false,
        InputType::P2pk
        | InputType::P2pkh
        | InputType::P2pkhLaxDer
        | InputType::P2shP2wpkh
        | InputType::P2wpkh
        | InputType::P2ms
        | InputType::P2sh
        | InputType::P2shP2wsh
        | InputType::P2wsh
        | InputType::P2trkp
        | InputType::P2trsp
        | InputType::P2a
        | InputType::Coinbase
        | InputType::CoinbaseWitness => true,
    }
}

#[test]
fn the_table_covers_every_input_type() {
    let distinct: HashSet<InputType> = ALL_INPUT_TYPES.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        ALL_INPUT_TYPES.len(),
        "ALL_INPUT_TYPES lists an input type more than once"
    );

    for in_type in ALL_INPUT_TYPES {
        let in_table = EXPECTED.iter().any(|case| case.in_type == in_type);
        if expected_in_table(in_type) {
            assert!(in_table, "no test transaction with a {} input", in_type);
        } else {
            assert!(
                !in_table,
                "the table has a {} row, so the type is no longer an exception",
                in_type
            );
        }
    }
}

#[test]
fn spending_categories_are_mutually_exclusive() {
    for case in EXPECTED {
        let tx = decode_tx(case.tx);
        let info = InputInfo::new(&tx.input[0]).unwrap();
        let name = case.name;

        // an input is nested SegWit or native SegWit, never both
        assert!(
            !(info.is_spending_nested_segwit() && info.is_spending_native_segwit()),
            "the {} input spends both nested and native SegWit",
            name
        );
        // both are SegWit spends
        assert_eq!(
            info.is_spending_nested_segwit() || info.is_spending_native_segwit(),
            info.is_spending_segwit(),
            "the {name} input disagrees about spending SegWit"
        );
        // and neither is a legacy spend
        assert!(
            !(info.is_spending_legacy() && info.is_spending_segwit()),
            "the {} input spends both legacy and SegWit",
            name
        );
        // taproot spends are native SegWit spends
        if info.is_spending_taproot() {
            assert!(
                info.is_spending_native_segwit(),
                "the {} input spends taproot but not native SegWit",
                name
            );
        }
    }
}
