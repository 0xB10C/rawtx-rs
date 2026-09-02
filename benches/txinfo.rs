use bitcoin::Transaction;
use criterion::{criterion_group, criterion_main, Criterion};
use rawtx_rs::testdata;
use rawtx_rs::tx::{TransactionSigops, TxInfo};
use std::hint::black_box;

fn decode_tx(hex: &str) -> Transaction {
    let raw = hex::decode(hex).unwrap();
    bitcoin::consensus::deserialize(&raw).unwrap()
}

fn bench_txinfo_new(c: &mut Criterion) {
    let cases: Vec<(&str, &str)> = vec![
        // Input types
        ("p2pk", testdata::TX_P2PK),
        ("p2pkh", testdata::TX_P2PKH),
        ("p2pkh_lax_der", testdata::TX_P2PKH_LAX_DER),
        ("p2sh", testdata::TX_P2SH),
        ("p2sh_rsk", testdata::TX_P2SH_RSK),
        ("p2sh_p2wpkh", testdata::TX_P2SH_P2WPKH),
        ("p2sh_p2wsh", testdata::TX_P2SH_P2WSH),
        ("p2wpkh", testdata::TX_P2WPKH),
        ("p2wsh", testdata::TX_P2WSH),
        ("p2wsh_non_multisig", testdata::TX_P2WSH_NON_MULTISIG),
        ("p2tr_keypath", testdata::TX_P2TRKP),
        ("p2tr_scriptpath", testdata::TX_P2TRSP),
        ("p2a", testdata::TX_P2A),
        ("p2ms_1of2", testdata::TX_P2MS_1OF2),
        ("p2ms_2of3", testdata::TX_P2MS_2OF3),
        // Coinbase
        ("coinbase", testdata::TX_COINBASE),
        ("coinbase_2", testdata::TX_COINBASE_2),
        ("coinbase_witness", testdata::TX_COINBASE_WITNESS),
        // Inscription
        ("inscription", testdata::TX_INSCRIPTION),
        ("inscription_2", testdata::TX_INSCRIPTION_2),
        // Unknown/short input
        ("unknown_input", testdata::TX_UNKNOWN_INPUT),
        // Multi-input/output
        ("2in_4out", testdata::TX_2IN_4OUT),
        ("1in_1out", testdata::TX_1IN_1OUT),
        ("1in_2out", testdata::TX_1IN_2OUT),
        ("1in_3out_opreturn", testdata::TX_1IN_3OUT_OPRETURN),
        ("1in_6out_5opreturn", testdata::TX_1IN_6OUT_5OPRETURN),
        // BIP69
        ("bip69_1in_1out", testdata::TX_BIP69_1IN_1OUT),
        ("bip69_3in_4out", testdata::TX_BIP69_3IN_4OUT),
        ("bip69_not_compliant", testdata::TX_BIP69_NOT_COMPLIANT),
        // Output-specific types
        ("p2ms_output", testdata::TX_P2MS_OUTPUT),
        ("p2ms_output_2", testdata::TX_P2MS_OUTPUT_2),
        ("p2tr_output", testdata::TX_P2TR_OUTPUT),
        ("p2a_output", testdata::TX_P2A_OUTPUT),
        ("witness_commitment", testdata::TX_WITNESS_COMMITMENT),
        ("opreturn_omni", testdata::TX_OPRETURN_OMNI),
        ("opreturn_stacks", testdata::TX_OPRETURN_STACKS),
        // Sigops
        ("sigops_6", testdata::TX_SIGOPS_6),
        ("sigops_5", testdata::TX_SIGOPS_5),
        ("sigops_29", testdata::TX_SIGOPS_29),
        ("sigops_9", testdata::TX_SIGOPS_9),
        ("sigops_8", testdata::TX_SIGOPS_8),
        (
            "sigops_0_witness_coinbase",
            testdata::TX_SIGOPS_0_WITNESS_COINBASE,
        ),
        ("sigops_0_coinbase", testdata::TX_SIGOPS_0_COINBASE),
        ("sigops_86", testdata::TX_SIGOPS_86),
        // BIP47
        ("bip47_failure", testdata::TX_BIP47_FAILURE),
        ("bip47_1", testdata::TX_BIP47_1),
        ("bip47_2", testdata::TX_BIP47_2),
        ("bip47_3", testdata::TX_BIP47_3),
        ("bip47_4", testdata::TX_BIP47_4),
        ("bip47_5", testdata::TX_BIP47_5),
        ("bip47_6", testdata::TX_BIP47_6),
        ("bip47_7", testdata::TX_BIP47_7),
        ("bip47_8", testdata::TX_BIP47_8),
        ("bip47_9", testdata::TX_BIP47_9),
        ("bip47_10", testdata::TX_BIP47_10),
        ("bip47_11", testdata::TX_BIP47_11),
        // Coinbase OP_RETURN
        ("coinbase_opreturn_1", testdata::TX_COINBASE_OPRETURN_1),
        ("coinbase_opreturn_2", testdata::TX_COINBASE_OPRETURN_2),
        ("coinbase_opreturn_3", testdata::TX_COINBASE_OPRETURN_3),
        ("coinbase_opreturn_4", testdata::TX_COINBASE_OPRETURN_4),
        ("coinbase_opreturn_5", testdata::TX_COINBASE_OPRETURN_5),
        ("coinbase_opreturn_6", testdata::TX_COINBASE_OPRETURN_6),
        ("coinbase_opreturn_7", testdata::TX_COINBASE_OPRETURN_7),
        ("coinbase_opreturn_8", testdata::TX_COINBASE_OPRETURN_8),
        ("coinbase_opreturn_9", testdata::TX_COINBASE_OPRETURN_9),
        // Runestone
        ("runestone_1", testdata::TX_RUNESTONE_1),
        ("runestone_2", testdata::TX_RUNESTONE_2),
        ("runestone_3", testdata::TX_RUNESTONE_3),
        ("runestone_4", testdata::TX_RUNESTONE_4),
    ];

    let mut group = c.benchmark_group("txinfo_new");
    for (name, hex) in &cases {
        let tx = decode_tx(hex);
        group.bench_function(*name, |b| {
            b.iter(|| TxInfo::new(black_box(&tx)).unwrap());
        });
    }
    group.finish();
}

fn bench_txinfo_methods(c: &mut Criterion) {
    let tx = decode_tx(testdata::TX_2IN_4OUT);
    let info = TxInfo::new(&tx).unwrap();

    let mut group = c.benchmark_group("txinfo_methods");
    group.bench_function("payments", |b| {
        b.iter(|| black_box(&info).payments());
    });
    group.bench_function("is_signaling_explicit_rbf_replicability", |b| {
        b.iter(|| black_box(&info).is_signaling_explicit_rbf_replicability());
    });
    group.bench_function("is_spending_segwit", |b| {
        b.iter(|| black_box(&info).is_spending_segwit());
    });
    group.bench_function("is_spending_taproot", |b| {
        b.iter(|| black_box(&info).is_spending_taproot());
    });
    group.finish();
}

/// Compares counting sigops standalone (via [TransactionSigops], which has to
/// run input and output type detection itself) with counting them as part of
/// building a [TxInfo] (where the types are already known).
fn bench_sigops(c: &mut Criterion) {
    let cases: Vec<(&str, &str)> = vec![
        ("p2pkh", testdata::TX_P2PKH),
        ("p2sh", testdata::TX_P2SH),
        ("p2sh_rsk", testdata::TX_P2SH_RSK),
        ("p2sh_p2wsh", testdata::TX_P2SH_P2WSH),
        ("p2wpkh", testdata::TX_P2WPKH),
        ("p2wsh", testdata::TX_P2WSH),
        ("p2tr_keypath", testdata::TX_P2TRKP),
        ("p2tr_scriptpath", testdata::TX_P2TRSP),
        ("p2ms_2of3", testdata::TX_P2MS_2OF3),
        ("coinbase", testdata::TX_COINBASE),
        ("sigops_86", testdata::TX_SIGOPS_86),
    ];

    // sigops counted standalone, without a TxInfo
    let mut group = c.benchmark_group("sigops_standalone");
    for (name, hex) in &cases {
        let tx = decode_tx(hex);
        group.bench_function(*name, |b| {
            b.iter(|| black_box(&tx).sigops().unwrap());
        });
    }
    group.finish();

    // building a TxInfo and reading the sigops it counted along the way
    let mut group = c.benchmark_group("sigops_via_txinfo");
    for (name, hex) in &cases {
        let tx = decode_tx(hex);
        group.bench_function(*name, |b| {
            b.iter(|| TxInfo::new(black_box(&tx)).unwrap().sigops());
        });
    }
    group.finish();

    // building a TxInfo and then counting the sigops standalone. This is what
    // callers had to do before TxInfo counted sigops itself.
    let mut group = c.benchmark_group("sigops_txinfo_and_standalone");
    for (name, hex) in &cases {
        let tx = decode_tx(hex);
        group.bench_function(*name, |b| {
            b.iter(|| {
                let info = TxInfo::new(black_box(&tx)).unwrap();
                black_box(info);
                black_box(&tx).sigops().unwrap()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_txinfo_new,
    bench_txinfo_methods,
    bench_sigops
);
criterion_main!(benches);
