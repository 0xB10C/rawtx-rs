//! Checks the signatures and public keys of every test transaction against a
//! table of expected values.

use rawtx_rs::bitcoin::consensus::deserialize;
use rawtx_rs::bitcoin::Transaction;
use rawtx_rs::input::{InputType, InputTypeDetection};
use rawtx_rs::output::{OpReturnFlavor, OutputType, OutputTypeDetection};
use rawtx_rs::script::{
    DEREncoding, PubKeyInfo, PubkeyType, Signature, SignatureInfo, SignatureType,
};
use rawtx_rs::testdata;

struct Testcase {
    name: &'static str,
    rawtx: &'static str,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

struct Input {
    in_type: InputType,
    signatures: Vec<ExpectedSignature>,
    pubkeys: Vec<PubKeyInfo>,
}

struct Output {
    out_type: OutputType,
    pubkeys: Vec<PubKeyInfo>,
}

struct ExpectedSignature {
    length: usize,
    sig_hash: u8,
    low_r: bool,
    low_s: bool,
    der_encoded: DEREncoding,
}

/// Shorthand for an expected signature.
fn sig(
    length: usize,
    sig_hash: u8,
    low_r: bool,
    low_s: bool,
    der_encoded: DEREncoding,
) -> ExpectedSignature {
    ExpectedSignature {
        length,
        sig_hash,
        low_r,
        low_s,
        der_encoded,
    }
}

/// Shorthand for an expected public key.
fn pk(compressed: bool, pubkey_type: PubkeyType) -> PubKeyInfo {
    PubKeyInfo {
        compressed,
        pubkey_type,
    }
}

/// Shorthand for a number of identical compressed ECDSA public keys.
fn compressed_ecdsa_keys(count: usize) -> Vec<PubKeyInfo> {
    (0..count).map(|_| pk(true, PubkeyType::ECDSA)).collect()
}

fn testcases() -> Vec<Testcase> {
    vec![
        Testcase {
            name: "TX_P2PK",
            rawtx: testdata::TX_P2PK,
            inputs: vec![Input {
                in_type: InputType::P2pk,
                signatures: vec![sig(71, 0x01, true, true, DEREncoding::Valid)],
                pubkeys: vec![],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2pkh,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2PKH",
            rawtx: testdata::TX_P2PKH,
            inputs: vec![Input {
                in_type: InputType::P2pkh,
                signatures: vec![sig(71, 0x01, true, true, DEREncoding::Valid)],
                pubkeys: vec![pk(true, PubkeyType::ECDSA)],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2pkh,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2PKH_LAX_DER",
            rawtx: testdata::TX_P2PKH_LAX_DER,
            inputs: vec![Input {
                in_type: InputType::P2pkhLaxDer,
                signatures: vec![sig(75, 0x01, true, true, DEREncoding::SigTooLong)],
                pubkeys: vec![pk(false, PubkeyType::ECDSA)],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2pkh,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2SH",
            rawtx: testdata::TX_P2SH,
            inputs: vec![Input {
                in_type: InputType::P2sh,
                signatures: vec![sig(71, 0x01, true, true, DEREncoding::Valid)],
                pubkeys: vec![pk(true, PubkeyType::ECDSA), pk(true, PubkeyType::ECDSA)],
            }],
            outputs: vec![
                Output {
                    out_type: OutputType::P2pkh,
                    pubkeys: vec![],
                },
                Output {
                    out_type: OutputType::P2sh,
                    pubkeys: vec![],
                },
            ],
        },
        Testcase {
            name: "TX_P2SH_RSK",
            rawtx: testdata::TX_P2SH_RSK,
            inputs: vec![Input {
                in_type: InputType::P2sh,
                signatures: vec![
                    sig(72, 0x01, false, true, DEREncoding::Valid),
                    sig(71, 0x01, true, true, DEREncoding::Valid),
                    sig(71, 0x01, true, true, DEREncoding::Valid),
                    sig(72, 0x01, false, true, DEREncoding::Valid),
                    sig(72, 0x01, false, true, DEREncoding::Valid),
                ],
                pubkeys: compressed_ecdsa_keys(13),
            }],
            outputs: vec![
                Output {
                    out_type: OutputType::P2pkh,
                    pubkeys: vec![],
                },
                Output {
                    out_type: OutputType::P2sh,
                    pubkeys: vec![],
                },
            ],
        },
        Testcase {
            name: "TX_P2SH_P2WPKH",
            rawtx: testdata::TX_P2SH_P2WPKH,
            inputs: vec![Input {
                in_type: InputType::P2shP2wpkh,
                signatures: vec![sig(71, 0x01, true, true, DEREncoding::Valid)],
                pubkeys: vec![pk(true, PubkeyType::ECDSA)],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2sh,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2SH_P2WSH",
            rawtx: testdata::TX_P2SH_P2WSH,
            inputs: vec![Input {
                in_type: InputType::P2shP2wsh,
                signatures: vec![
                    sig(72, 0x01, false, true, DEREncoding::Valid),
                    sig(71, 0x01, true, true, DEREncoding::Valid),
                ],
                pubkeys: vec![
                    pk(true, PubkeyType::ECDSA),
                    pk(true, PubkeyType::ECDSA),
                    pk(true, PubkeyType::ECDSA),
                ],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2pkh,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2WPKH",
            rawtx: testdata::TX_P2WPKH,
            inputs: vec![Input {
                in_type: InputType::P2wpkh,
                signatures: vec![sig(71, 0x01, true, true, DEREncoding::Valid)],
                pubkeys: vec![pk(true, PubkeyType::ECDSA)],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2wpkhV0,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2WSH",
            rawtx: testdata::TX_P2WSH,
            inputs: vec![Input {
                in_type: InputType::P2wsh,
                signatures: vec![
                    sig(71, 0x01, true, true, DEREncoding::Valid),
                    sig(72, 0x01, false, true, DEREncoding::Valid),
                ],
                pubkeys: vec![pk(true, PubkeyType::ECDSA), pk(true, PubkeyType::ECDSA)],
            }],
            outputs: vec![
                Output {
                    out_type: OutputType::P2sh,
                    pubkeys: vec![],
                },
                Output {
                    out_type: OutputType::P2wshV0,
                    pubkeys: vec![],
                },
            ],
        },
        Testcase {
            name: "TX_P2WSH_NON_MULTISIG",
            rawtx: testdata::TX_P2WSH_NON_MULTISIG,
            inputs: vec![Input {
                in_type: InputType::P2wsh,
                signatures: vec![sig(72, 0x01, false, true, DEREncoding::Valid)],
                pubkeys: vec![],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2wpkhV0,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2TRKP",
            rawtx: testdata::TX_P2TRKP,
            inputs: vec![
                Input {
                    in_type: InputType::P2trkp,
                    signatures: vec![sig(65, 0x01, true, true, DEREncoding::NotApplicable)],
                    pubkeys: vec![],
                },
                Input {
                    in_type: InputType::P2wpkh,
                    signatures: vec![sig(71, 0x01, true, true, DEREncoding::Valid)],
                    pubkeys: vec![pk(true, PubkeyType::ECDSA)],
                },
            ],
            outputs: vec![
                Output {
                    out_type: OutputType::P2tr,
                    pubkeys: vec![pk(true, PubkeyType::Schnorr)],
                },
                Output {
                    out_type: OutputType::P2wpkhV0,
                    pubkeys: vec![],
                },
            ],
        },
        Testcase {
            name: "TX_P2TRSP",
            rawtx: testdata::TX_P2TRSP,
            inputs: vec![Input {
                in_type: InputType::P2trsp,
                signatures: vec![sig(64, 0x01, true, false, DEREncoding::NotApplicable)],
                pubkeys: vec![],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2wpkhV0,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2MS_1OF2",
            rawtx: testdata::TX_P2MS_1OF2,
            inputs: vec![Input {
                in_type: InputType::P2ms,
                signatures: vec![sig(73, 0x01, false, false, DEREncoding::Valid)],
                pubkeys: vec![],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2ms,
                pubkeys: vec![pk(true, PubkeyType::ECDSA)],
            }],
        },
        Testcase {
            name: "TX_P2MS_2OF3",
            rawtx: testdata::TX_P2MS_2OF3,
            inputs: vec![Input {
                in_type: InputType::P2ms,
                signatures: vec![
                    sig(72, 0x01, false, true, DEREncoding::Valid),
                    sig(72, 0x01, false, true, DEREncoding::Valid),
                ],
                pubkeys: vec![],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2pkh,
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_P2TR_OUTPUT",
            rawtx: testdata::TX_P2TR_OUTPUT,
            inputs: vec![
                Input {
                    in_type: InputType::P2wpkh,
                    signatures: vec![sig(71, 0x01, true, true, DEREncoding::Valid)],
                    pubkeys: vec![pk(true, PubkeyType::ECDSA)],
                },
                Input {
                    in_type: InputType::P2wpkh,
                    signatures: vec![sig(71, 0x01, true, true, DEREncoding::Valid)],
                    pubkeys: vec![pk(true, PubkeyType::ECDSA)],
                },
            ],
            outputs: vec![
                Output {
                    out_type: OutputType::P2tr,
                    pubkeys: vec![pk(true, PubkeyType::Schnorr)],
                },
                Output {
                    out_type: OutputType::P2tr,
                    pubkeys: vec![pk(true, PubkeyType::Schnorr)],
                },
                Output {
                    out_type: OutputType::P2wpkhV0,
                    pubkeys: vec![],
                },
                Output {
                    out_type: OutputType::P2tr,
                    pubkeys: vec![pk(true, PubkeyType::Schnorr)],
                },
            ],
        },
        Testcase {
            name: "TX_P2MS_OUTPUT",
            rawtx: testdata::TX_P2MS_OUTPUT,
            inputs: vec![Input {
                in_type: InputType::P2pkh,
                signatures: vec![sig(70, 0x01, true, true, DEREncoding::Valid)],
                pubkeys: vec![pk(true, PubkeyType::ECDSA)],
            }],
            outputs: vec![
                Output {
                    out_type: OutputType::P2ms,
                    pubkeys: vec![pk(true, PubkeyType::ECDSA)],
                },
                Output {
                    out_type: OutputType::P2pkh,
                    pubkeys: vec![],
                },
                Output {
                    out_type: OutputType::P2pkh,
                    pubkeys: vec![],
                },
            ],
        },
        Testcase {
            name: "TX_P2MS_OUTPUT_2",
            rawtx: testdata::TX_P2MS_OUTPUT_2,
            inputs: vec![Input {
                in_type: InputType::P2pkh,
                signatures: vec![sig(72, 0x01, false, true, DEREncoding::Valid)],
                pubkeys: vec![pk(true, PubkeyType::ECDSA)],
            }],
            outputs: vec![
                Output {
                    out_type: OutputType::P2ms,
                    pubkeys: vec![pk(true, PubkeyType::ECDSA)],
                },
                Output {
                    out_type: OutputType::P2pkh,
                    pubkeys: vec![],
                },
            ],
        },
        Testcase {
            name: "TX_INSCRIPTION",
            rawtx: testdata::TX_INSCRIPTION,
            inputs: vec![Input {
                in_type: InputType::P2trsp,
                signatures: vec![sig(64, 0x01, false, true, DEREncoding::NotApplicable)],
                pubkeys: vec![],
            }],
            outputs: vec![Output {
                out_type: OutputType::P2tr,
                pubkeys: vec![pk(true, PubkeyType::Schnorr)],
            }],
        },
        Testcase {
            name: "TX_P2A",
            rawtx: testdata::TX_P2A,
            inputs: vec![Input {
                in_type: InputType::P2a,
                signatures: vec![],
                pubkeys: vec![],
            }],
            outputs: vec![Output {
                out_type: OutputType::OpReturn(OpReturnFlavor::Unspecified),
                pubkeys: vec![],
            }],
        },
        Testcase {
            name: "TX_UNKNOWN_INPUT",
            rawtx: testdata::TX_UNKNOWN_INPUT,
            inputs: vec![
                Input {
                    in_type: InputType::P2sh,
                    signatures: vec![],
                    pubkeys: vec![],
                },
                Input {
                    in_type: InputType::P2sh,
                    signatures: vec![],
                    pubkeys: vec![],
                },
                Input {
                    in_type: InputType::P2sh,
                    signatures: vec![],
                    pubkeys: vec![],
                },
            ],
            outputs: vec![Output {
                out_type: OutputType::P2pkh,
                pubkeys: vec![],
            }],
        },
    ]
}

#[test]
fn signatures_and_pubkeys_of_the_test_transactions() {
    for testcase in testcases().iter() {
        let tx: Transaction = deserialize(&hex::decode(testcase.rawtx).unwrap()).unwrap();
        assert_eq!(tx.input.len(), testcase.inputs.len(), "{}", testcase.name);
        assert_eq!(tx.output.len(), testcase.outputs.len(), "{}", testcase.name);

        for (index, (input, expected)) in tx.input.iter().zip(testcase.inputs.iter()).enumerate() {
            let at = format!("{} input {}", testcase.name, index);

            assert_eq!(input.get_type().unwrap(), expected.in_type, "{}", at);

            let signature_infos = SignatureInfo::all_from(input).unwrap();
            assert_eq!(
                signature_infos.len(),
                expected.signatures.len(),
                "number of signatures of {}",
                at
            );
            // Passing the input type explicitly must give the same result.
            assert_eq!(
                SignatureInfo::all_from_with_type(input, expected.in_type).unwrap(),
                signature_infos,
                "{}",
                at
            );

            for (i, (info, expected)) in signature_infos
                .iter()
                .zip(expected.signatures.iter())
                .enumerate()
            {
                let at = format!("{} signature {}", at, i);
                assert_eq!(info.length, expected.length, "length of {}", at);
                assert_eq!(info.sig_hash, expected.sig_hash, "sighash flag of {}", at);
                assert_eq!(info.low_r(), expected.low_r, "low r of {}", at);
                assert_eq!(info.low_s(), expected.low_s, "low s of {}", at);
                assert_eq!(
                    info.der_encoded, expected.der_encoded,
                    "DER encoding of {}",
                    at
                );

                // A Schnorr signature is never DER encoded and an ECDSA
                // signature always is.
                match info.signature {
                    SignatureType::Ecdsa(_) => {
                        assert_ne!(info.der_encoded, DEREncoding::NotApplicable, "{}", at)
                    }
                    SignatureType::Schnorr(_) => {
                        assert_eq!(info.der_encoded, DEREncoding::NotApplicable, "{}", at)
                    }
                }
            }

            assert_eq!(
                PubKeyInfo::from_input(input).unwrap(),
                expected.pubkeys,
                "public keys of {}",
                at
            );
            assert_eq!(
                PubKeyInfo::from_input_with_type(input, expected.in_type).unwrap(),
                expected.pubkeys,
                "public keys of {}",
                at
            );
        }

        for (index, (output, expected)) in tx.output.iter().zip(testcase.outputs.iter()).enumerate()
        {
            let at = format!("{} output {}", testcase.name, index);

            assert_eq!(output.get_type(), expected.out_type, "{}", at);
            assert_eq!(
                PubKeyInfo::from_output(output).unwrap(),
                expected.pubkeys,
                "public keys of {}",
                at
            );
            assert_eq!(
                PubKeyInfo::from_output_with_type(output, expected.out_type).unwrap(),
                expected.pubkeys,
                "public keys of {}",
                at
            );
        }
    }
}

/// Every signature found in a test transaction must also be recognized as a
/// signature by the byte slice based helpers.
#[test]
fn found_signatures_are_recognized_as_signatures() {
    let mut ecdsa = 0;
    let mut schnorr = 0;

    for rawtx in testdata::ALL_TRANSACTIONS.iter() {
        let tx: Transaction = deserialize(&hex::decode(rawtx).unwrap()).unwrap();

        for input in tx.input.iter() {
            for info in SignatureInfo::all_from(input).unwrap().iter() {
                match info.signature {
                    SignatureType::Ecdsa(signature) => {
                        ecdsa += 1;
                        let mut bytes = signature.serialize_der().to_vec();
                        bytes.push(info.sig_hash);
                        assert!(bytes.is_ecdsa_signature(false));
                        assert!(bytes.is_signature());
                        // is_schnorr_signature() is a length check, so a
                        // short DER signature of 64 or 65 bytes passes it
                        // too. Two inputs of TX_MANY_TYPES have signatures
                        // ground down that far.
                        if !matches!(bytes.len(), 64 | 65) {
                            assert!(!bytes.is_schnorr_signature());
                        }
                    }
                    SignatureType::Schnorr(signature) => {
                        schnorr += 1;
                        let serialized: [u8; 64] = *signature.as_ref();
                        let mut bytes = serialized.to_vec();
                        assert_eq!(bytes.len(), 64);
                        assert!(bytes.is_schnorr_signature());
                        assert!(bytes.is_signature());
                        bytes.push(info.sig_hash);
                        assert!(bytes.is_schnorr_signature());
                        assert!(!bytes.is_ecdsa_signature(false));
                    }
                }
            }
        }
    }

    // Make sure we actually looked at signatures of both kinds.
    assert!(ecdsa > 20, "only found {} ECDSA signatures", ecdsa);
    assert!(schnorr > 2, "only found {} Schnorr signatures", schnorr);
}
