//! Information about Bitcoin transaction outputs.

use crate::script::{Multisig, PubKeyInfo};
use bitcoin::{blockdata::opcodes::all as opcodes, script, Amount, TxOut};
use std::{error, fmt};

#[derive(Debug, Clone)]
pub enum OutputError {
    PubkeyInfo(script::Error),
}

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OutputError::PubkeyInfo(e) => {
                write!(f, "Could not extract pubkey infos from input: {}", e)
            }
        }
    }
}

impl error::Error for OutputError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            OutputError::PubkeyInfo(ref e) => Some(e),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct OutputInfo {
    pub out_type: OutputType,
    pub value: Amount,
    pub pubkey_stats: Vec<PubKeyInfo>,
    /// Number of sigops this output contributes to the block sigop limit. These
    /// are scaled by a factor of four.
    pub sigops: usize,
}

impl OutputInfo {
    pub fn new(output: &TxOut) -> Result<OutputInfo, OutputError> {
        let out_type = output.get_type();
        Ok(OutputInfo {
            value: Amount::from_sat(output.value.to_sat()),
            pubkey_stats: PubKeyInfo::from_output_with_type(output, out_type)?,
            sigops: output.sigops_with_type(out_type),
            out_type,
        })
    }

    /// Returns true if the output is an OP_RETURN output (of any [OpReturnFlavor]).
    pub fn is_opreturn(&self) -> bool {
        matches!(self.out_type, OutputType::OpReturn(_))
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum OutputType {
    P2pk,
    P2pkh,
    P2wpkhV0,
    P2ms,
    P2sh,
    P2wshV0,
    OpReturn(OpReturnFlavor),
    P2tr,
    P2a,
    Unknown,
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum OpReturnFlavor {
    Unspecified,
    WitnessCommitment,
    Omni,
    /// Stacks version 2 blockcommit. OP_RETURN start with `X2[`.
    /// https://forum.stacks.org/t/op-return-outputs/12000
    StacksBlockCommit,
    Len1Byte,
    Len20Byte,
    Len80Byte,
    Bip47PaymentCode,
    /// A Rootstock (https://rootstock.io/) coinbase OP_RETURN marker.
    /// Documented on https://dev.rootstock.io/node-operators/merged-mining/getting-started/
    RSKBlock,
    /// A CoreDao (https://coredao.org/) coinbase OP_RETURN marker.
    /// Documented on https://github.com/coredao-org/docs/blob/main/docs/become-a-delegator/delegators/delegating-hash.md#implementation
    CoreDao,
    /// A ExSat (https://exsat.network/) coinbase OP_RETURN marker.
    /// Documented on https://docs.exsat.network/guides-of-data-consensus/others/operation-references/synchronizer-operations/synchronizer-registration#register-on-chain-via-op_return
    ExSat,
    /// A HathorNetwork (https://hathor.network/) coinbase OP_RETURN marker.
    /// Documented on https://github.com/HathorNetwork/rfcs/blob/master/text/0006-merged-mining-with-bitcoin.md
    HathorNetwork,
    /// A Ordinals Runestone
    /// Documented on https://docs.ordinals.com/runes.html
    Runestone,
}

impl fmt::Display for OpReturnFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpReturnFlavor::Unspecified => write!(f, "OP_RETURN"),
            OpReturnFlavor::WitnessCommitment => write!(f, "Witness Commitment"),
            OpReturnFlavor::Omni => write!(f, "OP_RETURN (OmniLayer)"),
            OpReturnFlavor::StacksBlockCommit => write!(f, "OP_RETURN (Stacks v2 blockcommit)"),
            OpReturnFlavor::Len1Byte => write!(f, "OP_RETURN (0 byte)"),
            OpReturnFlavor::Len20Byte => write!(f, "OP_RETURN (20 byte)"),
            OpReturnFlavor::Len80Byte => write!(f, "OP_RETURN (80 byte)"),
            OpReturnFlavor::Bip47PaymentCode => write!(f, "OP_RETURN (BIP 47 Payment Code)"),
            OpReturnFlavor::RSKBlock => write!(f, "OP_RETURN (Rootstock merge mining info)"),
            OpReturnFlavor::CoreDao => write!(f, "OP_RETURN (CoreDao delegation info)"),
            OpReturnFlavor::ExSat => write!(f, "OP_RETURN (ExSat info)"),
            OpReturnFlavor::HathorNetwork => write!(f, "OP_RETURN (HatorNetwork aux_block_hash)"),
            OpReturnFlavor::Runestone => write!(f, "OP_RETURN (Runestone)"),
        }
    }
}

impl fmt::Display for OutputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputType::P2pk => write!(f, "P2PK"),
            OutputType::P2pkh => write!(f, "P2PKH"),
            OutputType::P2wpkhV0 => write!(f, "P2WPKH v0"),
            OutputType::P2ms => write!(f, "P2MS"),
            OutputType::P2sh => write!(f, "P2SH"),
            OutputType::P2wshV0 => write!(f, "P2WSH v0"),
            OutputType::OpReturn(flavor) => write!(f, "{}", flavor),
            OutputType::P2tr => write!(f, "P2TR"),
            OutputType::P2a => write!(f, "P2A"),
            OutputType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

pub trait OutputTypeDetection {
    fn get_type(&self) -> OutputType;

    fn is_p2ms(&self) -> bool;
    fn is_p2tr(&self) -> bool;
    fn is_p2a(&self) -> bool;

    // OP_RETURN flavor detection
    fn is_witness_commitment(&self) -> bool;
    fn is_opreturn_omni(&self) -> bool;
    fn is_opreturn_stacks_blockcommit(&self) -> bool;
    fn is_opreturn_with_len(&self, length: usize) -> bool;
    fn is_opreturn_bip47_payment_code(&self) -> bool;
    fn is_opreturn_rsk_block(&self) -> bool;
    fn is_opreturn_coredao(&self) -> bool;
    fn is_opreturn_exsat(&self) -> bool;
    fn is_opreturn_hathor(&self) -> bool;
    fn is_opreturn_runestone(&self) -> bool;
}

impl OutputTypeDetection for TxOut {
    fn get_type(&self) -> OutputType {
        if self.script_pubkey.is_p2pkh() {
            OutputType::P2pkh
        } else if self.script_pubkey.is_p2sh() {
            OutputType::P2sh
        } else if self.script_pubkey.is_p2wpkh() {
            OutputType::P2wpkhV0
        } else if self.script_pubkey.is_p2wsh() {
            OutputType::P2wshV0
        } else if self.is_p2tr() {
            OutputType::P2tr
        } else if self.is_p2a() {
            OutputType::P2a
        } else if self.script_pubkey.is_op_return() {
            if self.is_witness_commitment() {
                return OutputType::OpReturn(OpReturnFlavor::WitnessCommitment);
            } else if self.is_opreturn_omni() {
                return OutputType::OpReturn(OpReturnFlavor::Omni);
            } else if self.is_opreturn_stacks_blockcommit() {
                return OutputType::OpReturn(OpReturnFlavor::StacksBlockCommit);
            } else if self.is_opreturn_bip47_payment_code() {
                return OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode);
            } else if self.is_opreturn_rsk_block() {
                return OutputType::OpReturn(OpReturnFlavor::RSKBlock);
            } else if self.is_opreturn_coredao() {
                return OutputType::OpReturn(OpReturnFlavor::CoreDao);
            } else if self.is_opreturn_exsat() {
                return OutputType::OpReturn(OpReturnFlavor::ExSat);
            } else if self.is_opreturn_hathor() {
                return OutputType::OpReturn(OpReturnFlavor::HathorNetwork);
            } else if self.is_opreturn_runestone() {
                return OutputType::OpReturn(OpReturnFlavor::Runestone);
            } else if self.is_opreturn_with_len(1) {
                return OutputType::OpReturn(OpReturnFlavor::Len1Byte);
            } else if self.is_opreturn_with_len(20) {
                return OutputType::OpReturn(OpReturnFlavor::Len20Byte);
            // catch-all for 80 byte OP_RETURNs. Inlcude known flavors before this one
            } else if self.is_opreturn_with_len(80) {
                return OutputType::OpReturn(OpReturnFlavor::Len80Byte);
            }
            OutputType::OpReturn(OpReturnFlavor::Unspecified)
        } else if self.script_pubkey.is_p2pk() {
            OutputType::P2pk
        } else if self.is_p2ms() {
            OutputType::P2ms
        } else {
            OutputType::Unknown
        }
    }

    /// Checks if an output pays to a P2MS script.
    ///
    /// A P2MS output has a standard OP_CHECKMULTSIG template as usually seen in
    /// e.g. P2SH redeemscripts as script_pubkey. N and M (n-of-m) can't be
    /// bigger than 3 and m must be bigger than or equal to n;
    /// `script_pubkey: [ <OP_PUSHNUM_N>   M * <pubkey>   <OP_PUSHNUM_M> <OP_CHECKMULTISIG> ]`
    fn is_p2ms(&self) -> bool {
        if let Ok(Some(n_of_m)) = self.script_pubkey.get_opcheckmultisig_n_m() {
            let n = n_of_m.0;
            let m = n_of_m.1;
            if n <= 3 && m <= 3 && m >= n {
                return true;
            }
        }
        false
    }

    /// Checks if an output pays to a P2TR script.
    ///
    /// A P2TR output pushes the witness version 1 followed by a 32-byte schnorr-pubkey
    /// `script_pubkey: [ OP_PUSHNUM_1  <32-byte pubkey> ]`
    fn is_p2tr(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        if script_pubkey_bytes.len() == 34
            && script_pubkey_bytes[0] == opcodes::OP_PUSHNUM_1.to_u8()
            && script_pubkey_bytes[1] == opcodes::OP_PUSHBYTES_32.to_u8()
        {
            return true;
        }
        false
    }

    /// Checks if an output pays to a P2A script.
    ///
    /// A P2A output pushes the witness version 1 followed by the 2 bytes hex-encoded as 4e73
    /// `script_pubkey: [ OP_PUSHNUM_1  <4e73> ]`
    fn is_p2a(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        script_pubkey_bytes.len() == 4
            && script_pubkey_bytes[0] == opcodes::OP_PUSHNUM_1.to_u8()
            && script_pubkey_bytes[1] == opcodes::OP_PUSHBYTES_2.to_u8()
            && script_pubkey_bytes[2] == 0x4eu8
            && script_pubkey_bytes[3] == 0x73u8
    }

    /// Checks if an output is a OP_RETURN output meeting the requirements for an wittness commitment
    /// as found in Coinbase transactions.
    ///
    /// A witness commitment is atleast 38 bytes long and starts with `6a24aa21a9ed`. More details
    /// can be found in [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#commitment-structure).
    fn is_witness_commitment(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        if script_pubkey_bytes.len() >= 38
            && script_pubkey_bytes[0] == 0x6A
            && script_pubkey_bytes[1] == 0x24
            && script_pubkey_bytes[2] == 0xAA
            && script_pubkey_bytes[3] == 0x21
            && script_pubkey_bytes[4] == 0xA9
            && script_pubkey_bytes[5] == 0xED
        {
            return true;
        }
        false
    }

    /// Checks if an output is a OP_RETURN output meeting the requirements for a OmniLayer transaction.
    ///
    /// The data in OmniLayer transactions starts with the String 'omni' which is 6f 6d 6e 69 in hex.
    fn is_opreturn_omni(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        if script_pubkey_bytes.len() > 6 && script_pubkey_bytes[0] == 0x6A &&
                // -- leaving this out as its not clear if all omni op_returns have the same length
                // script_pubkey_bytes[1] == 0x14 &&
                script_pubkey_bytes[2] == 0x6f &&
                script_pubkey_bytes[3] == 0x6d &&
                script_pubkey_bytes[4] == 0x6e &&
                script_pubkey_bytes[5] == 0x69
        {
            return true;
        }
        false
    }

    /// Checks if an output is a OP_RETURN output meeting the requirements
    /// for a Stacks blockcommit.
    ///
    /// The script_pubkey of a Stacks OP_RETURN block_commit pushes 80 bytes
    /// with 'OP_PUSHDATA1 80'. These 80 bytes start with the string 'X2'
    /// which is 0x58 0x32 in hex followed a '[' (0x5b).
    /// https://forum.stacks.org/t/op-return-outputs/12000
    fn is_opreturn_stacks_blockcommit(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        if script_pubkey_bytes.len() == 83
            && script_pubkey_bytes[0] == 0x6A
            && script_pubkey_bytes[1] == 0x4C
            && script_pubkey_bytes[2] == 0x50
            && script_pubkey_bytes[3] == 0x58
            && script_pubkey_bytes[4] == 0x32
            && script_pubkey_bytes[5] == 0x5b
        {
            return true;
        }
        false
    }

    /// Checks if an output is a OP_RETURN output meeting the requirements
    /// for a resuable payment code
    ///
    /// A payment code notification transaction contains an OP_RETURN output
    /// with 80-byte payload. The script pubkey is of the structure
    /// OP_RETURN(0x6a) OP_PUSHDATA1(0x4c) 80-bytes(0x50)
    ///
    fn is_opreturn_bip47_payment_code(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        if script_pubkey_bytes.len() != 83 {
            return false;
        }

        if !(script_pubkey_bytes[0] == opcodes::OP_RETURN.to_u8()
            && script_pubkey_bytes[1] == opcodes::OP_PUSHDATA1.to_u8()
            && script_pubkey_bytes[2] == 80)
        {
            return false;
        }

        // Examine the payload
        let payload = &script_pubkey_bytes[3..];
        // Byte 0 - version should be 0x01 or 0x02
        if payload[0] != 0x01 && payload[0] != 0x02 {
            return false;
        }
        // Byte 2 - Sign should be 0x02 or 0x03
        let sign_byte = payload[2];
        if sign_byte != 0x02 && sign_byte != 0x03 {
            return false;
        }
        // Bytes 3-34 - x value, must be a member of the secp256k1 group
        // However, we can't test this as the x value is blinded / masked. Since
        // we aren't the receiver of the notifaction, we can't unblind/unmask the notification.
        // However, it shouldn't be all zeros.
        if payload[3..35].iter().all(|&b| b == 0) {
            return false;
        }

        // Bytes 35-66 - chain-code, must not be all zeros
        let chain_code = &payload[35..67];
        if chain_code.iter().all(|&b| b == 0) {
            return false;
        }
        // Bytes 67-79 - reserved for future expansion, zero-filled
        let reserved_bytes = &payload[67..80];
        if !reserved_bytes.iter().all(|&b| b == 0) {
            return false;
        }
        true
    }

    /// Checks if an output is an OP_RETURN output meeting the requirements
    /// for a RSK merge mining information output in a coinbase transaction.
    ///
    /// Format: OP_RETURN [length 0x29] [RSKBLOCK: (0x52534b424c4f434b3a)] [RskBlockInfo]
    fn is_opreturn_rsk_block(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        script_pubkey_bytes.len() == 43
            && script_pubkey_bytes[0] == 0x6A
            && script_pubkey_bytes[1] == 0x29 // length (OP_PUSHBYTES_41)
            && script_pubkey_bytes[2] == b'R'
            && script_pubkey_bytes[3] == b'S'
            && script_pubkey_bytes[4] == b'K'
            && script_pubkey_bytes[5] == b'B'
            && script_pubkey_bytes[6] == b'L'
            && script_pubkey_bytes[7] == b'O'
            && script_pubkey_bytes[8] == b'C'
            && script_pubkey_bytes[9] == b'K'
            && script_pubkey_bytes[10] == b':'
            // F2Pool is using OP_PUSHDATA1 instead of the OP_PUSHBYTES_41
            || script_pubkey_bytes.len() == 44
            && script_pubkey_bytes[0] == 0x6A
            && script_pubkey_bytes[1] == 0x4c // OP_PUSHDATA1 (F2Pool is doing this..)
            && script_pubkey_bytes[2] == 0x29 // length
            && script_pubkey_bytes[3] == b'R'
            && script_pubkey_bytes[4] == b'S'
            && script_pubkey_bytes[5] == b'K'
            && script_pubkey_bytes[6] == b'B'
            && script_pubkey_bytes[7] == b'L'
            && script_pubkey_bytes[8] == b'O'
            && script_pubkey_bytes[9] == b'C'
            && script_pubkey_bytes[10] == b'K'
            && script_pubkey_bytes[11] == b':'
    }

    /// Checks if an output is an OP_RETURN output meeting the requirements
    /// for a CORE dao output in a coinbase transaction.
    ///
    /// Format: OP_RETURN [length 0x2d] [CORE (0x434f5245)] [Version 0x01] [Delegate Information]
    fn is_opreturn_coredao(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        script_pubkey_bytes.len() == 47
            && script_pubkey_bytes[0] == 0x6A
            && script_pubkey_bytes[1] == 0x2d // length
            && script_pubkey_bytes[2] == b'C'
            && script_pubkey_bytes[3] == b'O'
            && script_pubkey_bytes[4] == b'R'
            && script_pubkey_bytes[5] == b'E'
            && script_pubkey_bytes[6] == 0x01 // version
    }

    /// Checks if an output is an OP_RETURN output meeting the requirements
    /// for a CORE dao output in a coinbase transaction.
    ///
    /// Format: OP_RETURN [length 0x12] [EXSAT (0x4558534154)] [Version 0x01] [synchronizer account]
    fn is_opreturn_exsat(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        script_pubkey_bytes.len() > 8
            && script_pubkey_bytes[0] == 0x6A
            // script_pubkey_bytes[1] is the length, but this might be different for each pool
            && script_pubkey_bytes[2] == b'E'
            && script_pubkey_bytes[3] == b'X'
            && script_pubkey_bytes[4] == b'S'
            && script_pubkey_bytes[5] == b'A'
            && script_pubkey_bytes[6] == b'T'
            && script_pubkey_bytes[7] == 0x01 // version
    }

    /// Checks if an output is an OP_RETURN output meeting the requirements
    /// for a HathorNetwork output in a coinbase transaction.
    ///
    /// Format: OP_RETURN [length 0x12] [Hath (48 61 74 68)] [aux_block_hash]
    fn is_opreturn_hathor(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        script_pubkey_bytes.len() == 38
            && script_pubkey_bytes[0] == 0x6A
            && script_pubkey_bytes[1] == 0x24 // length
            && script_pubkey_bytes[2] == b'H'
            && script_pubkey_bytes[3] == b'a'
            && script_pubkey_bytes[4] == b't'
            && script_pubkey_bytes[5] == b'h'
    }

    /// Checks if an output is an OP_RETURN output meeting the requirements
    /// for a Runestone OP_RETURN output.
    ///
    /// Format: OP_RETURN OP_PUSHNUM_13 [OP_PUSHBYTES_X]
    fn is_opreturn_runestone(&self) -> bool {
        let script_pubkey_bytes = self.script_pubkey.as_bytes();
        if script_pubkey_bytes.len() > 2
            && script_pubkey_bytes[0] == opcodes::OP_RETURN.to_u8()
            && script_pubkey_bytes[1] == opcodes::OP_PUSHNUM_13.to_u8()
        {
            for (index, inst_result) in self.script_pubkey.instructions().enumerate() {
                if let Ok(inst) = inst_result {
                    match index {
                        0 => (), // we already checked that this is an OP_RETURN
                        1 => (), // we already checked that this is an OP_PUSHNUM_13
                        _ => {
                            // all others need to be data pushes
                            match inst {
                                script::Instruction::Op(_) => {
                                    return false;
                                }
                                script::Instruction::PushBytes(_) => (),
                            }
                        }
                    }
                } else {
                    return false;
                }
            }
            return true;
        }
        false
    }

    /// Compares the data length of an OP_RETURN output with the given `data_length`. Returns
    /// true if equal.
    ///
    /// This assumes OP_RETURN use the minimal data push. That means for data shorter than
    /// or equal to (<=) 75 bytes a OP_PUSHBYTES_X is used. For longer data a OP_PUSHDATA1
    /// is used.
    fn is_opreturn_with_len(&self, data_length: usize) -> bool {
        const MIN_OPRETURN_LEN: usize = 1 + 1; // OP_RETURN OP_0
        const MAX_OPRETURN_LEN: usize = 1 + 1 + 1 + 80; // OP_RETURN OP_PUSHDATA1 data-length [80 btyes]
        const MAX_OPPUSHBYTES_LEN: usize = 1 + 1 + 75; // OP_RETURN OP_PUSHBYTES_75 [75 bytes]

        if self.script_pubkey.len() < MIN_OPRETURN_LEN
            || self.script_pubkey.len() > MAX_OPRETURN_LEN
        {
            return false;
        }

        if !self.script_pubkey.as_bytes()[0] == 0x6A {
            return false;
        }

        if self.script_pubkey.len() <= MAX_OPPUSHBYTES_LEN {
            return self.script_pubkey.len() - 1 - 1 == data_length;
        }

        if self.script_pubkey.len() > MAX_OPPUSHBYTES_LEN {
            return self.script_pubkey.len() - 1 - 1 - 1 == data_length;
        }

        false
    }
}

/// Sigops in legacy scripts are scaled by a factor of four.
const SIGOPS_SCALE_FACTOR: usize = 4;

pub trait OutputSigops {
    fn sigops(&self) -> usize;
    fn sigops_with_type(&self, out_type: OutputType) -> usize;
}

impl OutputSigops for TxOut {
    fn sigops(&self) -> usize {
        // in P2TR scripts, no sigops are counted
        if self.is_p2tr() {
            return 0;
        }

        // for example, for P2MS script_pubkeys (OP_CHECKMUTLISIG)
        SIGOPS_SCALE_FACTOR * self.script_pubkey.count_sigops_legacy()
    }

    /// Counts the sigops of an output with an already known [OutputType].
    /// Callers that built an [OutputInfo] should use this to avoid re-running
    /// the output type detection.
    fn sigops_with_type(&self, out_type: OutputType) -> usize {
        // in P2TR scripts, no sigops are counted
        if out_type == OutputType::P2tr {
            return 0;
        }

        SIGOPS_SCALE_FACTOR * self.script_pubkey.count_sigops_legacy()
    }
}

#[cfg(test)]
mod tests {
    use super::{OpReturnFlavor, OutputType, OutputTypeDetection};
    use crate::testdata;
    use bitcoin::Transaction;

    fn decode_tx(hex: &str) -> Transaction {
        let raw = hex::decode(hex).unwrap();
        bitcoin::consensus::deserialize(&raw).unwrap()
    }

    #[test]
    fn output_type_detection_p2ms() {
        let tx = decode_tx(testdata::TX_P2MS_OUTPUT);
        let out0 = &tx.output[0];
        assert!(out0.is_p2ms());
        assert_eq!(out0.get_type(), OutputType::P2ms);
    }

    #[test]
    fn output_type_detection_p2ms2() {
        let tx = decode_tx(testdata::TX_P2MS_OUTPUT_2);
        let out0 = &tx.output[0];
        assert!(out0.is_p2ms());
        assert_eq!(out0.get_type(), OutputType::P2ms);
    }

    #[test]
    fn output_type_detection_p2tr() {
        let tx = decode_tx(testdata::TX_P2TR_OUTPUT);
        let out0 = &tx.output[0];
        let out1 = &tx.output[1];
        let out3 = &tx.output[3];
        assert!(out0.is_p2tr());
        assert!(out1.is_p2tr());
        assert!(out3.is_p2tr());
        assert_eq!(out0.get_type(), OutputType::P2tr);
        assert_eq!(out1.get_type(), OutputType::P2tr);
        assert_eq!(out3.get_type(), OutputType::P2tr);
    }

    #[test]
    fn output_type_detection_witness_commitment() {
        let tx = decode_tx(testdata::TX_WITNESS_COMMITMENT);
        let out1 = &tx.output[1];
        assert!(out1.is_witness_commitment());
        assert_eq!(
            out1.get_type(),
            OutputType::OpReturn(OpReturnFlavor::WitnessCommitment)
        );
    }

    #[test]
    fn output_type_detection_opreturn_omni() {
        let tx = decode_tx(testdata::TX_OPRETURN_OMNI);
        let out2 = &tx.output[2];
        assert!(out2.is_opreturn_omni());
        assert_eq!(out2.get_type(), OutputType::OpReturn(OpReturnFlavor::Omni));
    }

    #[test]
    fn output_type_detection_opreturn_stacks_blockcommmit() {
        let tx = decode_tx(testdata::TX_OPRETURN_STACKS);
        let out2 = &tx.output[0];
        assert!(out2.is_opreturn_stacks_blockcommit());
        assert_eq!(
            out2.get_type(),
            OutputType::OpReturn(OpReturnFlavor::StacksBlockCommit)
        );
    }

    #[test]
    fn output_type_detection_p2a() {
        let tx = decode_tx(testdata::TX_P2A_OUTPUT);
        let out0 = &tx.output[0];
        let out1 = &tx.output[1];
        assert!(out0.is_p2a());
        assert!(out1.is_p2tr());
        assert_eq!(out0.get_type(), OutputType::P2a);
        assert_eq!(out1.get_type(), OutputType::P2tr);
    }

    #[test]
    fn output_type_detection_bip47_failure() {
        let tx = decode_tx(testdata::TX_BIP47_FAILURE);
        let out = &tx.output[0];
        assert!(!out.is_opreturn_bip47_payment_code());
    }

    #[test]
    fn output_type_detection_bip47_payment_code() {
        let testcases: Vec<(usize, &str)> = vec![
            (0, testdata::TX_BIP47_1),
            (0, testdata::TX_BIP47_2),
            (0, testdata::TX_BIP47_3),
            (0, testdata::TX_BIP47_4),
            (0, testdata::TX_BIP47_5),
            (1, testdata::TX_BIP47_6),
            (0, testdata::TX_BIP47_7),
            (0, testdata::TX_BIP47_8),
            (1, testdata::TX_BIP47_9),
            (1, testdata::TX_BIP47_10),
            (1, testdata::TX_BIP47_11),
        ];
        for (i, (output_index, txhex)) in testcases.iter().enumerate() {
            println!("Testing case {}", i);
            let tx = decode_tx(txhex);
            let out = &tx.output[*output_index];
            assert!(out.is_opreturn_bip47_payment_code());
            assert_eq!(
                out.get_type(),
                OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode)
            );
        }
    }

    #[test]
    fn output_type_detection_opreturn_coinbase() {
        const NA: usize = usize::MAX;
        let testcases: Vec<(usize, usize, usize, usize, &str)> = vec![
            (5, 3, 4, NA, testdata::TX_COINBASE_OPRETURN_1),
            (5, 3, 4, NA, testdata::TX_COINBASE_OPRETURN_2),
            (3, 2, NA, NA, testdata::TX_COINBASE_OPRETURN_3),
            (1, NA, NA, NA, testdata::TX_COINBASE_OPRETURN_4),
            (5, 3, NA, NA, testdata::TX_COINBASE_OPRETURN_5),
            (6, 3, 4, 5, testdata::TX_COINBASE_OPRETURN_6),
            (4, 3, NA, NA, testdata::TX_COINBASE_OPRETURN_7),
            (NA, 3, NA, NA, testdata::TX_COINBASE_OPRETURN_8),
            (6, 3, 4, 5, testdata::TX_COINBASE_OPRETURN_9),
        ];
        for (i, (rsk_out_i, coredao_out_i, exsat_out_i, hathor_out_i, txhex)) in
            testcases.iter().enumerate()
        {
            println!("Testing case {}", i);
            let tx = decode_tx(txhex);

            // not all test cases have rsk outputs..
            if *rsk_out_i != NA {
                let rsk_out = &tx.output[*rsk_out_i];
                assert!(rsk_out.is_opreturn_rsk_block());
                assert_eq!(
                    rsk_out.get_type(),
                    OutputType::OpReturn(OpReturnFlavor::RSKBlock)
                );
            }

            // not all test cases have coredao outputs..
            if *coredao_out_i != NA {
                let coredao_out = &tx.output[*coredao_out_i];
                assert!(coredao_out.is_opreturn_coredao());
                assert_eq!(
                    coredao_out.get_type(),
                    OutputType::OpReturn(OpReturnFlavor::CoreDao)
                );
            }

            // not all test cases have exsat outputs..
            if *exsat_out_i != NA {
                let exsat_out = &tx.output[*exsat_out_i];
                assert!(exsat_out.is_opreturn_exsat());
                assert_eq!(
                    exsat_out.get_type(),
                    OutputType::OpReturn(OpReturnFlavor::ExSat)
                );
            }

            // not all test cases have hathor outputs..
            if *hathor_out_i != NA {
                let hathor_out = &tx.output[*hathor_out_i];
                assert!(hathor_out.is_opreturn_hathor());
                assert_eq!(
                    hathor_out.get_type(),
                    OutputType::OpReturn(OpReturnFlavor::HathorNetwork)
                );
            }
        }
    }

    #[test]
    fn output_type_detection_opreturn_runestone() {
        let testcases: Vec<(usize, &str)> = vec![
            (0, testdata::TX_RUNESTONE_1),
            (1, testdata::TX_RUNESTONE_2),
            (1, testdata::TX_RUNESTONE_3),
            (1, testdata::TX_RUNESTONE_4),
        ];
        for (i, (output_index, txhex)) in testcases.iter().enumerate() {
            println!("Testing case {}", i);
            let tx = decode_tx(txhex);
            let out = &tx.output[*output_index];
            assert!(out.is_opreturn_runestone());
            assert_eq!(
                out.get_type(),
                OutputType::OpReturn(OpReturnFlavor::Runestone)
            );
        }
    }
}
