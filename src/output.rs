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
                write!(f, "Could not extract pubkey infos from output: {}", e)
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
            OpReturnFlavor::Len1Byte => write!(f, "OP_RETURN (1 byte)"),
            OpReturnFlavor::Len20Byte => write!(f, "OP_RETURN (20 byte)"),
            OpReturnFlavor::Len80Byte => write!(f, "OP_RETURN (80 byte)"),
            OpReturnFlavor::Bip47PaymentCode => write!(f, "OP_RETURN (BIP 47 Payment Code)"),
            OpReturnFlavor::RSKBlock => write!(f, "OP_RETURN (Rootstock merge mining info)"),
            OpReturnFlavor::CoreDao => write!(f, "OP_RETURN (CoreDao delegation info)"),
            OpReturnFlavor::ExSat => write!(f, "OP_RETURN (ExSat info)"),
            OpReturnFlavor::HathorNetwork => write!(f, "OP_RETURN (HathorNetwork aux_block_hash)"),
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
        script_pubkey_bytes.len() == 34
            && script_pubkey_bytes[0] == opcodes::OP_PUSHNUM_1.to_u8()
            && script_pubkey_bytes[1] == opcodes::OP_PUSHBYTES_32.to_u8()
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
        script_pubkey_bytes.len() >= 38
            && script_pubkey_bytes[0] == 0x6A
            && script_pubkey_bytes[1] == 0x24
            && script_pubkey_bytes[2] == 0xAA
            && script_pubkey_bytes[3] == 0x21
            && script_pubkey_bytes[4] == 0xA9
            && script_pubkey_bytes[5] == 0xED
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
        script_pubkey_bytes.len() == 83
            && script_pubkey_bytes[0] == 0x6A
            && script_pubkey_bytes[1] == 0x4C
            && script_pubkey_bytes[2] == 0x50
            && script_pubkey_bytes[3] == 0x58
            && script_pubkey_bytes[4] == 0x32
            && script_pubkey_bytes[5] == 0x5b
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
        reserved_bytes.iter().all(|&b| b == 0)
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

        if self.script_pubkey.as_bytes()[0] != 0x6A {
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
    use super::{OpReturnFlavor, OutputError, OutputType, OutputTypeDetection};
    use crate::testdata;
    use bitcoin::blockdata::opcodes::all as opcodes;
    use bitcoin::script::{self, PushBytesBuf};
    use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
    use std::convert::TryFrom;

    fn decode_tx(hex: &str) -> Transaction {
        let raw = hex::decode(hex).unwrap();
        bitcoin::consensus::deserialize(&raw).unwrap()
    }

    fn output_with_script(script_pubkey: ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(0),
            script_pubkey,
        }
    }

    fn script_output(script_pubkey_bytes: Vec<u8>) -> TxOut {
        output_with_script(ScriptBuf::from_bytes(script_pubkey_bytes))
    }

    /// Builds a `n-of-m` P2MS script_pubkey:
    /// OP_PUSHNUM_n <m * 33-byte push> OP_PUSHNUM_m OP_CHECKMULTISIG
    fn p2ms_output(n: u8, m: u8) -> TxOut {
        let mut bytes = vec![opcodes::OP_PUSHNUM_1.to_u8() + n - 1];
        for _ in 0..m {
            bytes.push(opcodes::OP_PUSHBYTES_33.to_u8());
            bytes.extend_from_slice(&[0x02; 33]);
        }
        bytes.push(opcodes::OP_PUSHNUM_1.to_u8() + m - 1);
        bytes.push(opcodes::OP_CHECKMULTISIG.to_u8());
        script_output(bytes)
    }

    /// Returns a copy of `bytes` with the byte at `index` replaced by `byte`.
    fn with_byte_replaced(bytes: &[u8], index: usize, byte: u8) -> Vec<u8> {
        let mut bytes = bytes.to_vec();
        bytes[index] = byte;
        bytes
    }

    fn opreturn_output(data: &[u8]) -> TxOut {
        output_with_script(
            script::Builder::new()
                .push_opcode(opcodes::OP_RETURN)
                .push_slice(PushBytesBuf::try_from(data.to_vec()).unwrap())
                .into_script(),
        )
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
    fn p2ms_detection_n_of_m_bounds() {
        // Up to three signatures and three public keys are detected as P2MS,
        // as long as there are at least as many public keys as signatures.
        for (n, m) in [(1u8, 1u8), (1, 2), (1, 3), (2, 2), (2, 3), (3, 3)].iter() {
            let out = p2ms_output(*n, *m);
            assert!(out.is_p2ms(), "{}-of-{} should be a P2MS output", n, m);
            assert_eq!(out.get_type(), OutputType::P2ms);
        }

        // More than three public keys isn't detected as P2MS.
        for (n, m) in [(1u8, 4u8), (3, 4), (4, 4), (1, 5)].iter() {
            let out = p2ms_output(*n, *m);
            assert!(!out.is_p2ms(), "{}-of-{} shouldn't be a P2MS output", n, m);
            assert_eq!(out.get_type(), OutputType::Unknown);
        }

        // Asking for more signatures than there are public keys isn't P2MS either.
        for (n, m) in [(2u8, 1u8), (3, 1), (3, 2)].iter() {
            let out = p2ms_output(*n, *m);
            assert!(!out.is_p2ms(), "{}-of-{} shouldn't be a P2MS output", n, m);
            assert_eq!(out.get_type(), OutputType::Unknown);
        }
    }

    #[test]
    fn p2tr_detection_byte_by_byte() {
        // OP_PUSHNUM_1 OP_PUSHBYTES_32 <32 bytes>
        let valid = [vec![0x51, 0x20], vec![0xaa; 32]].concat();
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 34);
        assert!(out.is_p2tr());
        assert_eq!(out.get_type(), OutputType::P2tr);

        // witness version 2 instead of version 1
        let out = script_output(with_byte_replaced(&valid, 0, 0x52));
        assert!(!out.is_p2tr());
        assert_eq!(out.get_type(), OutputType::Unknown);

        // OP_PUSHBYTES_33 instead of OP_PUSHBYTES_32
        let out = script_output(with_byte_replaced(&valid, 1, 0x21));
        assert_eq!(out.script_pubkey.len(), 34);
        assert!(!out.is_p2tr());

        // 33 bytes, one byte too short
        let out = script_output([vec![0x51, 0x20], vec![0xaa; 31]].concat());
        assert_eq!(out.script_pubkey.len(), 33);
        assert!(!out.is_p2tr());

        // 35 bytes, one byte too long
        let out = script_output([vec![0x51, 0x20], vec![0xaa; 33]].concat());
        assert_eq!(out.script_pubkey.len(), 35);
        assert!(!out.is_p2tr());
    }

    #[test]
    fn p2a_detection_byte_by_byte() {
        // OP_PUSHNUM_1 OP_PUSHBYTES_2 4e73
        let valid = vec![0x51, 0x02, 0x4e, 0x73];
        let out = script_output(valid.clone());
        assert!(out.is_p2a());
        assert_eq!(out.get_type(), OutputType::P2a);

        // each of the four bytes is checked
        for (index, byte) in [(0usize, 0x52u8), (1, 0x03), (2, 0x4f), (3, 0x74)].iter() {
            let out = script_output(with_byte_replaced(&valid, *index, *byte));
            assert!(!out.is_p2a(), "byte {} should be checked", index);
        }

        // one byte too long, even though it starts with the P2A script
        let out = script_output(vec![0x51, 0x02, 0x4e, 0x73, 0x00]);
        assert!(!out.is_p2a());

        // one byte too short
        let out = script_output(vec![0x51, 0x02, 0x4e]);
        assert!(!out.is_p2a());
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

    #[test]
    fn witness_commitment_detection_byte_by_byte() {
        // OP_RETURN OP_PUSHBYTES_36 aa21a9ed <32 byte commitment>
        let header = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        let valid = [header.clone(), vec![0x11; 32]].concat();
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 38);
        assert!(out.is_witness_commitment());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::WitnessCommitment)
        );

        // longer witness commitments are allowed
        let out = script_output([header.clone(), vec![0x11; 40]].concat());
        assert!(out.is_witness_commitment());

        // 37 bytes is one byte too short
        let out = script_output([header.clone(), vec![0x11; 31]].concat());
        assert_eq!(out.script_pubkey.len(), 37);
        assert!(!out.is_witness_commitment());

        // each of the six header bytes is checked
        for (index, byte) in header.iter().enumerate() {
            let out = script_output(with_byte_replaced(&valid, index, byte.wrapping_add(1)));
            assert!(
                !out.is_witness_commitment(),
                "byte {} should be checked",
                index
            );
        }
    }

    #[test]
    fn opreturn_omni_detection_byte_by_byte() {
        // OP_RETURN OP_PUSHBYTES_5 'omni' <1 byte>
        let valid = vec![0x6a, 0x05, b'o', b'm', b'n', b'i', 0x00];
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 7);
        assert!(out.is_opreturn_omni());
        assert_eq!(out.get_type(), OutputType::OpReturn(OpReturnFlavor::Omni));

        // seven bytes is the shortest Omni OP_RETURN, six bytes aren't enough
        let out = script_output(vec![0x6a, 0x04, b'o', b'm', b'n', b'i']);
        assert_eq!(out.script_pubkey.len(), 6);
        assert!(!out.is_opreturn_omni());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::Unspecified)
        );

        // the OP_RETURN and each of the four 'omni' bytes are checked
        for index in [0usize, 2, 3, 4, 5].iter() {
            let out = script_output(with_byte_replaced(&valid, *index, b'x'));
            assert!(!out.is_opreturn_omni(), "byte {} should be checked", index);
        }

        // the data push length in byte 1 isn't checked, as it differs between
        // Omni OP_RETURNs
        let out = script_output(with_byte_replaced(&valid, 1, 0x14));
        assert!(out.is_opreturn_omni());
    }

    #[test]
    fn opreturn_stacks_blockcommit_detection_byte_by_byte() {
        // OP_RETURN OP_PUSHDATA1 80 'X2[' <77 bytes>
        let header = vec![0x6a, 0x4c, 0x50, b'X', b'2', b'['];
        let valid = [header.clone(), vec![0x11; 77]].concat();
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 83);
        assert!(out.is_opreturn_stacks_blockcommit());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::StacksBlockCommit)
        );

        // each of the six header bytes is checked
        for (index, byte) in header.iter().enumerate() {
            let out = script_output(with_byte_replaced(&valid, index, byte.wrapping_add(1)));
            assert!(
                !out.is_opreturn_stacks_blockcommit(),
                "byte {} should be checked",
                index
            );
        }

        // 82 bytes is one byte too short
        let out = script_output([header.clone(), vec![0x11; 76]].concat());
        assert_eq!(out.script_pubkey.len(), 82);
        assert!(!out.is_opreturn_stacks_blockcommit());

        // 84 bytes is one byte too long
        let out = script_output([header.clone(), vec![0x11; 78]].concat());
        assert_eq!(out.script_pubkey.len(), 84);
        assert!(!out.is_opreturn_stacks_blockcommit());
    }

    /// Builds an 80 byte BIP-47 payment code payload:
    /// <version> <features> <sign> <32 byte x value> <32 byte chain code> <13 zero bytes>
    fn bip47_payload(version: u8, sign: u8) -> Vec<u8> {
        let payload = [
            vec![version, 0x00, sign],
            vec![0x11; 32],
            vec![0x22; 32],
            vec![0x00; 13],
        ]
        .concat();
        assert_eq!(payload.len(), 80);
        payload
    }

    /// Wraps a BIP-47 payload in an OP_RETURN OP_PUSHDATA1 80 <payload> script.
    fn bip47_output(payload: &[u8]) -> TxOut {
        script_output([&[0x6a, 0x4c, 0x50], payload].concat())
    }

    #[test]
    fn opreturn_bip47_payment_code_detection_byte_by_byte() {
        // both payment code versions and both public key signs are detected
        for version in [0x01u8, 0x02].iter() {
            for sign in [0x02u8, 0x03].iter() {
                let out = bip47_output(&bip47_payload(*version, *sign));
                assert_eq!(out.script_pubkey.len(), 83);
                assert!(
                    out.is_opreturn_bip47_payment_code(),
                    "version {} with sign {} should be a payment code",
                    version,
                    sign
                );
                assert_eq!(
                    out.get_type(),
                    OutputType::OpReturn(OpReturnFlavor::Bip47PaymentCode)
                );
            }
        }

        // only version 0x01 and 0x02 are payment codes
        for version in [0x00u8, 0x03, 0xff].iter() {
            let out = bip47_output(&bip47_payload(*version, 0x02));
            assert!(
                !out.is_opreturn_bip47_payment_code(),
                "version {} shouldn't be a payment code",
                version
            );
        }

        // only sign 0x02 and 0x03 are valid
        for sign in [0x00u8, 0x01, 0x04].iter() {
            let out = bip47_output(&bip47_payload(0x01, *sign));
            assert!(
                !out.is_opreturn_bip47_payment_code(),
                "sign {} shouldn't be a payment code",
                sign
            );
        }

        // the x value must not be all zeros
        let mut payload = bip47_payload(0x01, 0x02);
        payload[3..35].fill(0x00);
        assert!(!bip47_output(&payload).is_opreturn_bip47_payment_code());

        // the chain code must not be all zeros
        let mut payload = bip47_payload(0x01, 0x02);
        payload[35..67].fill(0x00);
        assert!(!bip47_output(&payload).is_opreturn_bip47_payment_code());

        // the reserved bytes must all be zero
        let payload = bip47_payload(0x01, 0x02);
        for index in 67..80 {
            let modified = with_byte_replaced(&payload, index, 0x01);
            assert!(
                !bip47_output(&modified).is_opreturn_bip47_payment_code(),
                "reserved byte {} should be zero",
                index
            );
        }

        // the three script header bytes are checked. The replacements keep the
        // script at 83 bytes.
        let payload = bip47_payload(0x01, 0x02);
        let valid = [&[0x6a, 0x4c, 0x50], &payload[..]].concat();
        for (index, byte) in [(0usize, 0x6bu8), (1, 0x4b), (2, 0x4f)].iter() {
            let out = script_output(with_byte_replaced(&valid, *index, *byte));
            assert_eq!(out.script_pubkey.len(), 83);
            assert!(
                !out.is_opreturn_bip47_payment_code(),
                "byte {} should be checked",
                index
            );
        }

        // 82 bytes is one byte too short
        let out = script_output([&[0x6a, 0x4c, 0x4f], &payload[..79]].concat());
        assert_eq!(out.script_pubkey.len(), 82);
        assert!(!out.is_opreturn_bip47_payment_code());

        // 84 bytes is one byte too long
        let out = script_output([&[0x6a, 0x4c, 0x51][..], &payload[..], &[0x00]].concat());
        assert_eq!(out.script_pubkey.len(), 84);
        assert!(!out.is_opreturn_bip47_payment_code());
    }

    #[test]
    fn opreturn_rsk_block_detection_byte_by_byte() {
        // OP_RETURN OP_PUSHBYTES_41 'RSKBLOCK:' <32 bytes>
        let header = [vec![0x6a, 0x29], b"RSKBLOCK:".to_vec()].concat();
        let valid = [header.clone(), vec![0x11; 32]].concat();
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 43);
        assert!(out.is_opreturn_rsk_block());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::RSKBlock)
        );

        // each of the header bytes is checked
        for (index, byte) in header.iter().enumerate() {
            let out = script_output(with_byte_replaced(&valid, index, byte.wrapping_add(1)));
            assert!(
                !out.is_opreturn_rsk_block(),
                "byte {} should be checked",
                index
            );
        }

        // 42 bytes is one byte too short
        let out = script_output([header.clone(), vec![0x11; 31]].concat());
        assert_eq!(out.script_pubkey.len(), 42);
        assert!(!out.is_opreturn_rsk_block());

        // 44 bytes is one byte too long for this form
        let out = script_output([header.clone(), vec![0x11; 33]].concat());
        assert_eq!(out.script_pubkey.len(), 44);
        assert!(!out.is_opreturn_rsk_block());

        // F2Pool pushes the same data with an OP_PUSHDATA1 instead:
        // OP_RETURN OP_PUSHDATA1 41 'RSKBLOCK:' <32 bytes>
        let header = [vec![0x6a, 0x4c, 0x29], b"RSKBLOCK:".to_vec()].concat();
        let valid = [header.clone(), vec![0x11; 32]].concat();
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 44);
        assert!(out.is_opreturn_rsk_block());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::RSKBlock)
        );

        // each of the header bytes is checked
        for (index, byte) in header.iter().enumerate() {
            let out = script_output(with_byte_replaced(&valid, index, byte.wrapping_add(1)));
            assert!(
                !out.is_opreturn_rsk_block(),
                "byte {} should be checked",
                index
            );
        }

        // 43 bytes is one byte too short for the OP_PUSHDATA1 form
        let out = script_output([header.clone(), vec![0x11; 31]].concat());
        assert_eq!(out.script_pubkey.len(), 43);
        assert!(!out.is_opreturn_rsk_block());

        // 45 bytes is one byte too long
        let out = script_output([header.clone(), vec![0x11; 33]].concat());
        assert_eq!(out.script_pubkey.len(), 45);
        assert!(!out.is_opreturn_rsk_block());
    }

    #[test]
    fn opreturn_coredao_detection_byte_by_byte() {
        // OP_RETURN OP_PUSHBYTES_45 'CORE' <version 0x01> <40 bytes>
        let header = [vec![0x6a, 0x2d], b"CORE".to_vec(), vec![0x01]].concat();
        let valid = [header.clone(), vec![0x11; 40]].concat();
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 47);
        assert!(out.is_opreturn_coredao());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::CoreDao)
        );

        // each of the header bytes is checked, including the version byte
        for (index, byte) in header.iter().enumerate() {
            let out = script_output(with_byte_replaced(&valid, index, byte.wrapping_add(1)));
            assert!(
                !out.is_opreturn_coredao(),
                "byte {} should be checked",
                index
            );
        }

        // only version 0x01 is known
        let out = script_output(with_byte_replaced(&valid, 6, 0x02));
        assert!(!out.is_opreturn_coredao());

        // 46 bytes is one byte too short
        let out = script_output([header.clone(), vec![0x11; 39]].concat());
        assert_eq!(out.script_pubkey.len(), 46);
        assert!(!out.is_opreturn_coredao());

        // 48 bytes is one byte too long
        let out = script_output([header.clone(), vec![0x11; 41]].concat());
        assert_eq!(out.script_pubkey.len(), 48);
        assert!(!out.is_opreturn_coredao());
    }

    #[test]
    fn opreturn_exsat_detection_byte_by_byte() {
        // OP_RETURN OP_PUSHBYTES_7 'EXSAT' <version 0x01> <1 byte>
        let header = [vec![0x6a, 0x07], b"EXSAT".to_vec(), vec![0x01]].concat();
        let valid = [header.clone(), vec![0x11; 1]].concat();
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 9);
        assert!(out.is_opreturn_exsat());
        assert_eq!(out.get_type(), OutputType::OpReturn(OpReturnFlavor::ExSat));

        // nine bytes is the shortest ExSat OP_RETURN, eight bytes aren't enough
        let out = script_output(header.clone());
        assert_eq!(out.script_pubkey.len(), 8);
        assert!(!out.is_opreturn_exsat());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::Unspecified)
        );

        // the OP_RETURN, the five 'EXSAT' bytes and the version are checked
        for index in [0usize, 2, 3, 4, 5, 6, 7].iter() {
            let byte = valid[*index].wrapping_add(1);
            let out = script_output(with_byte_replaced(&valid, *index, byte));
            assert!(!out.is_opreturn_exsat(), "byte {} should be checked", index);
        }

        // the data push length in byte 1 isn't checked, as it differs between pools
        let out = script_output(with_byte_replaced(&valid, 1, 0x12));
        assert!(out.is_opreturn_exsat());

        // longer ExSat OP_RETURNs are detected too
        let out = script_output([header.clone(), vec![0x11; 10]].concat());
        assert!(out.is_opreturn_exsat());
    }

    #[test]
    fn opreturn_hathor_detection_byte_by_byte() {
        // OP_RETURN OP_PUSHBYTES_36 'Hath' <32 byte aux_block_hash>
        let header = [vec![0x6a, 0x24], b"Hath".to_vec()].concat();
        let valid = [header.clone(), vec![0x11; 32]].concat();
        let out = script_output(valid.clone());
        assert_eq!(out.script_pubkey.len(), 38);
        assert!(out.is_opreturn_hathor());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::HathorNetwork)
        );

        // each of the header bytes is checked
        for (index, byte) in header.iter().enumerate() {
            let out = script_output(with_byte_replaced(&valid, index, byte.wrapping_add(1)));
            assert!(
                !out.is_opreturn_hathor(),
                "byte {} should be checked",
                index
            );
        }

        // 37 bytes is one byte too short
        let out = script_output([header.clone(), vec![0x11; 31]].concat());
        assert_eq!(out.script_pubkey.len(), 37);
        assert!(!out.is_opreturn_hathor());

        // 39 bytes is one byte too long
        let out = script_output([header.clone(), vec![0x11; 33]].concat());
        assert_eq!(out.script_pubkey.len(), 39);
        assert!(!out.is_opreturn_hathor());
    }

    #[test]
    fn opreturn_runestone_detection() {
        // OP_RETURN OP_PUSHNUM_13 OP_PUSHBYTES_2 <2 bytes>
        let out = script_output(vec![0x6a, 0x5d, 0x02, 0xaa, 0xbb]);
        assert!(out.is_opreturn_runestone());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::Runestone)
        );

        // several data pushes are fine
        let out = script_output(vec![0x6a, 0x5d, 0x01, 0xaa, 0x03, 0x01, 0x02, 0x03]);
        assert!(out.is_opreturn_runestone());

        // an OP_RETURN OP_PUSHNUM_13 without any data push isn't a runestone
        let out = script_output(vec![0x6a, 0x5d]);
        assert_eq!(out.script_pubkey.len(), 2);
        assert!(!out.is_opreturn_runestone());
        assert_eq!(
            out.get_type(),
            OutputType::OpReturn(OpReturnFlavor::Unspecified)
        );

        // anything but a data push after the OP_PUSHNUM_13 isn't allowed
        let out = script_output(vec![0x6a, 0x5d, 0x51]);
        assert!(!out.is_opreturn_runestone());

        // a truncated data push can't be parsed
        let out = script_output(vec![0x6a, 0x5d, 0x4c]);
        assert!(!out.is_opreturn_runestone());

        // OP_PUSHNUM_12 instead of OP_PUSHNUM_13
        let out = script_output(vec![0x6a, 0x5c, 0x02, 0xaa, 0xbb]);
        assert!(!out.is_opreturn_runestone());

        // the script has to start with an OP_RETURN. Here it starts with an
        // OP_TOALTSTACK, while all following instructions are data pushes.
        let out = script_output(vec![0x6b, 0x5d, 0x02, 0xaa, 0xbb]);
        assert!(!out.is_opreturn_runestone());

        // a P2WPKH script isn't a runestone either
        let out = script_output([vec![0x00, 0x14], vec![0xab; 20]].concat());
        assert!(!out.is_opreturn_runestone());
    }

    /// A script that is not an OP_RETURN must never be reported as an OP_RETURN
    /// with a given data length, even when its total length happens to match.
    /// A 22 byte P2WPKH script (OP_0 OP_PUSHBYTES_20 <20 bytes>) is such a
    /// case, as 22 - 2 == 20.
    #[test]
    fn is_opreturn_with_len_rejects_non_opreturn() {
        let p2wpkh = output_with_script(ScriptBuf::from_bytes(
            [vec![0x00, 0x14], vec![0xab; 20]].concat(),
        ));
        assert_eq!(p2wpkh.script_pubkey.len(), 22);
        assert!(!p2wpkh.script_pubkey.is_op_return());
        assert!(!p2wpkh.is_opreturn_with_len(20));
    }

    #[test]
    fn is_opreturn_with_len_matches_pushed_data_length() {
        // OP_RETURN OP_PUSHBYTES_20 <20 bytes>
        let twenty = opreturn_output(&[0xab; 20]);
        assert_eq!(twenty.script_pubkey.len(), 22);
        assert!(twenty.is_opreturn_with_len(20));
        assert!(!twenty.is_opreturn_with_len(1));
        assert!(!twenty.is_opreturn_with_len(80));

        // OP_RETURN OP_PUSHDATA1 0x50 <80 bytes>
        let eighty = opreturn_output(&[0xab; 80]);
        assert_eq!(eighty.script_pubkey.len(), 83);
        assert_eq!(eighty.script_pubkey.as_bytes()[1], 0x4c);
        assert!(eighty.is_opreturn_with_len(80));
        assert!(!eighty.is_opreturn_with_len(20));
    }

    #[test]
    fn is_opreturn_with_len_boundaries() {
        // A bare OP_RETURN is shorter than the two byte minimum. It doesn't
        // have a data push at all, not even an empty one.
        let bare = script_output(vec![0x6a]);
        for data_length in 0..3 {
            assert!(
                !bare.is_opreturn_with_len(data_length),
                "a bare OP_RETURN doesn't push {} bytes",
                data_length
            );
        }

        // OP_RETURN OP_0 is the shortest OP_RETURN with a data push. It pushes
        // zero bytes.
        let empty_push = script_output(vec![0x6a, 0x00]);
        assert_eq!(empty_push.script_pubkey.len(), 2);
        assert!(empty_push.is_opreturn_with_len(0));
        assert!(!empty_push.is_opreturn_with_len(1));

        // OP_RETURN OP_PUSHBYTES_1 <1 byte>
        let one = script_output(vec![0x6a, 0x01, 0xaa]);
        assert!(one.is_opreturn_with_len(1));
        assert!(!one.is_opreturn_with_len(0));
        assert!(!one.is_opreturn_with_len(2));

        // OP_RETURN OP_PUSHBYTES_74 <74 bytes>, 76 bytes in total
        let seventy_four = script_output([vec![0x6a, 0x4a], vec![0xaa; 74]].concat());
        assert_eq!(seventy_four.script_pubkey.len(), 76);
        assert!(seventy_four.is_opreturn_with_len(74));
        assert!(!seventy_four.is_opreturn_with_len(73));
        assert!(!seventy_four.is_opreturn_with_len(75));

        // The longest OP_PUSHBYTES form:
        // OP_RETURN OP_PUSHBYTES_75 <75 bytes>, 77 bytes in total
        let seventy_five = script_output([vec![0x6a, 0x4b], vec![0xaa; 75]].concat());
        assert_eq!(seventy_five.script_pubkey.len(), 77);
        assert!(seventy_five.is_opreturn_with_len(75));
        assert!(!seventy_five.is_opreturn_with_len(74));
        assert!(!seventy_five.is_opreturn_with_len(76));

        // The shortest OP_PUSHDATA1 form, which needs one byte more for the
        // data length: OP_RETURN OP_PUSHDATA1 76 <76 bytes>, 79 bytes in total
        let seventy_six = script_output([vec![0x6a, 0x4c, 0x4c], vec![0xaa; 76]].concat());
        assert_eq!(seventy_six.script_pubkey.len(), 79);
        assert!(seventy_six.is_opreturn_with_len(76));
        assert!(!seventy_six.is_opreturn_with_len(75));
        assert!(!seventy_six.is_opreturn_with_len(77));

        // The longest standard OP_RETURN:
        // OP_RETURN OP_PUSHDATA1 80 <80 bytes>, 83 bytes in total
        let eighty = script_output([vec![0x6a, 0x4c, 0x50], vec![0xaa; 80]].concat());
        assert_eq!(eighty.script_pubkey.len(), 83);
        assert!(eighty.is_opreturn_with_len(80));
        assert!(!eighty.is_opreturn_with_len(79));
        assert!(!eighty.is_opreturn_with_len(81));

        // One byte longer than the maximum length: no data length matches.
        let eighty_one = script_output([vec![0x6a, 0x4c, 0x51], vec![0xaa; 81]].concat());
        assert_eq!(eighty_one.script_pubkey.len(), 84);
        for data_length in 0..=84 {
            assert!(
                !eighty_one.is_opreturn_with_len(data_length),
                "an 84 byte script doesn't push {} bytes",
                data_length
            );
        }
    }

    #[test]
    fn opreturn_flavor_display() {
        let testcases: Vec<(OpReturnFlavor, &str)> = vec![
            (OpReturnFlavor::Unspecified, "OP_RETURN"),
            (OpReturnFlavor::WitnessCommitment, "Witness Commitment"),
            (OpReturnFlavor::Omni, "OP_RETURN (OmniLayer)"),
            (
                OpReturnFlavor::StacksBlockCommit,
                "OP_RETURN (Stacks v2 blockcommit)",
            ),
            (OpReturnFlavor::Len1Byte, "OP_RETURN (1 byte)"),
            (OpReturnFlavor::Len20Byte, "OP_RETURN (20 byte)"),
            (OpReturnFlavor::Len80Byte, "OP_RETURN (80 byte)"),
            (
                OpReturnFlavor::Bip47PaymentCode,
                "OP_RETURN (BIP 47 Payment Code)",
            ),
            (
                OpReturnFlavor::RSKBlock,
                "OP_RETURN (Rootstock merge mining info)",
            ),
            (
                OpReturnFlavor::CoreDao,
                "OP_RETURN (CoreDao delegation info)",
            ),
            (OpReturnFlavor::ExSat, "OP_RETURN (ExSat info)"),
            (
                OpReturnFlavor::HathorNetwork,
                "OP_RETURN (HathorNetwork aux_block_hash)",
            ),
            (OpReturnFlavor::Runestone, "OP_RETURN (Runestone)"),
        ];
        for (flavor, expected) in testcases.iter() {
            assert_eq!(&flavor.to_string(), expected);
        }
    }

    #[test]
    fn output_type_display() {
        let testcases: Vec<(OutputType, &str)> = vec![
            (OutputType::P2pk, "P2PK"),
            (OutputType::P2pkh, "P2PKH"),
            (OutputType::P2wpkhV0, "P2WPKH v0"),
            (OutputType::P2ms, "P2MS"),
            (OutputType::P2sh, "P2SH"),
            (OutputType::P2wshV0, "P2WSH v0"),
            (
                OutputType::OpReturn(OpReturnFlavor::Len1Byte),
                "OP_RETURN (1 byte)",
            ),
            (OutputType::P2tr, "P2TR"),
            (OutputType::P2a, "P2A"),
            (OutputType::Unknown, "UNKNOWN"),
        ];
        for (out_type, expected) in testcases.iter() {
            assert_eq!(&out_type.to_string(), expected);
        }
    }

    #[test]
    fn output_error_display() {
        let error = OutputError::PubkeyInfo(script::Error::EarlyEndOfScript);
        assert_eq!(
            error.to_string(),
            "Could not extract pubkey infos from output: unexpected end of script"
        );
    }

    #[test]
    fn output_error_source() {
        let error = OutputError::PubkeyInfo(script::Error::EarlyEndOfScript);
        let source =
            std::error::Error::source(&error).expect("the script error should be the source");
        assert_eq!(
            source.to_string(),
            script::Error::EarlyEndOfScript.to_string()
        );
    }

    #[test]
    fn output_type_detection_opreturn_data_lengths() {
        // OP_RETURN OP_PUSHBYTES_1 0x00 pushes one byte of data
        let one_byte = opreturn_output(&[0x00]);
        assert_eq!(
            one_byte.get_type(),
            OutputType::OpReturn(OpReturnFlavor::Len1Byte)
        );

        // A bare OP_RETURN pushes no data at all
        let bare = output_with_script(ScriptBuf::from_bytes(vec![0x6a]));
        assert_eq!(
            bare.get_type(),
            OutputType::OpReturn(OpReturnFlavor::Unspecified)
        );

        // OP_RETURN OP_0 doesn't push any bytes either
        let op_return_op_0 = output_with_script(
            script::Builder::new()
                .push_opcode(opcodes::OP_RETURN)
                .push_opcode(opcodes::OP_PUSHBYTES_0)
                .into_script(),
        );
        assert_eq!(op_return_op_0.script_pubkey.len(), 2);
        assert_eq!(
            op_return_op_0.get_type(),
            OutputType::OpReturn(OpReturnFlavor::Unspecified)
        );
    }
}
