//! Information about Bitcoin transaction outputs.

use std::{error, fmt};

use bitcoin::{blockdata::opcodes::all as opcodes, script, Amount, TxOut};

use crate::script::{Multisig, PubKeyInfo};

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
}

impl OutputInfo {
    pub fn new(output: &TxOut) -> Result<OutputInfo, OutputError> {
        Ok(OutputInfo {
            out_type: output.get_type(),
            value: Amount::from_sat(output.value.to_sat()),
            pubkey_stats: PubKeyInfo::from_output(output)?,
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
        // Check the length and structure
        if script_pubkey_bytes.len() != 83
            && script_pubkey_bytes[0] != 0x6A
            && script_pubkey_bytes[1] != 0x4C
            && script_pubkey_bytes[2] != 0x50
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
        script_pubkey_bytes[0] == 0x6A
            // script_pubkey_bytes[1] is the length, but this might be different for each pool
            && script_pubkey_bytes[2] == b'E'
            && script_pubkey_bytes[3] == b'X'
            && script_pubkey_bytes[4] == b'S'
            && script_pubkey_bytes[5] == b'A'
            && script_pubkey_bytes[6] == b'T'
            && script_pubkey_bytes[7] == 0x01 // version
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

pub trait OutputSigops {
    fn sigops(&self) -> usize;
}

impl OutputSigops for TxOut {
    fn sigops(&self) -> usize {
        const SIGOPS_SCALE_FACTOR: usize = 4;

        // in P2TR scripts, no sigops are counted
        if self.is_p2tr() {
            return 0;
        }

        // for example, for P2MS script_pubkeys (OP_CHECKMUTLISIG)
        SIGOPS_SCALE_FACTOR * self.script_pubkey.count_sigops_legacy()
    }
}

#[cfg(test)]
mod tests {
    use super::{OpReturnFlavor, OutputType, OutputTypeDetection};
    use bitcoin::Transaction;

    #[test]
    fn output_type_detection_p2ms() {
        // mainnet ac1d9ed701af32ea52fabd0834acfb1ba4e3584cf0553551f1b61b3d7fb05ee7
        let raw_tx = hex::decode("0100000001ffc0d6d6b592cd2b4160300a278ea5e250b5055b5536dcfb2da5dcc46022765a00000000694630430220575ddd235a989befbf98f43b008666e56af07be89e47e09d18690c75846fb587021f00830605aa09febc51132001e0dbcad860e54d4657b55aaf961b527a935b8a01210281feb90c058c3436f8bc361930ae99fcfb530a699cdad141d7244bfcad521a1fffffffff03204e0000000000002551210281feb90c058c3436f8bc361930ae99fcfb530a699cdad141d7244bfcad521a1f51ae204e0000000000001976a914a988f8039a203cf86136e0d32b9d77eafa5a6bef88ac46f4d501000000001976a914161d7a3d0ee15c793ab300433192f949d8f3566588ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        let out0 = &tx.output[0];
        assert!(out0.is_p2ms());
        assert_eq!(out0.get_type(), OutputType::P2ms);
    }

    #[test]
    fn output_type_detection_p2ms2() {
        // mainnet d5a02fd4d7e3cf5ca02d2a4c02c8124ba00907eb85801dddfe984428714e3946
        let raw_tx = hex::decode("010000000150db0324e3733b7d4915a42acf51d4cd95629fb5a659da68d01292e3152abf7d010000006b4830450221008c24014a99a87736aa47a773d738cbbcd60dadfbb2aa294d4f00cda1e4dae66f022076fa9be5d50eecd2e8e1dbe364b158f2d5df049cbcd8cc759970dd23fab41423012102dc6546ba58b9bc26365357a428516d48c9bbc230dd6fc72912654aaad460ef19ffffffff02781e00000000000069512102d7f69a1fc373a72468ae84634d9949fdeab4d1c903c6f23a3465f79c889342a421028836687b0c942c94801ce11b2601cbb1e900e6544ef28369e69977195794d47b2102dc6546ba58b9bc26365357a428516d48c9bbc230dd6fc72912654aaad460ef1953ae3c660d00000000001976a914e4e9d188d9806fef75904225f370009aa4103a9d88ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        let out0 = &tx.output[0];
        assert!(out0.is_p2ms());
        assert_eq!(out0.get_type(), OutputType::P2ms);
    }

    #[test]
    fn output_type_detection_p2tr() {
        // signet 9f3d438ab92e86bd86c64749416df8d3a48bcef97b7c32ccefc2ec4f02caac74
        let raw_tx = hex::decode("020000000001029dac93ef467e6035bf641f4076b2a8ac6a4368e93d6c7dc8dcfb38b9bed7da840100000000feffffffbe415b1058e5294f30ccc12332d00636aa8874448141a0446737a1ffc7e6f5060100000000feffffff0410270000000000002251207a61c588fd357d8ed58f624fa7f97a651d1ac00b53b055e9b852507dd319a3d41027000000000000225120acd385f4c428f2ce97644de474a579a77435f40b6161d1c1875f48f2626fccde1e0e1e00000000001600147f611a8cfa64617c05c1b44341b4e469631371c3102700000000000022512070271d98a521d0e4102ebdbc40f3e553666fb5b85c8c3d2709138568c6c90b230247304402202945170a29517bf8773f6a741e587d87b3f4ec6e7348fae8443d45bc5a30f82402200207fcdb3369e55060725bdc2343236271e2dddb62a3077577a85e6f79d22404012103f682085f03c8a27288258933370b4cef8badb4c8a0e8bbfa31d78a450dffd543024730440220711d103aaed2122a8ddef8fd5523ccc7e3748382804dddccdf46e4755c2d1e9f022060e0564f3bf307d5c2128a4bcfd521c33a2bf1c3590cfc0d4fa7c8e02af26ab4012103f682085f03c8a27288258933370b4cef8badb4c8a0e8bbfa31d78a450dffd54300000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
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
        // mainnet 2a352a3473385dc9f7b79967aba7aeaafa5f7994d5031ac5b43d168b7566c092
        // coinbase of 00000000000000000009a77c962fabb1b12c54dc1e978080df0155381f97fb5f (674485)
        let raw_tx = hex::decode("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5403b54a0a41d8134fa906ec3741d8134fa83cdae32f3154486173682ffabe6d6d022644aec8e65c41869919439905bd5a6546045825016e8ab843121b089ee79f8000000000000000bf00d52a508f000000000000ffffffff02114cf82c000000001976a9142220867b1e79c403fafe339a809a65ed01cb697988ac0000000000000000266a24aa21a9ed0a8154218fc45bc35f274fafd2490849f8b88f75b3cd63b95096b2a861018f300120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        let out1 = &tx.output[1];
        assert!(out1.is_witness_commitment());
        assert_eq!(
            out1.get_type(),
            OutputType::OpReturn(OpReturnFlavor::WitnessCommitment)
        );
    }

    #[test]
    fn output_type_detection_opreturn_omni() {
        // mainnet 60d37517d7f6140a560c1aa3961f8c00ac663c73620825e889fb9e19b62d3ad7
        let raw_tx = hex::decode("0100000001305fe5e034c625b571638cbce7837970ca1e84830e794c77de6582ea419bcfb5000000006a47304402206d3f22eff2a26e7f6e2c6e1ccfafa0ae174b5c265353b19d8ee3510316de40ed02201a49d55eaad2f78e7a0358e6ec0f9230ace39451c883845ad107af8822e1ccef0121030651e1d15ae9a284ffd712885529d3344db3700be756e6c22c56a6c1b57d359dffffffff03f64e0600000000001976a914b64513c1f1b889a556463243cca9c26ee626b9a088ac22020000000000001976a914c958135faa72449c106564acba252cfbc3a35ca688ac0000000000000000166a146f6d6e69000000000000001f000002115728ef0000000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        let out2 = &tx.output[2];
        assert!(out2.is_opreturn_omni());
        assert_eq!(out2.get_type(), OutputType::OpReturn(OpReturnFlavor::Omni));
    }

    #[test]
    fn output_type_detection_opreturn_stacks_blockcommmit() {
        // mainnet 04496abaffb19abf1390b8fc94a8e487eba640c8adc385cfc951637b963fc86a
        let raw_tx = hex::decode("01000000018d9da5a2bc0789aa38bd9e2c1248a5ddaea8f00e097748ca80695f6333adcc04030000006a47304402200704d5f943227080b0c1b8668a37d819804a5c99a0bdda593b3dc167c32a39d402207d2bbd4384e369d671f0c46a54fc4fbfeb14724ab99ea695d1184d4f1074ad18012103fb3bc5bae4c088ca38a8c68bfe741f3b1cb62a067b69917908089a2082af31aefdffffff040000000000000000536a4c5058325b1352fba61836c82246b240fb64043b3e705f8975aa2062d886e247aaeee76ad26f14f91d22c38c8c2fd41ff85e4b22b0cf97b412c53f9aa0182bd6deb51c9567000a3596004b000a2f80012b03989f0400000000001976a914000000000000000000000000000000000000000088ac989f0400000000001976a914000000000000000000000000000000000000000088ac1132920b000000001976a9142c16c83270b688fa3ac46dc69cc01f6321bce41088ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        let out2 = &tx.output[0];
        assert!(out2.is_opreturn_stacks_blockcommit());
        assert_eq!(
            out2.get_type(),
            OutputType::OpReturn(OpReturnFlavor::StacksBlockCommit)
        );
    }

    #[test]
    fn output_type_detection_p2a() {
        // mainnet 4752bdfc1041b46fb49cb551d35d06233bcb71ee3b6e7df9cb765db881f8104f
        let rawtx = hex::decode("020000000001016352fb25843f7e3e20ac70119a9e46447d24257e0a250215402da5449764610f0100000000fdffffff02d0070000000000000451024e73581b00000000000022512044b35747ac9a995294839fdbefa823ae2d0cfbed950b72755499d9039ae739b501400cb9cb49f7790080d9601d1c24bebfd0668ef170145888f303f487ab5a9c4acdb511274f7b305faef35718af80c108df5ac51538f71f450ecda63c8fa952365200000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let out0 = &tx.output[0];
        let out1 = &tx.output[1];
        assert!(out0.is_p2a());
        assert!(out1.is_p2tr());
        assert_eq!(out0.get_type(), OutputType::P2a);
        assert_eq!(out1.get_type(), OutputType::P2tr);
    }

    #[test]
    fn output_type_detection_bip47_payment_code() {
        let testcases = vec![
            // output, raw tx hex
            // ---
            // mainnet aa7bb5c839e6d513fdde4ef994995363f98a6d6cbe795663f432a39a38d71025 with BIP47
            // output in output 0
            (0, "02000000000101cdd51d9048b22420cd2af3538aa7ea71951b81b4dee3894cc20f5c13fe463f783500000000fdffffff040000000000000000536a4c50010003a4b1880f11b6de85617c0aa9a21a3073dbe5a2fa277aa8f626ba9cb95b3c9c025e36a6ec791cedb876a079a264a40fa42531aa60825ca1d243998f54dd8977450000000000000000000000000022020000000000001976a914f522819122c73c04068577724e2ee7d05a0965d888ac983a00000000000016001437808929e894e2c691bd705f802c203716ea11fc9bdb00000000000016001427f5f2387d9efc49fade31556e81c30f8fa666730247304402206661b9bba8f4bf116f9a53c36de4b4ba35501f0d46a1c36a76c0e792b1c422ef02206dc75e32ec9a47068a749d0e1fee455ee483568a78387b86c8b179d293230f90012103c6c004d651ae8428b33a7ba4222bc92e4a7631f5791cb286e49fb38e89a3e662806b0b00"),
            // testnet cccd8cdb344df8e93e6e6c783688605c500e81f4cd130427c6f9f042446176af with BIP47
            // output in output 0
            // from https://medium.com/@ottosch/how-bip47-works-ee641cc14bf3
            (0, "02000000000101ba7f679c0adb514945c9a4a00f73ecbb73f2e6116208e4ae314b9910c9f221020000000000ffffffff040000000000000000536a4c50010002b13b2911719409d704ecc69f74fa315a6cb20fdd6ee39bc9874667703d67b164927b0e88f89f3f8b963549eab2533b5d7ed481a3bea7e953b546b4e91b6f50d80000000000000000000000000022020000000000001976a914e335b83658f7565d19405117cbd2f85a743653ba88ac983a000000000000160014b1c8c8ba853483ac9faaa9445e5d2b64f6e4e5fed291200000000000160014b9623df59eda43987c3102cf8fc3935c0c651b2e0247304402201de79d8959e8d0420b9ca54932497aad6d068c0d7222c0a7ac5badab335169ff02206f67d38356d7238eb0a5a53cfe57bf7c0553a6bbe270199b969eba008fa1a35f01210281ae97b31eccbbfd83b3cbef1c0c6dc82cd13f34668fae266cf9dc87352144ef00000000"),
            // testnet 0e2e4695a3c49272ef631426a9fd2dae6ec3a469e3a39a3db51aa476cd09de2e with BIP47
            // output in output 0
            // from https://medium.com/@ottosch/how-bip47-works-ee641cc14bf3
            (0, "01000000000101a390284b399704a12c1d5c9b43181f0b984f2c17f619522675de80962546e5af0000000000ffffffff030000000000000000536a4c500100036c11d62dc5d47a03edf9027dc045406f81da1bf89e701c3ac691468ecb154661d7e65b9aa400701c44f396b627e8592bbb081764d92df98ebce9a8a3b9360dfc0000000000000000000000000022020000000000001976a9143431c401040f906b9eaea2d0fe2511688b4033c988ac1c470000000000001600147701a0aa820832428ef0133c7ba1b44b627ecd0f0247304402202ebad56e95f7dfa91c68c0e7a7e4e70e4b0eff674e903f1909ae3b03649ca25602206b6b31a17a231e90a035e10127e4cde84a36270d1e5e21ef11140078f65fac91012102a7a6edc3de4e35ab54f98b69bedace05cc649e0dc51c7dfdeabe0db42be32d7c00000000"),
            // signet ee001f84787f48a53dc460d1aeba78da663e10b9aeee152270ff93404918b229 with BIP47
            // output in output 0
            (0, "020000000001012364df1e5c5b2a357e63183f7985bfd14e0be165c76bfb34d9067c63e6bfd19be400000000fdffffff030000000000000000536a4c500100029a516f23dcc89a26430b72baac2e6b3abded6cdf98e1a6b377f519e77b9facf5c2affa8263329f80d922378fbf63a62cf07cda0b67942bd00db44823c91f72070000000000000000000000000056fa05000000000016001418387b71aa4c8d241f5ae8848e79299a40bb5e6922020000000000001976a91465724c591ae40f62c0815a51522d60d2e319b45f88ac0247304402202a10fff3b0fc8cf275f54bd4e71fdc1fad6580fc442842c3a6da81e63dcfe75102203b96541ceef9e33cc9c459f028446e36300a83f958598b750b64d608478dffe0012102010012e1eb74242bdd7c9c43be974cdd1d8e301f3cd52823d28f100bc53b40becaad0300"),
            // signet 1e40201df09c10cd42340756aebfe9e8614791ae144f4caf75f95ebd699f365a with BIP47
            // output in output 0
            (0, "02000000000101dca9b1082c0ebb7d3c56368c5edca4feb254c55bae4fca2bdf2a92f52a9ce5320200000000fdffffff030000000000000000536a4c50010002fc575207a99903a525022be54fb6c9872ab418ff766795a6437c80393a57861d078e55fe8dbc995d772703bbe6076143b05c5ee8e007e2bffedf87d618e3d76a0000000000000000000000000002e80500000000001600145f13323a3d6271d8ea28370cdeb2d3c07d172fdf22020000000000001976a9142cedadc4dc423f698cbdcac8ee9571b91c56f13f88ac0247304402201168bb51d7031ddeaf6fd95abe14b6641b2cdfcc38e3983ecc0ff19f249063d002200a2afd7afed9cae6888761808c1440370f48eaada67d008f1143e0dd96ec884f01210288263dfde13ab364938a44fa983c3f51f7c38cad01fdde7d0c94ade12deeb860caad0300"),
            // signet 4d8dc61d66203a8ed76a9b70e4198d6678abc2f9e63dfa828a7a1a35be618582 with BIP47
            // output in output 1
            (1, "02000000000101866718b8560b53bdb878865e6c8c5ca76415d00a0d00cd9cf4b7b7154a81fdd90100000000fdffffff032cf10500000000001600149e1c68bf6d006ac3ffa59cd75efab7888ee862390000000000000000536a4c50010002c1addde6d69e908195bc0e43c4fd16ba0f7c1e4181a03f7c04d5a21dd8c378af6c0c378f068498915452cf7005b0cd5f33f228971c345038271bf974cec731730000000000000000000000000022020000000000001976a91464fa781a0d4389518af519efe591dd8f1ca63e2488ac0247304402204458c82463809b368cf705f1ade063bd46174d2f679e2e9ebc4e54fe7f37e6ac02204c1c7f6e1b7541c8a6eb3954b4eca694a9a4fd8da9712c1348a34b951c9506e1012103ce30da189fed4a7885ec579feacc008a2df738d5592ecbd3ac840fd973675063caad0300"),
            // signet d9fd814a15b7b7f49ccd000d0ad01564a75c8c6c5e8678b8bd530b56b8186786 with BIP47
            // output in output 0
            (0, "020000000001018d456318a27c4b421fbbcc8f9714dec7f99c21fa19677c9e7478e01ee041f89a0200000000fdffffff030000000000000000536a4c5001000202d0f2d07130dace07e45b57e5f6fb6a5f1c86e5aa7d6dd4d8aa4f30337f1fe3827dc9098a6650fc8b8e81a48c4c9c5b04dca2f77e8a98241d319842ab2517f1000000000000000000000000003af405000000000016001431afd3b96454958646eaf28726ab8f9916267b4622020000000000001976a914d86b062ac7d8d682149d71ab884dae54b4b816f188ac0247304402200a7fa0ee9048147bcdf043e93c6913e7b3620edc4eaa570d7eaf764c98c775a502203664108b6f06b237fb41911390b94267f2177b90319c3ecafdf2fcb87d8833810121026d02c3435f4e13f348c8ca852995b756ee34539cdeb3da39c8d87ec163ef2bcccaad0300"),
            // signet 9af841e01ee078749e7c6719fa219cf9c7de14978fccbb1f424b7ca21863458d with BIP47
            // output in output 0
            (0, "0200000000010129b218494093ff702215eeaeb9103e66da78baaed160c43da5487f78841f00ee0100000000fdffffff030000000000000000536a4c50010002cdd82e5a14af597148a04cc15b0209c67b27ade0f763de4af9c8277a80725b6f22f46db3d2815e080fac413c758cd26ad54196e42744ebde36a159b0179c55b30000000000000000000000000022020000000000001976a914f85cc4a7022a3f2b91eccd5b426d68ba40be9b8988ac48f7050000000000160014043f2fd2079a9d7a2e0fec2e25a9667cd0f79c380247304402206fb17a155cfce2a1c0c55bdafdc7935f538bea5ff74cfacd4ee998dbb51ffae20220571dce283d7288fd759aed0bcd44aeeee897a588434c62f0952e0f18cf9c6a46012103c961e88949b6ed625a9bacdd104d190dd2b0fbcc94f97afdfe8ddfad25dca9c0caad0300"),
            // signet fb5b842cae4ceec77dd1a54d901a53c1d27d3ae9311112af3b6affba4634aabb with BIP47
            // output in output 1
            (1, "02000000000101828561be351a7a8a82fa3de6f9c2ab78668d19e4709b6ad78e3a20661dc68d4d0000000000fdffffff031eee05000000000016001444267dab545a75dfe6af8178e20b9cad6cd8e2ff0000000000000000536a4c500100020ddf6d3bb46d48e5211db2760ef7438dc419654dbe695d58c948b8b1f5ea7353cfdced7eab6f6a80fa14bc74d91e058b0c1d120a605c36ad5f3246ffa4d89b580000000000000000000000000022020000000000001976a914e705081188cdd43527fbea2150db9b0189970e0c88ac0247304402204261a04f3b8651612bb94cb204a5f90139f196a87aa166ebf92a26c75d3c18a402204422255c8222527ad445e2f063175dfc274b98b14a97b065b33e5c4cd6c74de9012103b1a3d3e1277b64dfe9e05f3a2421c1a53a3bd41aa2f8e69fd24985bf105a355ecaad0300"),
            // signet 32e59c2af5922adf2bca4fae5bc554b2fea4dc5e8c36563c7dbb0e2c08b1a9dc with BIP47
            // output in output 1
            (1, "02000000000101bbaa3446baff6a3baf121131e93a7dd2c1531a904da5d17dc7ee4cae2c845bfb0000000000fdffffff0322020000000000001976a914ffba4d90d0be82b01c490e08697b9ffc673310e388ac0000000000000000536a4c50010002d0e5ecefdcad186cee3d4bf2a5c68a0bd8cd463a4ee644e2f21023cdf0e4a68dd79604907773547b8e0f7acf57c55fdcf7da42b1ce3761ea333498a4904824a00000000000000000000000000010eb05000000000016001411732aa696294ca454a633e909d5544367a6f9250247304402202ae0ceb7a1f898e99bfb79c5d60143ea4505dae0bb225c0fdb3481189c0c4d050220521b0a2e98ad682d151155b16d7f97ba1458e72741359d61e093756c02d96bde012102f1f400b3976309cc5bf1c81b09fd8cb59e4c49d5118c2d8ad5e3036d25fe1314caad0300"),
            // mainnet 9414f1681fb1255bd168a806254321a837008dd4480c02226063183deb100204 with BIP47
            // output in output 1
            // from test vectors https://gist.github.com/SamouraiDev/6aad669604c5930864bd
            (1, "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000")
        ];
        for (i, (output_index, txhex)) in testcases.iter().enumerate() {
            println!("Testing case {}", i);
            let rawtx = hex::decode(txhex).unwrap();
            let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
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
        let testcases = vec![
            // rsk output, coredao output, exsat output, raw tx hex
            // ---
            // mainnet coinbase of block 890680 da7bc085ce387c50c8b280934a93d0b05ec987fa06345fa0a82c195f4c030916
            (5, 3, 4, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff580338970d1b4d696e656420627920416e74506f6f6c3937304d0043010b007fe4fabe6d6d0b528b660c38cd611ff89d34e03ae3d92d7f9ac6bec6599422e8fcb18978507f08000000000000000000936100aeb83100000000ffffffff06220200000000000017a91442402a28dd61f2718a4b27ae72a4791d5bbdade7874b31eb120000000017a9145249bdf2c131d43995cff42e8feee293f79297a8870000000000000000266a24aa21a9ed2b33a26f7157d656c9fd7aab093e4a63a3c463ecf9294156002e6a134ac22f7200000000000000002f6a2d434f52450142fdeae88682a965939fee9b7b2bd5b99694ff644e3ecda72cb7961caa4b541b1e322bcfe0b5a0300000000000000000146a12455853415401000d130f0e0e0b041f12001300000000000000002b6a2952534b424c4f434b3a359c5f6d8523559163efd9f7884d3ef37b5953b334cd79efab0af412007111430120000000000000000000000000000000000000000000000000000000000000000000000000"),
            // mainnet coinbase of block 890688 f5adbbcf21bb598e260e5ea9ce40eba0c39747fe1347e1f3dd3072f19f0232d4
            (5, 3, 4, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff590340970d1c4d696e656420627920416e74506f6f6c3935394d006b001d88b8f801fabe6d6d332a2c23490221c9658da4e117b5d8a3d6aea298b15e8eca1e6ef8b5060d19bc08000000000000000000f8608d6d020000000000ffffffff06220200000000000017a91442402a28dd61f2718a4b27ae72a4791d5bbdade7878f3dc4120000000017a9145249bdf2c131d43995cff42e8feee293f79297a8870000000000000000266a24aa21a9ed3bca42ac84fe2476aa283585a57912919dc0989a4ff0c2ed69006ec4f0aedcdb00000000000000002f6a2d434f5245012953559db5cc88ab20b1960faa9793803d0703374e3ecda72cb7961caa4b541b1e322bcfe0b5a0300000000000000000146a12455853415401000d130f0e0e0b041f12001300000000000000002b6a2952534b424c4f434b3ac217de142117834272725babb0a7ffc355805877cc34cd79efab0a0a007111bf0120000000000000000000000000000000000000000000000000000000000000000000000000"),
            // mainnet coinbase of block 799999 c61bfc223ec25581bde44aa229deccb2ac855b99bff7098ecb6edb5dd5fca816
            (3, 2, usize::MAX, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5803ff340c1b4d696e656420627920416e74506f6f6c3930374a00b3004c23a345fabe6d6d4bd088d7ad6d953c6204534adf6e781f1b9dc83b631c445e22010a064e1e080b02000000000000002fd40000510e160000000000ffffffff04485d0f260000000017a9144b09d828dfc8baaba5d04ee77397e04b1050cc73870000000000000000266a24aa21a9ed8d16907a7020cedcdeb04966ea3550de7240d647e24ebbdd9dad990f324339c300000000000000002f6a2d434f52450164db24a662e20bbdf72d1cc6e973dbb2d12897d55997be5a09d05bb9bac27ec60419d0b373f32b2000000000000000002b6a2952534b424c4f434b3a4a327f77c940503af6f3b98b88419e0bfefff343ffe2a212327ed32a0053dfbf0120000000000000000000000000000000000000000000000000000000000000000000000000"),
            // mainnet coinbase of block 840000 a0db149ace545beabbd87a8d6b20ffd6aa3b5a50e58add49a3d435f898c272cf
            (1, usize::MAX, usize::MAX, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff600340d10c192f5669614254432f4d696e65642062792062757a7a3132302f2cfabe6d6d144b553283a6e1a150c9989428c0695e3a1bef7d482ed1f829bbe25897fd37dc10000000000000001058a4c9000cc3a31889b38ae08249000000000000ffffffff03fb80e4f2000000001976a914536ffa992491508dca0354e52f32a3a7a679a53a88ac00000000000000002b6a2952534b424c4f434b3a52e15efafb3e2cf6dc2fc0e6bde5cb1d7d2143f1e089bd874e6b7913005fb2a00000000000000000266a24aa21a9ed88601d3d03ccce017fe2131c4c95a7292e4372983148e62996bb5e2de0e4d1d80120000000000000000000000000000000000000000000000000000000000000000000000000"),
            // mainnet coinbase of block 840011 feecf78a27927207dc21540efeda88cc2a32d7c59a7c1a72329b04918ffc031c
            (5, 3, usize::MAX, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff64034bd10c2cfabe6d6d1f0fa69d2963d0c315a112f5f919c4d0225e21d109a8a40151a16f09460d4a6110000000f09f909f092f4632506f6f6c2f6600000000000000000000000000000000000000000000000000000000000000000000000500423d0100000000000622020000000000001976a914c6740a12d0a7d556f89782bf5faf0e12cf25a63988acf47c9083000000001976a914c85526a428126c00ad071b56341a5a553a5e96a388ac0000000000000000266a24aa21a9ed74a2c74f1251642cdeb0c0ac9222465f604afe78bfe6db8fc89d0c22924f8da300000000000000002f6a2d434f52450164db24a662e20bbdf72d1cc6e973dbb2d12897d5e7ec323813c943336c579e238228a8ebd096a7e50000000000000000266a24486174681f48b44796265b5f7229ddd13df801436533bfafb4ceb84c58c77483a9bbf3a200000000000000002c6a4c2952534b424c4f434b3a84396648c7e1be1123bfc316ffd41792323f833bb794b7e089bd871b005fb368012000000000000000000000000000000000000000000000000000000000000000000fdbe040"),
            // mainnet coinbase of block 877777 ddeb60b3d20864be2a029338e24a54c838a29727238c7ad7a95db696e01da3b3
            (6, 3, 4, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff6403d1640d2cfabe6d6d2b1fb3a4a828afdd7608d1f8c1b4dccc39d8a75f797a133a2f8a16d66f54893f10000000f09f909f092f4632506f6f6c2f7300000000000000000000000000000000000000000000000000000000000000000000000500673f084b000000000722020000000000001976a914c6740a12d0a7d556f89782bf5faf0e12cf25a63988acaefec312000000001976a914c85526a428126c00ad071b56341a5a553a5e96a388ac0000000000000000266a24aa21a9ed93a39b1567cf5ca8b9c4a80e4567e2ad642ed52c3b087f19b3f652148ed5ebb700000000000000002f6a2d434f524501ebbaf365b0d5fa072e2b2429db23696291f2c038e7ec323813c943336c579e238228a8ebd096a7e50000000000000000126a10455853415401051b0f0e0e0b1f1200130000000000000000266a24486174684878f3caa0965ac6a8c27596f07bb0968e14c2f68372c3903d970ed4e107e8f000000000000000002c6a4c2952534b424c4f434b3a16cf32df3db0d8dcd29513c17408ecdaffb11af833681fd54be8aa0b006c3ecb012000000000000000000000000000000000000000000000000000000000000000009a24f33e"),
            // mainnet coinbase of block 877780 1c1cd0ebe9cbdf1ca5e9debbd5007321019c50046e29a17ca38895a309a432dd
            (4, 3, usize::MAX, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5a03d4640d1d506f7765726564206279204c75786f7220546563682400320238d28ebcfabe6d6d84e0cf7e6b67e03bd3ff229bb662e6878c4f4ad115d4c9a1284fb8c6bd9012ec10000000000000000000c437001a360200000000ffffffff05220200000000000017a914bf73ad4cf3a107812bad3deb310611bee49a3c7987f53900130000000017a914056adde53ebc396a1b3b678bb0d3a5c116ff430c870000000000000000266a24aa21a9ed2159e3043910b8a942205da1e208a55841697cbc5fdc30add503374a23622d0000000000000000002f6a2d434f524501a21cbd3caa4fe89bccd1d716c92ce4533e4d4733f459cc4ca322d298304ff163b2a360d756c5db8400000000000000002b6a2952534b424c4f434b3ae5156a9b29201650c69df60be76c488512831869a47d33681fd54b18006c3f560120000000000000000000000000000000000000000000000000000000000000000000000000"),
            // mainnet coinbase of block 877792 0d22b51487d7b06b76fe894898b0cccf598f037b0f42701f37875e531b6e48e9
            (usize::MAX, 3, usize::MAX, "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3103e0640d04843979672f466f756e6472792055534120506f6f6c202364726f70676f6c642f234456df3d616f0000000000ffffffff0422020000000000002251203daaca9b82a51aca960c1491588246029d7e0fc49e0abdbcc8fd17574be5c74b7efcc512000000002200207086320071974eef5e72eaa01dd9096e10c0383483855ea6b344259c244f73c20000000000000000266a24aa21a9ed9674ac27a1d6a81ee2087cc127ef242ccfa4d7f8245e41df9d2007c337dfb72d00000000000000002f6a2d434f5245012e50087fb834747606ed01ad67ad0f32129ab431e6d18fda214e5b9f350ffc7b6cf3058b9026e7650120000000000000000000000000000000000000000000000000000000000000000000000000"),
        ];
        for (i, (rsk_out_i, coredao_out_i, exsat_out_i, txhex)) in testcases.iter().enumerate() {
            println!("Testing case {}", i);
            let rawtx = hex::decode(txhex).unwrap();
            let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();

            // not all test cases have rsk outputs..
            if *rsk_out_i != usize::MAX {
                let rsk_out = &tx.output[*rsk_out_i];
                assert!(rsk_out.is_opreturn_rsk_block());
                assert_eq!(
                    rsk_out.get_type(),
                    OutputType::OpReturn(OpReturnFlavor::RSKBlock)
                );
            }

            // not all test cases have coredao outputs..
            if *coredao_out_i != usize::MAX {
                let coredao_out = &tx.output[*coredao_out_i];
                assert!(coredao_out.is_opreturn_coredao());
                assert_eq!(
                    coredao_out.get_type(),
                    OutputType::OpReturn(OpReturnFlavor::CoreDao)
                );
            }

            // not all test cases have exsat outputs..
            if *exsat_out_i != usize::MAX {
                let exsat_out = &tx.output[*exsat_out_i];
                assert!(exsat_out.is_opreturn_exsat());
                assert_eq!(
                    exsat_out.get_type(),
                    OutputType::OpReturn(OpReturnFlavor::ExSat)
                );
            }
        }
    }
}
