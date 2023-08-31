//! Information about Bitcoin transaction outputs.

use std::fmt;

use bitcoin::{blockdata::opcodes::all as opcodes, script, Amount, TxOut};

use crate::script::{Multisig, PubKeyInfo};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct OutputInfo {
    pub out_type: OutputType,
    pub value: Amount,
    pub pubkey_stats: Vec<PubKeyInfo>,
}

impl OutputInfo {
    pub fn new(output: &TxOut) -> Result<OutputInfo, script::Error> {
        Ok(OutputInfo {
            out_type: output.get_type(),
            value: Amount::from_sat(output.value.to_sat()),
            pubkey_stats: PubKeyInfo::from_output(&output)?,
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
            OutputType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

pub trait OutputTypeDetection {
    fn get_type(&self) -> OutputType;

    fn is_p2ms(&self) -> bool;
    fn is_p2tr(&self) -> bool;

    // OP_RETURN flavor detection
    fn is_witness_commitment(&self) -> bool;
    fn is_opreturn_omni(&self) -> bool;
    fn is_opreturn_stacks_blockcommit(&self) -> bool;
    fn is_opreturn_with_len(&self, length: usize) -> bool;
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
        } else if self.script_pubkey.is_op_return() {
            if self.is_witness_commitment() {
                return OutputType::OpReturn(OpReturnFlavor::WitnessCommitment);
            } else if self.is_opreturn_omni() {
                return OutputType::OpReturn(OpReturnFlavor::Omni);
            } else if self.is_opreturn_stacks_blockcommit() {
                return OutputType::OpReturn(OpReturnFlavor::StacksBlockCommit);
            } else if self.is_opreturn_with_len(1) {
                return OutputType::OpReturn(OpReturnFlavor::Len1Byte);
            } else if self.is_opreturn_with_len(20) {
                return OutputType::OpReturn(OpReturnFlavor::Len20Byte);
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
    fn sigops(&self) -> Result<usize, script::Error>;
}

impl OutputSigops for TxOut {
    fn sigops(&self) -> Result<usize, script::Error> {
        const SIGOPS_SCALE_FACTOR: usize = 4;

        // in P2TR scripts, no sigops are counted
        if self.is_p2tr() {
            return Ok(0);
        }

        // for example, for P2MS script_pubkeys (OP_CHECKMUTLISIG)
        return Ok(SIGOPS_SCALE_FACTOR * self.script_pubkey.count_sigops_legacy());
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
}
