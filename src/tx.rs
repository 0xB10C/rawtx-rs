//! Information about Bitcoin transactions.

use crate::{input, output};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::Hash;
use bitcoin::script;
use bitcoin::{Amount, Transaction, TxIn, TxOut};
use input::{InputInfo, InputSigops};
use output::{OutputInfo, OutputSigops};
use std::collections::HashMap;
use std::{error, fmt};

#[cfg(feature = "counterparty")]
use crate::input::ScriptHashInput;
#[cfg(feature = "counterparty")]
use crate::output::OutputTypeDetection;
#[cfg(feature = "counterparty")]
use crate::script::{instructions_as_vec, Multisig};
#[cfg(feature = "counterparty")]
use bitcoin::blockdata::script::Instruction;
#[cfg(feature = "counterparty")]
use rc4::{consts::U32, Key, KeyInit, Rc4, StreamCipher};

#[derive(Clone, Debug)]
pub enum TxInfoError {
    Input(input::InputError),
    Output(output::OutputError),
    SigOps(script::Error),
}

impl fmt::Display for TxInfoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TxInfoError::Input(e) => write!(f, "Transaction input error: {}", e),
            TxInfoError::Output(e) => write!(f, "Transaction output error: {}", e),
            TxInfoError::SigOps(e) => write!(f, "Transaction sigops error: {}", e),
        }
    }
}

impl error::Error for TxInfoError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            TxInfoError::Input(ref e) => Some(e),
            TxInfoError::Output(ref e) => Some(e),
            TxInfoError::SigOps(ref e) => Some(e),
        }
    }
}

impl From<input::InputError> for TxInfoError {
    fn from(e: input::InputError) -> Self {
        TxInfoError::Input(e)
    }
}

impl From<output::OutputError> for TxInfoError {
    fn from(e: output::OutputError) -> Self {
        TxInfoError::Output(e)
    }
}

#[derive(Debug)]
pub struct TxInfo {
    pub txid: Txid,
    pub version: i32,
    /// Number of outputs minus one change output if there is more than one output.
    pub payments: u32,
    pub vsize: u64,
    pub weight: u64,
    /// Information about the transactions absolute time-lock.
    pub locktime: LockTime,
    /// Information about the transaction inputs.
    pub input_infos: Vec<InputInfo>,
    /// Information about the transaction outputs.
    pub output_infos: Vec<OutputInfo>,
    // is_coinbase struct field is not yet used.
    #[allow(dead_code)]
    is_coinbase: bool,
    is_bip69_compliant: bool,
}

impl TxInfo {
    /// Creates an new [TxInfo] from a [Transaction].
    /// Can return a TxInfoError if the transaction and it's scripts can't be parsed.
    pub fn new(tx: &Transaction) -> Result<TxInfo, TxInfoError> {
        let payments = if tx.output.len() > 1 {
            tx.output.len() as u32
        } else {
            1
        };

        let mut input_infos = vec![];
        for input in tx.input.iter() {
            input_infos.push(InputInfo::new(input)?);
        }

        let mut output_infos = vec![];
        for output in tx.output.iter() {
            output_infos.push(OutputInfo::new(output)?);
        }

        Ok(TxInfo {
            txid: tx.compute_txid(),
            version: tx.version.0,
            payments,
            vsize: tx.vsize() as u64,
            weight: tx.weight().to_wu(),
            is_coinbase: tx.is_coinbase(),
            is_bip69_compliant: is_bip69_compliant(&tx.input, &tx.output),
            locktime: tx.lock_time,
            input_infos,
            output_infos,
        })
    }

    /// Returns true if the transaction signals explicit RBF replicability by
    /// having all sequences of the inputs set to a value lower than 0xFFFF_FFFE.
    pub fn is_signaling_explicit_rbf_replicability(&self) -> bool {
        self.input_infos.iter().all(|i| i.sequence.is_rbf())
    }

    /// Returns true if at least one input spends either nested or native SegWit.
    pub fn is_spending_segwit(&self) -> bool {
        self.input_infos.iter().any(|i| i.is_spending_segwit())
    }

    /// Returns true if at least one input spends a Taproot output.
    pub fn is_spending_taproot(&self) -> bool {
        self.input_infos.iter().any(|i| i.is_spending_taproot())
    }

    /// Returns true if at least one input spends nested SegWit.
    pub fn is_spending_nested_segwit(&self) -> bool {
        self.input_infos
            .iter()
            .any(|i| i.is_spending_nested_segwit())
    }

    /// Returns true if at least one input spends native SegWit.
    pub fn is_spending_native_segwit(&self) -> bool {
        self.input_infos
            .iter()
            .any(|i| i.is_spending_native_segwit())
    }

    /// Returns true if all inputs spend SegWit outputs.
    pub fn is_only_spending_segwit(&self) -> bool {
        self.input_infos.iter().all(|i| i.is_spending_segwit())
    }

    /// Returns true if all inputs spend legacy outputs.
    pub fn is_only_spending_legacy(&self) -> bool {
        self.input_infos.iter().all(|i| i.is_spending_legacy())
    }

    /// Returns true if all inputs spend taproot outputs.
    pub fn is_only_spending_taproot(&self) -> bool {
        self.input_infos.iter().all(|i| i.is_spending_taproot())
    }

    /// Returns true if the inputs spend legacy and SegWit outputs.
    pub fn is_spending_segwit_and_legacy(&self) -> bool {
        let mut legacy = false;
        let mut segwit = false;
        for i in self.input_infos.iter() {
            legacy |= i.is_spending_legacy();
            segwit |= i.is_spending_segwit();
            if legacy && segwit {
                return true;
            }
        }
        legacy && segwit
    }

    /// Returns true if all inputs spend nested SegWit.
    pub fn is_only_spending_nested_segwit(&self) -> bool {
        self.input_infos
            .iter()
            .all(|i| i.is_spending_nested_segwit())
    }

    /// Returns true if all inputs spend native SegWit.
    pub fn is_only_spending_native_segwit(&self) -> bool {
        self.input_infos
            .iter()
            .all(|i| i.is_spending_native_segwit())
    }

    /// Returns true if at least one input spends native SegWit.
    pub fn is_spending_multisig(&self) -> bool {
        self.input_infos.iter().any(|i| i.is_spending_multisig())
    }

    /// Returns true if at the inputs and outputs are sorted according to BIP-69.
    pub fn is_bip69_compliant(&self) -> bool {
        self.is_bip69_compliant
    }

    /// Returns true if at least one output is an OP_RETURN output.
    pub fn has_opreturn_output(&self) -> bool {
        self.output_infos.iter().any(|o| o.is_opreturn())
    }

    /// Returns true if the transaction could be a equal-output-value coinjoin.
    /// Coinjoins require at least two inputs and two equal-value-outputs.
    /// Furthermore, we check if at least one third of the outputs has the same
    /// output-value.
    pub fn potentially_coinjoin(&self) -> bool {
        if !(self.input_infos.len() < 2 || self.output_infos.len() < 2) {
            let mut a: HashMap<Amount, usize> = HashMap::new();
            for amount in self.output_infos.iter().map(|o| o.value) {
                if let Some(count) = a.clone().get(&amount) {
                    a.insert(amount, *count + 1);
                } else {
                    a.insert(amount, 1);
                }
            }

            // a third of the outputs must have an equal-output-value
            let max_count = *a.values().max().unwrap();
            if max_count >= self.output_infos.len() / 3 && max_count > 2 {
                return true;
            }
        }
        false
    }

    pub fn potentially_consolidation(&self) -> bool {
        // Consolidations here are defined to have at least 10 inputs and up to two outputs.
        self.input_infos.len() >= 10 && self.output_infos.len() <= 2
    }

    /// Returns true if the transaction has a non-opreturn output with a value smaller than `value`.
    pub fn has_non_opretrun_output_smaller_than(&self, value: Amount) -> bool {
        self.output_infos
            .iter()
            .any(|o| o.value < value && !o.is_opreturn())
    }

    /// Returns true if the transaction has an output with a value larger than `value`.
    pub fn has_output_larger_than(&self, value: Amount) -> bool {
        self.output_infos.iter().any(|o| o.value > value)
    }

    /// Returns the sum of all output values
    pub fn output_value_sum(&self) -> Amount {
        self.output_infos
            .iter()
            .fold(Amount::from_sat(0), |acc, o| acc + o.value)
    }
}
pub trait TransactionSigops {
    fn sigops(&self) -> Result<usize, TxInfoError>;
}

impl TransactionSigops for Transaction {
    fn sigops(&self) -> Result<usize, TxInfoError> {
        let mut sigops: usize = 0;
        for input in self.input.iter() {
            sigops += input.sigops()?
        }
        for output in self.output.iter() {
            sigops += output.sigops()
        }
        Ok(sigops)
    }
}

fn is_bip69_compliant(inputs: &[TxIn], outputs: &[TxOut]) -> bool {
    let inputs_sorted = if inputs.len() == 1 {
        true
    } else {
        let mut to_be_sorted_inputs = inputs.to_vec();
        to_be_sorted_inputs.sort_by(|a, b| {
            let mut a_outpoint_txid_reversed = a.previous_output.txid.to_byte_array();
            a_outpoint_txid_reversed.reverse();
            let mut b_outpoint_txid_reversed = b.previous_output.txid.to_byte_array();
            b_outpoint_txid_reversed.reverse();

            a_outpoint_txid_reversed
                .cmp(&b_outpoint_txid_reversed)
                .then_with(|| a.previous_output.vout.cmp(&b.previous_output.vout))
        });

        inputs.to_vec() == to_be_sorted_inputs
    };

    let outputs_sorted = if outputs.len() == 1 {
        true
    } else {
        let mut to_be_sorted_outputs = outputs.to_vec();
        to_be_sorted_outputs.sort_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
        });
        outputs.to_vec() == to_be_sorted_outputs
    };
    inputs_sorted && outputs_sorted
}

#[cfg(feature = "counterparty")]
/// Returns true if the transaction is an OP_RETURN CounterParty transaction.
pub fn is_opreturn_counterparty(tx: &Transaction) -> bool {
    if tx.is_coinbase() {
        return false;
    }

    // find OP_RETURN output
    for output in tx.output.iter() {
        if output.script_pubkey.is_op_return() {
            // check if OP_RETRUN message is long enough
            if output.script_pubkey.len() > 1 + 1 + 8 {
                // OP_RETURN + length + CNTRPRTY prefix
                let first_input = match tx.input.first() {
                    Some(input) => input,
                    None => return false,
                };

                // CounterParty uses the human readable hex (block-explorer) representation
                // of the txid for encryption
                let mut first_outpoint_txid = first_input.previous_output.txid.to_byte_array();
                first_outpoint_txid.reverse();
                let key = Key::<U32>::from_slice(&first_outpoint_txid);

                // expected: OP_RETURN PUSH_DATA <payload>
                // drop the OP_RETURN and PUSH_DATA here
                let mut payload = output.script_pubkey.clone().as_bytes()[2..].to_vec();

                // decrypt the payload with the txid as key
                let mut rc4 = Rc4::new(key);
                rc4.apply_keystream(&mut payload);
                return payload.starts_with(&[0x43, 0x4e, 0x54, 0x52, 0x50, 0x52, 0x54, 0x59]);
            }
        }
    }
    false
}

#[cfg(feature = "counterparty")]
/// Returns true if the transaction is a multisig (P2MS) CounterParty transaction.
pub fn is_p2ms_counterparty(tx: &Transaction) -> bool {
    if tx.is_coinbase() {
        return false;
    }

    // find P2MS output
    for output in tx.output.iter() {
        if output.is_p2ms() {
            if let Ok(Some(n_of_m)) = output.script_pubkey.get_opcheckmultisig_n_m() {
                // for CounterParty, n == 1 and m == 3
                if n_of_m.0 == 1 && n_of_m.1 == 3 {
                    if let Ok(instructions) = instructions_as_vec(&output.script_pubkey) {
                        // expected: OP_PUSHNUM_1 PUSH(<pk1>) PUSH(<pk2>) PUSH(<pk3>) OP_PUSHNUM_3 OP_CHECKMULTISIG
                        if instructions.len() != 6 {
                            return false;
                        }

                        let first_pubkey = match instructions[1] {
                            Instruction::PushBytes(x) => x,
                            Instruction::Op(_) => return false,
                        };

                        let first_input = match tx.input.first() {
                            Some(input) => input,
                            None => return false,
                        };

                        // CounterParty uses the human readable hex (block-explorer) representation
                        // of the txid for encryption
                        let mut first_outpoint_txid =
                            first_input.previous_output.txid.to_byte_array();
                        first_outpoint_txid.reverse();
                        let key = Key::<U32>::from_slice(&first_outpoint_txid);

                        // expected: PUBKEYMARKER (02 or 03) and payload
                        // drop the PUBKEYMARKER
                        let mut payload: Vec<u8> = first_pubkey.as_bytes()[1..].to_vec();

                        // decrypt the payload with the txid as key
                        let mut rc4 = Rc4::new(key);
                        rc4.apply_keystream(&mut payload);

                        // expected: PAYLOAD_LENGTH + PAYLOAD
                        // drop PAYLOAD_LENGTH
                        return payload[1..]
                            .starts_with(&[0x43, 0x4e, 0x54, 0x52, 0x50, 0x52, 0x54, 0x59]);
                    } else {
                        return false;
                    }
                }
            }
        }
    }
    false
}

#[cfg(feature = "counterparty")]
/// Returns true if the transaction is a P2SH CounterParty transaction.
pub fn is_p2sh_counterparty(tx: &Transaction) -> bool {
    if tx.is_coinbase() {
        return false;
    }

    // find P2SH input
    for input in tx.input.iter() {
        let redeem_script = match input.redeem_script() {
            Ok(script) => match script {
                Some(script) => script,
                None => continue,
            },
            Err(_) => continue,
        };

        if let Ok(instructions) = instructions_as_vec(&redeem_script) {
            if instructions.len() < 8 {
                continue;
            }
            let payload = match instructions[0] {
                Instruction::PushBytes(x) => x.as_bytes(),
                Instruction::Op(_) => continue,
            };
            return payload.starts_with(&[0x43, 0x4e, 0x54, 0x52, 0x50, 0x52, 0x54, 0x59]);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::TransactionSigops;
    use super::TxInfo;
    use bitcoin::Transaction;

    #[cfg(feature = "counterparty")]
    use crate::tx::is_opreturn_counterparty;
    #[cfg(feature = "counterparty")]
    use crate::tx::is_p2ms_counterparty;
    #[cfg(feature = "counterparty")]
    use crate::tx::is_p2sh_counterparty;

    #[test]
    fn short_input_script() {
        // mainnet 0f24294a1d23efbb49c1765cf443fba7930702752aba6d765870082fe4f13cae
        let raw_tx = hex::decode("0100000003d4dfa41ffe9825af0aad023f084b4dd4a599d6cb8d083e58e3a53e8ad682a6ae010000000401030103ffffffffe2274e1294e1708f344e7cd5156648750bc60d3bf3705130cdcba66675e3439b010000000401030103fffffffff41d101368d124c5b10bf130bceece07623d87767a2c950a35d1b7b6217a2329000000000401030103ffffffff0170032d00000000001976a91429c9743283afd76eed5811788b20b23f9eece00788ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        TxInfo::new(&tx).unwrap();
    }

    #[test]
    fn bip69_compliance_1in_1out() {
        // mainnet 3d896cc02c6be867c1619bfcce8c96284f2fd17b34f070ab4b307b56edcf1a12
        let raw_tx = hex::decode("02000000000101f795ab70b2c98c1b97fdbd1e98a238bdbc4336362099ea2d07fd7b5db7c48aa72500000000ffffffff01236500000000000017a914f73d4190dba76f89573d8ecca6cd49c7ca9e852b870247304402202f95f204b7663a61f8d8a8b6691562d23f6774b3ed64b3d993233fa1ed6c6c98022005723fe5c98182aca858dfab50ea4e68103ddfd83ca10480c825169897fff42901210201fe8351e1908fc82cb314ca4a532d7a9d81726d9fd60df0487ff7dd4235c4e300000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        assert!(TxInfo::new(&tx).unwrap().is_bip69_compliant());
    }

    #[test]
    fn bip69_compliance_3in_4out_compliant() {
        // mainnet 95ce62ff4b64ea9358edb02d695559cb90461ec6f695ff5f207005e52cd5ba92
        let raw_tx = hex::decode("0200000003947511e452abbcfdb0cb56c05acfef41c22f68d2f54415b25cff7672a718a91e000000006a4730440220620a98a40e18e799f8adba3204acc776ae8fb6a9861ab739e346a26e3067e29202207bad9bbcf4278c48dac23061e3bb97821712f4ea0b8d42a8367fbb1f79018cf2012103241af1d91902d8ff26ccec89ff33664bb328b3f980f8e98e67187e931d8c4565fdffffffd75a3121036692055c44782dd6908bb346997659561a923bc96bc70b54f230ae000000006a47304402203389c2c3b51bdcb7c7c2bad02bb4ca78866ce202bc0bedf693d15b872a840f3f022029311b399c9f583cb746045aba2343e31bda147c88334bb93f0b8b9526aba0ed012103583031de58a37d8c0d5840b9db5d823f2aac071f9347c56824f1b926cff559fdfdffffffb0840efafc1fb1595c684225e10cb59e1440ee8698fad3be3399d97ae78cc4e6030000006a47304402202e46e5d1b5230225deed4fc395c05a1c163602e030feaa135de2e2498fb3979902200cb4c72782d1cc6167cb97a670a1cdb6bfb361bf104350d95b6cadb3c85d39d401210242191a9a0b2398032fba0b9503846555a07feebcb5822d60e50fb565dceeebfafdffffff040c2e0000000000001976a914c5a0ae47fec174bb1788cb2f379bfc49f59f751088ac3f430000000000001976a91425434bd302f418914bd8643cc6d814a27fb97a2288ac73660000000000001976a914434d62974d0263bbbd5accd4bf3222987059101888ac1d2c0e000000000017a914345eaf1ba7d68077f411ae3222ea840ebcb3f81487785c0a00").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        assert!(TxInfo::new(&tx).unwrap().is_bip69_compliant());
    }

    #[test]
    fn bip69_compliance_3in_3out_not_compliant() {
        // mainnet 8e8ab032d6df899610c3eb5d7d14d09eaf0e54e5da15dfd94c1472984a5a7087
        let raw_tx = hex::decode("02000000000103edfe97964f954656db279834f3fb810cf2868c26f1fe5fd2fd3bb6d293da80500100000017160014517f3e10051df116600af7f322ebad1eb0834676ffffffff6a5d444fe88ef03df7d8062c429850286c434cb9ee77947b6e73dc34e200ef040000000017160014c2af9fdf9f2e8dbe406163e1b3c22c4a98c22bccffffffff1df2a57be954c93f002d4d272616ebbe7952ec100fd77e8c9118a4df88ae694a0000000017160014fc89a4451ba56e5511aac20a634206391f267120ffffffff03a13f05000000000017a914acb331118b1b1d233dc5ee3972d8b0eb10a389648748d104000000000017a914e416571b39ca465e70ca21c4401925a2d53c9cd687823b9e000000000017a9144ff5174680c12f362699f4186e822e64c0f741ca8702473044022017f06d1a4baf4783566f5a751c3f5239d896728e26a34b484d5b804a83571b31022038e76fa397eae5644651a0c7c1fa8b4533f4df061d315ac4794669958e7afb3e0121032adeb16dc182591e03bbd57f68bbee23d1d2b95315103008ee7b2afc8151d8a00247304402200fadb196510acc654ddbd3b3be87051e0db8bf58a003f07628be44a666a2bc2102200e8010a7abdf6c635f5a3ec7ab06c2d4e7ce520e99a617724349025b588b52630121027c9b7d4b9789bdc5fdd4e170d593619bd185b376d53eaca3463f3925ca8047af024730440220486e51ace259a49ff14fd069b3c2ae4890da290651a9f364dbe352b67aee10d402203dc2f37182ed5bae92ebed04d531d7e34c6e1dc17e8ecaa60f83b054f967827401210295dec103680805c7934cde983acdbb3224119bfa770814808f98c651655d764a00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        assert!(!TxInfo::new(&tx).unwrap().is_bip69_compliant());
    }

    #[test]
    fn test_transaction_sigops() {
        let tx_sigops_pairs = [
            (6usize, "010000000001015b26c9550875279971632eafde56bd76d3c25fc544c250de8819c53cf30466c30000000000feffffff11b7640000000000001600143a7f1bba431ca8c37d4cd1cde573ca95b9ce33e57ccf000000000000160014c20781c62f767c44149cbc2faa131c24d1b596b68513010000000000160014056b0b030aa5bb5736273a3037c2e1b22fc951d08a3a01000000000016001474403ba47b091c6a72488b19b2acc207aee681641142010000000000160014d89710afe6e62b45284e50aab6697a13f754b6945c470100000000001600149118018676be9cde9d01e4e5cf9696649d01b5390768010000000000160014d49466813dbe618230ddfe033f991de4b1de9ddc72770100000000001976a91496070daa16d6226220a27632826eb262212b45f088ac8fcf010000000000160014df52cb8f365679fe7650ac89c18f39094a8289defbd30100000000001600148c6991d57e341187e42f3cde5635394eb88cef5ca2da01000000000016001496941f95afd6149ab45c5cc109fa6c7a184f5bc804ea010000000000160014c0fbd69ede930029485e0ef5f0fe90f9450d4cab020b02000000000016001466de96b53d55749d55e544b4c5c8788486e0e0ac14a8020000000000160014601c6732e6a22c3a4d87e97e18f205770131cf9249040300000000001600146ce2d6dac9c8aa6862ecc045b9b5114bcbfe0dcc1927030000000000160014f66758a0748c715d167b9c45bfc23af35587d478754503000000000016001418b3e52251c640a241de407b960ceeb6bc696722040047304402205194a738a89b8d5d38a9da65953effdabae7c2640482b89d44ffecc67b4b1f36022008e3ff0af2dd4b734288ab9e1c00f63e7fc654fe7664d885a91ba1f97d3d183b0147304402202a9bcb6d492583f7045cfffa375a772247ed50e7144c8acb58c658d6740646af02202e9bd9e63712d70b0d9d57af8ec6e9f51bd66e4fcf131f624684642f09a892e6014752210256abd6a1f3b25e64ce575e06c434ac49a48041c66a0fcc8a5f15a08c7fb2940c21031e14e051793339d04552004e0c6417c70d05aae1948962bed2188616623516ba52ae6ef90b00"),
            (29usize, "02000000000101cbdf7b986004a715fdc26fa43c539535a2ace9920d2f73721dc86270ed7086a40300000000fdffffff09134a1600000000001976a91424f7e9c66ba2a9e92aad42228dd6d5fd72c6258588ac4a8e0300000000001976a914b9676ad121e0b2c0a186f159d6942b4cc764699588acbb7c1e00000000001976a914b89b10ecd0c130f041ce2dff823b6518431c736c88ac4f111200000000001600147f3abf331ec3d7710a945faf498a68438bb4a1d1960a1b00000000001976a914bfc9663e29e246ae180eb176f1b5587ca6c287d788acf3f20900000000001976a914630302f6d3a63d9e4977f95f39d9a5edd2628da388ac40393200000000001976a914ab05fb0bcd16e6c1ca8f8d0b200b6a643b9d858788ac97741400000000001976a9148031b161c8441d11accb3933cc35aee5e7c7559488ac62f7af0f0000000016001424e5e542b61d260e7b46f29dc887f83b231f3d1d02473044022007b6e8f3391d6222baf53695659460be8f93996e9aadb7b21b807aeaa64f413802201e17be7fd7a4d05a2fd167a16e141151d7747d7bfb9b52d9abbf64c13ee8b794012103b4118dad6f16a2e60542ebc883583277172de605ccbba23dbb5899e401bc69638bf90b00"),
            (9usize, "02000000000101369e3987ed900be5360982501c59ec8f54763fff6a52e75ab00c66d78bddbec80100000000fdffffff0320300500000000001976a914b59c3a811b3480befcffd31253374bb27fabd77388ac6f0a0900000000001976a914573c227fde2d5dadc3aa33ce78f499e2ceb358e088ac1d0a594300000000160014f60834ef165253c571b11ce9fa74e46692fc5ec10247304402204e666de27d7117902b15d072e861c480cd06ac2b1bddd61349ad6f08db607dd202205f9f9ca6e56d57f03c88c9cfc24e4e4b2e655d9b365dca8aba29b0477f268bfd0121026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea28600000000"),
            (86usize, "01000000000102d962edaf1463fcbd3f7e5262e9013f1a665d18bb0593f02d9957d0123c67af294c00000000fffffffffe115c6ad5dd7622364198ab7ddbcb3a241d2c1595a4a0820e34fb60a14b8efa01000000232200204dabe51a312c54ff621373fd1bdd99c0ecc433fd78d4d8b5d4a1ec09c3b46ef3ffffffff353f960000000000001600145f8cff66afae811b8694c608caaaf0f0b035898fc057010000000000160014d583589a104a29c222e4f56b48ed494ee14e068c888a0100000000001976a914c19f638d64aecd593fcc695fcf19c0a1ec663c2588ac708e0100000000001976a9140133799122cb3697f93d74ebe448917afb805a9188acb0ad01000000000017a9142531c305d85ebed7d895ec0240536b20d228a5258748e80100000000001976a91434a741db089157ed4740cc8451a353433287913c88ac785d0200000000001600148b3c9eaabb004ba90954599e41c62e4b6aa3e333e8740200000000001600146736875ed53b2df91c6f7f6fe1a581cf9597929ad07802000000000016001490d370478e087bd2bb037b9b90b7ed1c478cabd0588c0200000000001600147a679175f97ce1964710c41f9fe085bb5251bc85409002000000000016001446fbb01007d57e6eaa30beab4e5b994035d1f311409002000000000016001488b9d2ba8f0263f5885ea8abdbf6a876c3ae3c24d8ca02000000000016001420cc1a5ceee8a1d4833dc3e80dc1126e5bc197bcd8ca020000000000160014b0489b275b03f20ed5282e0789af4f9c2d287c5c58090300000000001600140b7411a6646820a63394d37571ee17c193f9eadf400d03000000000017a914aef8ebc7394f746221d2db093c58ca4938f7ff3687101503000000000016001497f1b15ba312f2cf5b93d436ee9a1bb8fef4b699905303000000000017a91487757770c42cb5a1031474264a13258b1a0637a387c89d0300000000001976a9148ee571b7594b5673cccb8a2eef6e36bb27ba0a8688acc8970400000000001976a91495f4252e7a20bb06ec249694f4769f483ec385f788ac60d20400000000001976a914601ef774603d99bf413553a10b56a89c489dda6d88ac18de040000000000160014abf0e0755f36cf1026ef3dcb701e11a0bebb1a72e8e504000000000017a914d510c93e87e566e7e53b3a3ef25892897495f4678740010500000000001976a914b0736cafbf6a19048b414101e9c207eee170840888ac27450500000000001976a914c859652b6644181080123b6d6beeb01353eed4b588ac28ff0500000000001976a914bcc18a564b461a64c9513d5b8531d56ec828449588ace85c0600000000001976a914cb0f853abd9e8929129748b88a4a4c4ce10954bd88accb200800000000001600148e54c8d731d9f91f09dac6add1b22ef9daa643ba717e0a00000000001976a91429dac391762253b12b728ad4a192b3bb136f8e7188acd89a0a0000000000160014d9bbd1690ff0f34a66db5ff6b1e29693ec1947f300be0a00000000001976a9148c070b57613a81d734a9fd30675460f9ab6fe59588ac3cb60b00000000001600143a3297dbed6ea17e4cb3a762807e9054b0a4aa1ae8bb0b00000000001976a914496b455d3a29d2cbddc435e9029651955cea63ae88ac20060c000000000017a91473c4c8a65ecd3f75416c3535afd403efeca4f09f876f630c000000000017a9145aea48748e8aff443294696bdc5d1e51e250f5cb8790170d00000000001600141b947b0c659778eae66a87543bab81e395b59441d0360d00000000001600144d2f05456e694e6b33fdd93f0270ee70a31d8ddc20770e00000000001976a9148ec7a5ab3ca5392377ac18160e0cc682f29d4d3288aca0b50e00000000001976a914749cf68d7855cee5333198618bc11e36fc14f2af88aca8840f00000000001600140d2a31b46bc58a28ac57155819cb75f0cad89968a8f51100000000001600143095582bcfeb21a7e3b58340560dce47fa7c0733f83b1200000000001600147e276285bc7437c30480c14bfbb0666e00db2632203b180000000000160014a7f4c809680bfd517626226fa5739089d64c0a56109118000000000017a914d82e45767ce025298667a9e64f6feb6b312afc5b8718dd1900000000001976a91482e85ca18d50eca438fb6f07d38c80cdba2c983688acccb91a00000000001976a914d0d8ea777426c0b34850de0f3c2656d58ea226b688ac90c31a00000000001976a914e6a1f6543f64256574859b69e21086ff83dcc27d88acd041200000000000160014b4afc34958c0a0d33b7c4b43d895b58be6d3fca2e83c3500000000001600144d2f05456e694e6b33fdd93f0270ee70a31d8ddcf0446b00000000001976a914ba6d7f42fc439e3c1db99bda1086f2ea65171f9a88acb8ac7700000000001976a9148b4b2f5f7a508abe657d71199c3121f15d9a6ede88acc0eb83020000000017a9146c18cbd8b8d8db62f3f89bfa7929481cf460390687af86f102000000002200209ffa349e21dc16bf62e51f903947890f080d0becc6c145fef4db4fd6f56935fe0400483045022100b2a28e3877ec59b886f7a7d4ccf13600382520d724333dba67e1aa1fdf9c389f0220189a17c369d26896088f3b3ca59187b44a1a420aba62e5e510a748bd03c5588a01473044022015701affe64eca107942e18cb468338a17512a0a5faf160b2e6576c9acdbae21022001afbdfc8c1d6577103842a4f78b35fb8f3e01795fdd9b22bb3015189fe82c630169522102e0119b324f22f357b4d1736b25f51468e8080e821445662aadf6f268770e25fd210354b7fb16256afbcffcac8d6a63e65e585985a2ca2d3f0813b24ec27628ec1abc2103fe2c82f09defdf1f458b66b05642ab4299c241718d3a7cec3518c8cec188dced53ae0400473044022061080519531e7cd52fc36b163fd85fe466dd3c97e97438608dcf0eaaf67bb45b0220286721037311b638628e8bbeb26430c0dd7038cbe9f5a27df6b75782063ff5490147304402203b173dbb0fa08c3cf41de914de7488e7002bb5eed018e8f5298077289bb955150220780077fecb7d54a41a857419e60d1ea538ce1c487d0202300f7271d1fed1bcaf0169522102db43e4cde7cc070a45b6aa4a46d6d2e0bc615c31dcc27e2b97cd0b8287377d2a2102a8da544e96bf9f2ee56035a20420abe95ab19fe24026a553603fe73113ada43d2103a7d02955bc72bddf5d6c0893489b98cdce698964e94d1657f894eb8732d3f77653ae00000000"),
            (5, "02000000000101b557ad25033e2e7323d1ea26035bd8d84c0529a8d23c6d243002fb4d277d5ba10100000017160014d28e1be3503020526295715f41b4c9e0d291c5b90100000001c0d40100000000001976a914ea9911ef55b869720c76846bba0babf6f2748db388ac02483045022100c586d4e2ff16a8354fd4fbadcdfc1dc66782c66ba83f7be87e7692e90cc5105e0220759f96d12dce5acd7eb515a312ec9112b8a9eb8b220ef120d5f34ed35465b2e30121030955dbd8b34862058e6edaef080243cdd1b0b907d626990c1f404614d40be18700000000"),
            // coinbase with two P2PKH outputs (from F2Pool; splitting uncommon ordinals)
            (8, "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6403ac9b0c2cfabe6d6d654b01255ebb409c165395395b3f3c2301f032f53df45cba5ed5d266dc2c786010000000f09f909f092f4632506f6f6c2f7300000000000000000000000000000000000000000000000000000000000000000000000500ae970800000000000422020000000000001976a914c6740a12d0a7d556f89782bf5faf0e12cf25a63988ac1ebc4025000000001976a914c825a1ecf2a6830c4401620c3a16f1995057c2ab88ac00000000000000002f6a2d434f524501a21cbd3caa4fe89bccd1d716c92ce4533e4d4733bdb2a04b4ccf74792cc6753c27c5fd5f1d6458bf00000000000000002c6a4c2952534b424c4f434b3acd2e3ba1354794d09aabccd650c2155ae16cd9830cc9b0d57aecd423005ba3a64940a53f"),
            // failed the input check with EarlyEndOfScript, as we didn't skip the sigops counting for witness coinbase scripts
            (0, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5803ad9b0c1b4d696e656420627920416e74506f6f6c3936312900e50185de0c73fabe6d6d4045cd649213cd20a5b9fbc8e8d110413043505dd479aa610953d960b83bc22e10000000000000000000ca8d0370000000000000ffffffff05220200000000000017a91442402a28dd61f2718a4b27ae72a4791d5bbdade787821dea280000000017a9144b09d828dfc8baaba5d04ee77397e04b1050cc73870000000000000000266a24aa21a9ed7d3074d041ce338acb516547585351a0d058c476cf2b91141fa94db4096d3aea00000000000000002f6a2d434f524501a37cf4faa0758b26dca666f3e36d42fa15cc01065997be5a09d05bb9bac27ec60419d0b373f32b2000000000000000002b6a2952534b424c4f434b3a6b102098d342b6868cb55909ae57bec35e74ded30cc9b0d57aecd423005ba3ab0120000000000000000000000000000000000000000000000000000000000000000000000000"),
            // failed the output check with EarlyEndOfScript, as we failed on outputs pushing past the end
            (0, "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2f0363740c0474d64e652f7a7a616d78632f76649b3c094f135bf4b83108c14ea85f1226746ff200b4020000ffffffffffffffff03a1defc2900000000160014b6f3cfc20084e3b9f0d12b0e6f9da8fcbcf5a2d90000000000000000266a24aa21a9ed22e7492ea82d70262d12e74db7b7813d93365a2bf528aa803b191a209272a65f00000000000000002cfabe6d6d14c8eef25658e2e29cf3580d3c0cfe6cf5ece1bfba5949e1b44de824cc5c4be7010000000000000001200000000000000000000000000000000000000000000000000000000000000000a1233f55"),
            // mainnet 44c857ef596332bbdcec28d2337a3c7eda10c23da0dc1769325b40c9220c4816, non-standard rsk tx
            (84, "0200000001e5af92d188010aa34910c71de4a55d6f142c0989a62af388b10bd8a33b54e86c00000000fd3803004830450221008b42e9089fd73cd1367d7963664314fd7affc434766b97ef35e57f10c764eca802204bdf578f5339448053cc077b410050ca95f54f0773d1be37e4c8f7028b5b630d014730440220599fa798537dbca65defc998088b56df77993914f7b1f6d262ae210c49caf00a022013f11bc2c85befdcf36aac357e0d1cd9cd1954ccbbe6c90c56575b5e68dbb17401473044022040cf3f17bb5639e9a64c89566b21a13339e362ef27f02ac3bdd09a79b5564a4402203556c8a5ef82e99c4148ef1b9626d663fc8aabefee8eecbb016439d0dc255b6c01483045022100cc20e9db6c4ae335eb6a9af4f9f915b8dc9e6e130af4266a3c720464796d68b3022010203f84d6f9cc20fba81d2971fcb276595c6c5ed6f009f99da5cea93ff5dfdc01483045022100e39c1896c909b87f2d860ba23af7e94873dfeccee33657d28041335ca708bb36022002b70cb3050bf418645e4703958252706e3008ac7a940a7248747f5651b0ea0a01004dc801645521020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db21026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a422103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d59670350cd00b275532102370a9838e4d15708ad14a104ee5606b36caaaaf739d833e67770ce9fd9b3ec80210257c293086c4d4fe8943deda5f890a37d11bebd140e220faa76258a41d077b4d42103c2660a46aa73078ee6016dee953488566426cf55fc8011edd0085634d75395f92103cd3e383ec6e12719a6c69515e5559bcbe037d0aa24c187e1e26ce932e22ad7b35468aeffffffff026cd03c00000000001976a9143a267e4435e590d9e711d04954d8c8ef1003658588aca59f1d020000000017a91485aaffdabb34e8f7403291b3eff574129cc2486d8700000000"),
        ];

        for (sigops, rawtx) in tx_sigops_pairs.iter() {
            let tx: Transaction =
                bitcoin::consensus::deserialize(&hex::decode(rawtx).unwrap()).unwrap();
            assert_eq!(*sigops, tx.sigops().unwrap());
        }
    }

    #[test]
    #[cfg(feature = "counterparty")]
    fn test_is_opreturn_counterparty_tx() {
        // mainnet e08c3d808317731ef6040799646de2f567590ff890c8fe920a12e36502d8ceb0
        let raw_tx = hex::decode("0100000001c05b048e0964c3db4a87c33e00503ccdc3d7bff75892639029ba311ce7829745010000006b483045022100df78463aa570274bb2be52ee7410265f5165c0f9f00fb67285582a3e365711ed022074eb1c368569164bb1ad4bca9833b8398e1bb90409e58ac92a98d5ecd117e7e4012103a6e6e5baa76d34499b6b895bccf5a7b5f0d6b264637dd1cddad72cea2c4a1499ffffffff0200000000000000004b6a49f7032ee8d7f20e860d177068a124158cebaa066a209a916e2e6fa26637468bfa7742f6c58724fb1d36aa209aa394245b94afbe385df237e9c4821c6e9d8b9c234f8de5c68760561d03ebd0eb01000000001976a9142e9943921a473dee1e04a579c1762ff6e9ac34e488ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        assert!(is_opreturn_counterparty(&tx));

        // mainnet 229028368caadfbab2654f888e919062f117e24da5b3a1974ea9796162191a56
        let raw_tx = hex::decode("01000000011378419519eebd4034e6eae696e98eee4f247f2103394740844a1cc5462fa465010000006b483045022100f592b2df2e8b9dcf6bc77bd0e8cc1064b74c6119cfb3482f96d03d1442d60f82022040372b55fd7aba6d7474ddce7e6d6a7b9219018e925e31379d06f4216104e51e0121021f6dc395418fed2bce5eb47485b2945e3681ba0a690c57779b09f4b15cb66afbffffffff020000000000000000386a36a61966fd345606c378b4ccd3596ab28200b3cb90398c0babbd1ef635a6dfd106e89794feae9a58d7700e6d3b41782e2181118a94eb9117390000000000001976a914bcb7dadb45b78b33653d38789ac14d54dff6de1388ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        assert!(is_opreturn_counterparty(&tx));
    }

    #[test]
    #[cfg(feature = "counterparty")]
    fn test_is_p2ms_counterparty_tx() {
        // mainnet cf01557d4e6b0eec45d07d871e37253285e33672a3a9c0708a593c096ea98e16
        let raw_tx = hex::decode("0100000001b731c05ddc859c44326689fb588e81e054def1baff4cdc368a038abc26e9b197010000008b483045022100926a2470ccee567d806fd9697dbcb8b2ae5525888403132ab6da2bc66b36e8500220170d6ae7b5ea57946eb9f0479a83da96c1622057551059ffd645df8f628410a00141046e2298d86527d08589cf81eefb0857f5dda1167b49d99cf03f3fb2b01098e1e3cedcbb6da3c7dbdc893f15bdef80d51f9b2e3099949e7d7c9bbb2ec1c19aef4effffffff03781e000000000000895121021fab2c6657cd39baaf6fe10d9cb6731a6f221f57c5d65e6c34f69e62ed6aa9d92103fc9831f32e44cd7f8e88af4815d0be5aed5af278f3cc055031ceb16075c7709541046e2298d86527d08589cf81eefb0857f5dda1167b49d99cf03f3fb2b01098e1e3cedcbb6da3c7dbdc893f15bdef80d51f9b2e3099949e7d7c9bbb2ec1c19aef4e53ae781e0000000000008951210306ab2c6657cd39baaf546fe1af06444c763947788b97152d72dfd523a025fd552102b3b65b804142b90bfefb95673ab7cc349c28860addaf6a3d1eafc21310b3038541046e2298d86527d08589cf81eefb0857f5dda1167b49d99cf03f3fb2b01098e1e3cedcbb6da3c7dbdc893f15bdef80d51f9b2e3099949e7d7c9bbb2ec1c19aef4e53ae5bd14200000000001976a914a925bca955a11b6c07c2767acfb3f1dabce7ae5688ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        assert!(is_p2ms_counterparty(&tx));

        // mainnet 229028368caadfbab2654f888e919062f117e24da5b3a1974ea9796162191a56
        // OP_RETURN CounterParty tx
        let raw_tx = hex::decode("01000000011378419519eebd4034e6eae696e98eee4f247f2103394740844a1cc5462fa465010000006b483045022100f592b2df2e8b9dcf6bc77bd0e8cc1064b74c6119cfb3482f96d03d1442d60f82022040372b55fd7aba6d7474ddce7e6d6a7b9219018e925e31379d06f4216104e51e0121021f6dc395418fed2bce5eb47485b2945e3681ba0a690c57779b09f4b15cb66afbffffffff020000000000000000386a36a61966fd345606c378b4ccd3596ab28200b3cb90398c0babbd1ef635a6dfd106e89794feae9a58d7700e6d3b41782e2181118a94eb9117390000000000001976a914bcb7dadb45b78b33653d38789ac14d54dff6de1388ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        assert!(!is_p2ms_counterparty(&tx));
    }

    #[test]
    #[cfg(feature = "counterparty")]
    fn test_is_p2sh_counterparty_tx() {
        // testnet 66ca3ba2df81d9c1da8ef4c253fab2ab5eda1db699ab028050c4d261d3716181
        let raw_tx = hex::decode("010000000187e88fa930f1843d690db12fdb98b12efc9c52cc27b160aa4d128d82d4e8824500000000fd6201483045022100985cf3628b082c3af81509c048b13bf747251e869aee22133fc7a73dcfdfcc6a0220074fa0d9d1e0151e6f5cf84bccaf83f6f42c51aabec65c123bf327bdc13214a3014d16014ceb434e5452505254590300046f4a2fdff4db96b99f33972f11b9b32b545a824d086f5e1872b887654a3c44e5a3bd811e0ed8e911f58e6f78a50bfaf0e6a8dab23b0c802e7200d5a0d905c96fd8a4bff843c2ecd12b82b12b77e7151cd7928ef940000000584bf050f80000000000000007028000000000000000184746573744000000000000000619d989e5d195cf00000000000000018773656e64696e678000000000000000f0000000003253aac4c2a32b9ba1038bab4ba329030903637b7339039ba3934b7338000000000dc617b106b2cae6800000000533a84c4124ba60000000014f64d7104d2e60752102b1a624aadeb689e79e53c66cb282cbaaf9b381be4436ddcf48f99b5e403f2679ad0075740087ffffffff0100000000000000000e6a0cb18961d65a9207474701a54e00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw_tx).unwrap();
        assert!(is_p2sh_counterparty(&tx));
    }
}
