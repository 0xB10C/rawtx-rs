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
        let mut input_infos = Vec::with_capacity(tx.input.len());
        for input in tx.input.iter() {
            input_infos.push(InputInfo::new(input)?);
        }

        let mut output_infos = Vec::with_capacity(tx.output.len());
        for output in tx.output.iter() {
            output_infos.push(OutputInfo::new(output)?);
        }

        Ok(TxInfo {
            txid: tx.compute_txid(),
            version: tx.version.0,
            vsize: tx.vsize() as u64,
            weight: tx.weight().to_wu(),
            is_coinbase: tx.is_coinbase(),
            is_bip69_compliant: is_bip69_compliant(&tx.input, &tx.output),
            locktime: tx.lock_time,
            input_infos,
            output_infos,
        })
    }

    /// Number of sigops of the transaction. Sigops in legacy and P2SH scripts
    /// are scaled by a factor of four.
    ///
    /// These are counted while the inputs and outputs are processed in
    /// [TxInfo::new]. Prefer this over [TransactionSigops::sigops] on the
    /// [Transaction], which has to re-run input and output type detection.
    pub fn sigops(&self) -> usize {
        self.input_infos.iter().map(|i| i.sigops).sum::<usize>()
            + self.output_infos.iter().map(|o| o.sigops).sum::<usize>()
    }

    /// Number of non-OP_RETURN outputs minus one change output if there is more than one
    /// non-OP_RETURN output. This should approximate the number of real-world "payments"
    /// happening in this transaction. However, we don't actually know if a certain transaction
    /// really made X payments. It's more a guess-timate and helpful when looking at many
    /// transactions and blocks over time to observe changes in a payment trends.
    pub fn payments(&self) -> u32 {
        let non_opreturn_outputs = self
            .output_infos
            .iter()
            .filter(|o| !o.is_opreturn())
            .count();
        match non_opreturn_outputs {
            0 => 0,
            1 => 1u32,
            _ => (non_opreturn_outputs - 1) as u32,
        }
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
                *a.entry(amount).or_insert(0) += 1;
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
    let inputs_sorted = inputs.windows(2).all(|w| {
        let mut a_txid = w[0].previous_output.txid.to_byte_array();
        a_txid.reverse();
        let mut b_txid = w[1].previous_output.txid.to_byte_array();
        b_txid.reverse();

        a_txid
            .cmp(&b_txid)
            .then_with(|| w[0].previous_output.vout.cmp(&w[1].previous_output.vout))
            .is_le()
    });

    let outputs_sorted = outputs.windows(2).all(|w| {
        w[0].value
            .cmp(&w[1].value)
            .then_with(|| w[0].script_pubkey.cmp(&w[1].script_pubkey))
            .is_le()
    });

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
    use crate::testdata;
    use bitcoin::Transaction;

    #[cfg(feature = "counterparty")]
    use crate::tx::is_opreturn_counterparty;
    #[cfg(feature = "counterparty")]
    use crate::tx::is_p2ms_counterparty;
    #[cfg(feature = "counterparty")]
    use crate::tx::is_p2sh_counterparty;

    fn decode_tx(hex: &str) -> Transaction {
        bitcoin::consensus::deserialize(&hex::decode(hex).unwrap()).unwrap()
    }

    #[test]
    fn short_input_script() {
        let tx = decode_tx(testdata::TX_UNKNOWN_INPUT);
        TxInfo::new(&tx).unwrap();
    }

    #[test]
    fn bip69_compliance_1in_1out() {
        let tx = decode_tx(testdata::TX_BIP69_1IN_1OUT);
        assert!(TxInfo::new(&tx).unwrap().is_bip69_compliant());
    }

    #[test]
    fn bip69_compliance_3in_4out_compliant() {
        let tx = decode_tx(testdata::TX_BIP69_3IN_4OUT);
        assert!(TxInfo::new(&tx).unwrap().is_bip69_compliant());
    }

    #[test]
    fn bip69_compliance_3in_3out_not_compliant() {
        let tx = decode_tx(testdata::TX_BIP69_NOT_COMPLIANT);
        assert!(!TxInfo::new(&tx).unwrap().is_bip69_compliant());
    }

    #[test]
    fn tx_payments() {
        let testcases = vec![
            (3, testdata::TX_2IN_4OUT),
            (1, testdata::TX_1IN_1OUT),
            (1, testdata::TX_1IN_2OUT),
            (1, testdata::TX_1IN_3OUT_OPRETURN),
            // mainnet 6f660e9f1bbfcc8435593eb8ff70a501275ad6cdbaa536747bd9d55bdbeda65a
            // same hex as TX_1IN_3OUT_OPRETURN (two OP_RETURN outputs)
            (1, testdata::TX_1IN_3OUT_OPRETURN),
            (1, testdata::TX_1IN_6OUT_5OPRETURN),
        ];
        for c in testcases.iter() {
            let tx = decode_tx(c.1);
            assert_eq!(TxInfo::new(&tx).unwrap().payments(), c.0);
        }
    }

    #[test]
    fn test_transaction_sigops() {
        let tx_sigops_pairs = [
            (6usize, testdata::TX_SIGOPS_6),
            (29, testdata::TX_SIGOPS_29),
            (9, testdata::TX_SIGOPS_9),
            (86, testdata::TX_SIGOPS_86),
            (5, testdata::TX_SIGOPS_5),
            (8, testdata::TX_SIGOPS_8),
            (0, testdata::TX_SIGOPS_0_WITNESS_COINBASE),
            (0, testdata::TX_SIGOPS_0_COINBASE),
            (84, testdata::TX_P2SH_RSK),
        ];

        for (sigops, rawtx) in tx_sigops_pairs.iter() {
            let tx = decode_tx(rawtx);
            assert_eq!(*sigops, tx.sigops().unwrap());
            // TxInfo counts the sigops while it processes the inputs and
            // outputs. It must agree with the standalone counting above.
            assert_eq!(*sigops, TxInfo::new(&tx).unwrap().sigops());
        }
    }

    /// The sigops counted during TxInfo::new() (which reuses the already
    /// detected input and output types) must match the standalone sigops
    /// counting (which detects the types itself) for all test transactions.
    #[test]
    fn test_txinfo_sigops_matches_transaction_sigops() {
        for rawtx in testdata::ALL_TRANSACTIONS.iter() {
            let tx = decode_tx(rawtx);
            let tx_info = TxInfo::new(&tx).unwrap();
            assert_eq!(
                tx.sigops().unwrap(),
                tx_info.sigops(),
                "sigops mismatch for {}",
                tx_info.txid
            );
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
