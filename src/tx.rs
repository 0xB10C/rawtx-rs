//! Information about Bitcoin transactions.

use crate::{input, output};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::blockdata::script as bitcoin_script;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Transaction, TxIn, TxOut};
use input::{InputInfo, ScriptHashInput};
use output::{OutputInfo, OutputTypeDetection};
use std::collections::HashMap;

#[cfg(feature = "counterparty")]
use crate::script::{instructions_as_vec, Multisig};
#[cfg(feature = "counterparty")]
use bitcoin::blockdata::script::Instruction;
#[cfg(feature = "counterparty")]
use rc4::{consts::U32, Key, KeyInit, Rc4, StreamCipher};

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
    is_coinbase: bool,
    is_bip69_compliant: bool,
}

impl TxInfo {
    /// Creates an new [TxInfo] from a [Transaction].
    /// Can return an [bitcoin::blockdata::script::Error] if script in the transaction can't be parsed.
    pub fn new(tx: &Transaction) -> Result<TxInfo, bitcoin_script::Error> {
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
            output_infos.push(OutputInfo::new(output));
        }

        Ok(TxInfo {
            txid: tx.txid(),
            version: tx.version,
            payments,
            vsize: tx.vsize() as u64,
            weight: tx.weight().to_wu() as u64,
            is_coinbase: tx.is_coin_base(),
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

    /// Returns true if all inputs spend either nested or native SegWit.
    pub fn is_only_spending_segwit(&self) -> bool {
        self.input_infos.iter().all(|i| i.is_spending_segwit())
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
            let max_count = *a.iter().map(|(_, size)| size).max().unwrap();
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

fn is_bip69_compliant(inputs: &[TxIn], outputs: &[TxOut]) -> bool {
    let inputs_sorted: bool;
    if inputs.len() == 1 {
        inputs_sorted = true;
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

        inputs_sorted = inputs.to_vec() == to_be_sorted_inputs;
    }

    let outputs_sorted: bool;
    if outputs.len() == 1 {
        outputs_sorted = true;
    } else {
        let mut to_be_sorted_outputs = outputs.to_vec();
        to_be_sorted_outputs.sort_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
        });
        outputs_sorted = outputs.to_vec() == to_be_sorted_outputs;
    }
    inputs_sorted && outputs_sorted
}

#[cfg(feature = "counterparty")]
/// Returns true if the transaction is an OP_RETURN CounterParty transaction.
pub fn is_opreturn_counterparty(tx: &Transaction) -> bool {
    if tx.is_coin_base() {
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
    if tx.is_coin_base() {
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
    if tx.is_coin_base() {
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
    use super::TxInfo;
    use bitcoin::Transaction;

    #[cfg(feature = "counterparty")]
    use crate::tx::is_opreturn_counterparty;
    #[cfg(feature = "counterparty")]
    use crate::tx::is_p2ms_counterparty;
    #[cfg(feature = "counterparty")]
    use crate::tx::is_p2sh_counterparty;

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
