//! Information about Bitcoin transactions.

use crate::{input, output, timelock};
use bitcoin::blockdata::script as bitcoin_script;
use bitcoin::hash_types::Txid;
use bitcoin::{Amount, Transaction, TxIn, TxOut};
use input::InputInfo;
use output::OutputInfo;
use std::collections::HashMap;
use timelock::LocktimeInfo;

#[derive(Debug)]
pub struct TxInfo {
    pub txid: Txid,
    pub version: i32,
    /// Number of outputs minus one change output if there is more than one output.
    pub payments: u32,
    pub vsize: u64,
    pub weight: u64,
    /// Information about the transactions time-lock.
    pub locktime: LocktimeInfo,
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
            vsize: (tx.get_weight() as f64 / 4f64).ceil() as u64,
            weight: tx.get_weight() as u64,
            is_coinbase: tx.is_coin_base(),
            is_bip69_compliant: is_bip69_compliant(&tx.input, &tx.output),
            locktime: LocktimeInfo::new(tx),
            input_infos,
            output_infos,
        })
    }

    /// Returns true if the transaction signals explicit RBF replicability by
    /// having all sequences of the inputs set to a value lower than 0xFFFF_FFFE.
    pub fn is_signaling_explicit_rbf_replicability(&self) -> bool {
        self.input_infos.iter().all(|i| i.sequence < 0xFFFF_FFFE)
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
            let mut a_outpoint_txid_reversed = a.previous_output.txid.to_vec();
            a_outpoint_txid_reversed.reverse();
            let mut b_outpoint_txid_reversed = b.previous_output.txid.to_vec();
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

#[cfg(test)]
mod tests {
    use super::TxInfo;
    use bitcoin::Transaction;

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
}
