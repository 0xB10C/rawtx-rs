//! Information about Bitcoin PubKeys, Signatures and MultiSig constructs.

use crate::input::{InputType, InputTypeDetection};
use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script;
use bitcoin::secp256k1::{ecdsa, schnorr};
use std::convert::TryInto;

const SECP256K1_HALF_CURVE_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];
const LOW_R_THRESHOLD: [u8; 32] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Helper function collecting the Instructions iterator into a
// `Vec<script::Instruction>` for easier handling.
pub fn instructions_as_vec(
    script: &bitcoin::Script,
) -> Result<Vec<script::Instruction>, script::Error> {
    script
        .instructions()
        .collect::<Result<Vec<script::Instruction>, script::Error>>()
}

pub trait PublicKey {
    fn is_pubkey(&self) -> bool {
        self.is_ecdsa_pubkey()
    }
    fn is_ecdsa_pubkey(&self) -> bool;
}

impl PublicKey for script::Instruction<'_> {
    fn is_ecdsa_pubkey(&self) -> bool {
        match self {
            script::Instruction::PushBytes(bytes) => bytes.as_bytes().is_ecdsa_pubkey(),
            script::Instruction::Op(_) => false,
        }
    }
}

impl PublicKey for [u8] {
    fn is_ecdsa_pubkey(&self) -> bool {
        // Public keys should either be 33 bytes or 65 bytes long
        if self.len() != 33 && self.len() != 65 {
            return false;
        }
        bitcoin::PublicKey::from_slice(self).is_ok()
    }
}

impl PublicKey for Vec<u8> {
    fn is_ecdsa_pubkey(&self) -> bool {
        // Public keys should either be 33 bytes or 65 bytes long
        if self.len() != 33 && self.len() != 65 {
            return false;
        }
        bitcoin::PublicKey::from_slice(self).is_ok()
    }
}

pub trait Signature {
    fn is_signature(&self) -> bool {
        self.is_ecdsa_signature(false) || self.is_schnorr_signature()
    }
    /// Checks if the underlying bytes represent a Bitcoin ECDSA signature.
    /// This function expects that the SigHash is included.
    fn is_ecdsa_signature(&self, strict_der: bool) -> bool;

    /// Checks if the underlying bytes represent a Bitcoin Schnoor signature.
    /// This function expects that the SigHash is included.
    fn is_schnorr_signature(&self) -> bool;
}

impl Signature for script::Instruction<'_> {
    fn is_ecdsa_signature(&self, strict_der: bool) -> bool {
        match self {
            script::Instruction::PushBytes(bytes) => {
                bytes.as_bytes().is_ecdsa_signature(strict_der)
            }
            script::Instruction::Op(_) => false,
        }
    }
    fn is_schnorr_signature(&self) -> bool {
        match self {
            script::Instruction::PushBytes(bytes) => bytes.as_bytes().is_schnorr_signature(),
            script::Instruction::Op(_) => false,
        }
    }
}

impl Signature for [u8] {
    fn is_ecdsa_signature(&self, strict_der: bool) -> bool {
        self.to_vec().is_ecdsa_signature(strict_der)
    }

    fn is_schnorr_signature(&self) -> bool {
        self.to_vec().is_schnorr_signature()
    }
}

impl Signature for Vec<u8> {
    fn is_ecdsa_signature(&self, strict_der: bool) -> bool {
        if self.len() < 9 || self.len() > 73 {
            false
        } else {
            let sighash_stripped = &self[..self.len() - 1];
            if strict_der {
                secp256k1::Signature::from_der(sighash_stripped).is_ok()
            } else {
                secp256k1::Signature::from_der_lax(sighash_stripped).is_ok()
            }
        }
    }

    fn is_schnorr_signature(&self) -> bool {
        if self.len() == 64 {
            // As long as we see excatly 64 bytes here, we assume it's a Schnoor signature.
            return true;
        } else if self.len() == 65 {
            let sighash = self.last().unwrap();
            return *sighash == 0x01u8
                || *sighash == 0x02u8
                || *sighash == 0x03u8
                || *sighash == 0x81u8
                || *sighash == 0x82u8
                || *sighash == 0x83u8;
        }
        false
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum SignatureType {
    Ecdsa(ecdsa::Signature),
    Schnorr(schnorr::Signature),
}

// Contains information about a Bitcoin signature.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct SignatureInfo {
    /// The actual signature wrapped in a type enum.
    pub signature: SignatureType,
    /// Inidcates if a ECDSA signature was strictly DER encoded before being decoded. A
    /// Schnorr signature was never DER encoded.
    pub was_der_encoded: bool,
    /// SigHash flag of the signature.
    pub sig_hash: u8,
    /// length of the encoded signatur.e
    pub length: usize,
}

impl SignatureInfo {
    pub fn low_s(&self) -> bool {
        let compact: [u8; 64];
        match self.signature {
            SignatureType::Ecdsa(s) => {
                compact = s.serialize_compact();
            }
            SignatureType::Schnorr(s) => {
                compact = *s.as_ref();
            }
        }
        let (_, s) = compact.split_at(32);
        let s: [u8; 32] = s
            .try_into()
            .expect("Splitting a 64 byte array in half should procude two 32 byte arrays.");

        return s <= SECP256K1_HALF_CURVE_ORDER;
    }

    pub fn low_r(&self) -> bool {
        let compact: [u8; 64];
        match self.signature {
            SignatureType::Ecdsa(s) => {
                compact = s.serialize_compact();
            }
            SignatureType::Schnorr(s) => {
                compact = *s.as_ref();
            }
        }
        let (r, _) = compact.split_at(32);
        let r: [u8; 32] = r
            .try_into()
            .expect("Splitting a 64 byte array in half should procude two 32 byte arrays.");

        return r < LOW_R_THRESHOLD;
    }

    /// Returns Some(SignatureInfo) if the Instruction is a Bitcoin ECDSA Signature,
    /// otherwise None is returned.
    pub fn from_instruction_ecdsa(instruction: &script::Instruction) -> Option<SignatureInfo> {
        if instruction.is_ecdsa_signature(false) {
            match instruction {
                script::Instruction::PushBytes(bytes) => {
                    return SignatureInfo::from_u8_slice_ecdsa(bytes.as_bytes());
                }
                script::Instruction::Op(_) => return None,
            }
        }
        None
    }

    /// Returns Some(SignatureInfo) if the Instruction is a Bitcoin Schnorr Signature,
    /// otherwise None is returned.
    pub fn from_instruction_schnorr(instruction: &script::Instruction) -> Option<SignatureInfo> {
        if instruction.is_schnorr_signature() {
            match instruction {
                script::Instruction::PushBytes(bytes) => {
                    return SignatureInfo::from_u8_slice_schnorr(bytes.as_bytes());
                }
                script::Instruction::Op(_) => return None,
            }
        }
        None
    }

    /// Returns Some(SignatureInfo) if the Instruction is a Bitcoin ECDSA Signature,
    /// otherwise None is returned.
    pub fn from_u8_slice_ecdsa(bytes: &[u8]) -> Option<SignatureInfo> {
        if bytes.len() < 9 || bytes.len() > 73 {
            return None;
        }

        let signature: ecdsa::Signature;
        let sighash_stripped = &bytes[..bytes.len() - 1];
        let mut lax_der_encoded = false;
        if let Ok(sig) = ecdsa::Signature::from_der(sighash_stripped) {
            signature = sig;
        } else if let Ok(sig) = ecdsa::Signature::from_der_lax(sighash_stripped) {
            signature = sig;
            lax_der_encoded = true;
        } else {
            return None;
        }

        return Some(SignatureInfo {
            signature: SignatureType::Ecdsa(signature),
            sig_hash: *bytes.last().unwrap(),
            length: bytes.len(),
            was_der_encoded: !lax_der_encoded,
        });
    }

    /// Returns Some(SignatureInfo) if the Instruction is a Bitcoin Schnorr Signature,
    /// otherwise None is returned.
    pub fn from_u8_slice_schnorr(bytes: &[u8]) -> Option<SignatureInfo> {
        if bytes.to_vec().is_schnorr_signature() {
            let sighash: u8;
            let signature: schnorr::Signature;
            if bytes.len() == 64 {
                sighash = 0x01u8;
                signature = match schnorr::Signature::from_slice(bytes) {
                    Ok(sig) => sig,
                    Err(_) => return None,
                }
            } else {
                sighash = *bytes.last().unwrap();
                signature = match schnorr::Signature::from_slice(&bytes[..bytes.len() - 1]) {
                    Ok(sig) => sig,
                    Err(_) => return None,
                }
            }

            return Some(SignatureInfo {
                signature: SignatureType::Schnorr(signature),
                sig_hash: sighash,
                length: bytes.len(),
                was_der_encoded: false, // awlways false for Schnorr
            });
        }
        None
    }

    /// Constructs a vector of SignatureInfo for all Signatures in the input. If
    /// the inputs script_sig and witness don't contain any signatures, an empty
    /// vector is returned.
    pub fn all_from(input: &bitcoin::TxIn) -> Result<Vec<SignatureInfo>, script::Error> {
        let input_type = input.get_type()?;

        let mut signature_infos = vec![];

        match input_type {
            InputType::P2pk | InputType::P2pkLaxDer => {
                // a P2PK script_sig consists of a single signature. This means
                // the first byte is a PUSH_BYTES_XX followed by the bytes of the
                // signature.
                signature_infos.push(
                    SignatureInfo::from_u8_slice_ecdsa(
                        &input.script_sig.as_script().as_bytes()[1..],
                    )
                    .unwrap(),
                );
            }
            InputType::P2ms | InputType::P2msLaxDer => {
                // a P2MS script_sig contains up to three signatures after an
                // initial OP_FALSE.
                for instruction in instructions_as_vec(&input.script_sig)?[1..].iter() {
                    signature_infos
                        .push(SignatureInfo::from_instruction_ecdsa(instruction).unwrap());
                }
            }
            InputType::P2pkh | InputType::P2pkhLaxDer => {
                // P2PKH inputs have a signature as the first element of the
                // script_sig.
                signature_infos.push(
                    SignatureInfo::from_instruction_ecdsa(
                        &instructions_as_vec(&input.script_sig)?[0],
                    )
                    .unwrap(),
                );
            }
            InputType::P2shP2wpkh => {
                // P2SH wrapped P2WPKH inputs contain the signature as the
                // first element of the witness.
                signature_infos
                    .push(SignatureInfo::from_u8_slice_ecdsa(&input.witness.to_vec()[0]).unwrap());
            }
            InputType::P2wpkh => {
                // P2WPKH inputs contain the signature as the first element of
                // the witness.
                signature_infos
                    .push(SignatureInfo::from_u8_slice_ecdsa(&input.witness.to_vec()[0]).unwrap())
            }
            InputType::P2sh => {
                // P2SH inputs can contain zero or multiple signatures in
                // the script sig. It's very uncommon that signatures are placed
                // in the redeem script.
                let instructions = instructions_as_vec(&input.script_sig)?;
                for instruction in instructions[..instructions.len() - 1].iter() {
                    if let Some(signature_info) = SignatureInfo::from_instruction_ecdsa(instruction)
                    {
                        signature_infos.push(signature_info);
                    }
                }
            }
            InputType::P2shP2wsh => {
                // P2SH wrapped P2WSH inputs can contain zero or multiple signatures in
                // the witness. It's very uncommon that signatures are placed
                // in the witness (redeem) script.
                for bytes in input.witness.to_vec()[..input.witness.len() - 1].iter() {
                    if let Some(signature_info) = SignatureInfo::from_u8_slice_ecdsa(bytes) {
                        signature_infos.push(signature_info);
                    }
                }
            }
            InputType::P2wsh => {
                // P2WSH inputs can contain zero or multiple signatures in
                // the witness. It's very uncommon that signatures are placed
                // in the witness (redeem) script.
                for bytes in input.witness.to_vec()[..input.witness.len() - 1].iter() {
                    if let Some(signature_info) = SignatureInfo::from_u8_slice_ecdsa(bytes) {
                        signature_infos.push(signature_info);
                    }
                }
            }
            InputType::P2trkp => {
                // P2TR key-path spends contain exactly one Schnorr signature in the
                // witness.
                signature_infos
                    .push(SignatureInfo::from_u8_slice_schnorr(&input.witness.to_vec()[0]).unwrap())
            }
            InputType::P2trsp => {
                // P2TR script-path spends contain zero or multiple signatures in the witness.
                // There can't be any signatures in the annex, control block or script part.
                // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
                for bytes in input.witness.to_vec()[..input.witness.len() - 2].iter() {
                    if let Some(signature_info) = SignatureInfo::from_u8_slice_schnorr(bytes) {
                        signature_infos.push(signature_info);
                    }
                }
            }
            // exhaustive so the compiler warns us if we forget to add an input
            // type here.
            InputType::Unknown => (),
            InputType::Coinbase => (),
            InputType::CoinbaseWitness => (),
        }

        Ok(signature_infos)
    }
}

pub trait Multisig {
    fn is_opcheckmultisig(&self) -> bool;
    fn get_opcheckmultisig_n_m(&self) -> Result<Option<(u8, u8)>, script::Error>;
}

impl Multisig for bitcoin::Script {
    /// Tests if the script is OP_CHECKMULTISIG conform.
    /// Expected: <OP_PUSHNUM_N>   M * <pubkey>   <OP_PUSHNUM_M> <OP_CHECKMULTISIG>
    fn is_opcheckmultisig(&self) -> bool {
        if let Ok(res_option) = self.get_opcheckmultisig_n_m() {
            if res_option.is_some() {
                return true;
            }
        }
        false
    }

    /// Returns a tuple of `(n, m)` (`n-of-m`) of the OP_CHECKMULTISIG script.
    /// If the script is not a OP_CHECKMULTISIG script `Ok(None)` is returned.
    /// n: number of signatures required
    /// m: number of possible public keys
    fn get_opcheckmultisig_n_m(&self) -> Result<Option<(u8, u8)>, script::Error> {
        let script_bytes = self.to_bytes();

        if script_bytes.is_empty() {
            return Ok(None);
        }

        if let Some(last_byte) = script_bytes.last() {
            if *(last_byte) != opcodes::OP_CHECKMULTISIG.to_u8() {
                return Ok(None);
            }
        }

        // <OP_PUSHNUM_N>   M * <pubkey>   <OP_PUSHNUM_M> <OP_CHECKMULTISIG>
        let instructions = instructions_as_vec(self)?;

        if instructions.len() < 4 {
            return Ok(None);
        }

        let n: u8; // number of signatures required
        let m: u8; // number of possible public keys

        if let script::Instruction::Op(op) = instructions[0] {
            if op.to_u8() >= opcodes::OP_PUSHNUM_1.to_u8()
                && op.to_u8() <= opcodes::OP_PUSHNUM_16.to_u8()
            {
                n = (op.to_u8() - opcodes::OP_PUSHNUM_1.to_u8()) + 1;
            } else {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        if let script::Instruction::Op(op) = instructions[instructions.len() - 2] {
            if op.to_u8() >= opcodes::OP_PUSHNUM_1.to_u8()
                && op.to_u8() <= opcodes::OP_PUSHNUM_16.to_u8()
            {
                m = (op.to_u8() - opcodes::OP_PUSHNUM_1.to_u8()) + 1;
            } else {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        // check that there is space for exactly M public keys between
        // OP_PUSHNUM_N and OP_PUSHNUM_M.
        if instructions.len() - 2 - 1 != m as usize {
            return Ok(None);
        }

        
        // Normally, the instructions between OP_PUSHNUM_N and OP_PUSHNUM_M should be public keys.
        // However, these data pushes are sometimes used to store arbitraity data in P2MS output.
        // They are still multisig n-of-m's.
        if !instructions[1..instructions.len() - 2]
            .iter()
            .any(|inst| inst.push_bytes().is_some())
        {
            return Ok(None);
        }

        // If n is larger than m, the output is not considered a multisig here.
        // This happens, for example, in the the following testnet transaction:
        // 157c8495334e86b9422e656aa2c1a2fe977ed91fd27e2db71f6f64576f0456d9
        if n > m {
            return Ok(None);
        }

        Ok(Some((n, m)))
    }
}

#[cfg(test)]
mod tests {
    use super::Multisig;
    use bitcoin::ScriptBuf;

    #[test]
    fn multisig_opcheckmultisig_2of2() {
        // from mainnet f72d52eaae494da7c438a8456a9b20d2791fdf2b1c818825458f8f707d7b8011 input 0
        let redeem_script_ms_2of2 = ScriptBuf::from_hex("522103a2ea7e0b94c48fd799bf123c1f19b50fb6d15da310db8223fd7a6afd8b03e6932102eba627e6ea5bb7e0f4c981596872d0a97d800fb836b5b3a585c3f2b99c77a0e552ae").unwrap();
        assert_eq!(
            redeem_script_ms_2of2.get_opcheckmultisig_n_m(),
            Ok(Some((2, 2)))
        )
    }
    
    #[test]
    fn multisig_opcheckmultisig_1of3() {
        // from mainnet d5a02fd4d7e3cf5ca02d2a4c02c8124ba00907eb85801dddfe984428714e3946 output 0
        let p2ms_output_1of3 = ScriptBuf::from_hex("512102d7f69a1fc373a72468ae84634d9949fdeab4d1c903c6f23a3465f79c889342a421028836687b0c942c94801ce11b2601cbb1e900e6544ef28369e69977195794d47b2102dc6546ba58b9bc26365357a428516d48c9bbc230dd6fc72912654aaad460ef1953ae").unwrap();
        assert_eq!(
            p2ms_output_1of3.get_opcheckmultisig_n_m(),
            Ok(Some((1, 3)))
        )
    }
    
    #[test]
    fn multisig_opcheckmultisig_1of3_2() {
        // from mainnet 6e45ba2e4f71497291170c40e7161fb47675ff0a7d6c67c1fda485832ed7c923 output 1
        let p2ms_output_1of3 = ScriptBuf::from_hex("5121027f86d68a007dc5c214c67f964350136c69fa5c783f70b9e7e13935b3f4a1c60e21032e6d71977d2685a41eecdfc260c2463903bef6cc83eaaa77555d90ea7ba09e7a2103030303030303030303030303030303030303030303030303030303030303030353ae").unwrap();
        assert_eq!(
            p2ms_output_1of3.get_opcheckmultisig_n_m(),
            Ok(Some((1, 3)))
        )
    }

    #[test]
    fn multisig_opcheckmultisig_4of5() {
        // from mainnet 391f812dcce57d1b60669dfdc538d34fe25eec27134122d1fec8cd3208cb3ad4 input 0
        let redeem_script_ms_2of2 = ScriptBuf::from_hex("542102916d4144e950066e729b6142e6b0e24edeed8203303113c71bdf0fc8e1daad1e210236a7c19695857bacd26921ba932a287bfdc622498296166cd6ff5488525abf782103db287a99a4d208dd912e366494b1828c0046fd76cb2277f4a3abf4b43d9d6f6921034597594080142f4492f5f39a01c2ee203e1d9efedfebbccf77d0d5c6f54b92202102003af4953da0b10f848ce81c9564ff7cbe289fc9beda4e70d66176c12ec622e255ae").unwrap();
        assert_eq!(
            redeem_script_ms_2of2.get_opcheckmultisig_n_m(),
            Ok(Some((4, 5)))
        )
    }

    #[test]
    fn multisig_opcheckmultisig_non_multiscript_sig() {
        let redeem_script_non_multisig = ScriptBuf::from_hex("6382012088a820697ce4e1d91cdc96d53d1bc591367bd48855a076301972842aa5ffcb8fcb8b618876a9142c3a8a495c16839d5d975c1ca0ee504af825b52188ac6704c9191960b17576a9145a59f40f4ecb1f86efb13752b600ea3b8d4c633988ac68").unwrap();
        assert_eq!(
            redeem_script_non_multisig.get_opcheckmultisig_n_m(),
            Ok(None)
        )
    }

    #[test]
    fn multisig_opcheckmultisig_broken_2of3() {
        // A 2-of-2 script modified to have n = 2 and m = 3, but only 2 PubKeys
        let redeem_script_non_multisig = ScriptBuf::from_hex("522103a2ea7e0b94c48fd799bf123c1f19b50fb6d15da310db8223fd7a6afd8b03e6932102eba627e6ea5bb7e0f4c981596872d0a97d800fb836b5b3a585c3f2b99c77a0e553ae").unwrap();
        assert_eq!(
            redeem_script_non_multisig.get_opcheckmultisig_n_m(),
            Ok(None)
        )
    }

    #[test]
    fn multisig_opcheckmultisig_broken_2of1() {
        // A 2-of-1 script e.g. found twice in the testnet transaction 157c8495334e86b9422e656aa2c1a2fe977ed91fd27e2db71f6f64576f0456d9
        let redeem_script_non_multisig = ScriptBuf::from_hex(
            "5221021f5e6d618cf1beb74c79f42b0aae796094b3112bbe003209a2c1f757f1215bfd51ae",
        )
        .unwrap();
        assert_eq!(
            redeem_script_non_multisig.get_opcheckmultisig_n_m(),
            Ok(None)
        )
    }

    #[test]
    fn multisig_opcheckmultisig_invalid_script() {
        let redeem_script_non_multisig = ScriptBuf::from_hex("b10cabcdae").unwrap();
        assert!(redeem_script_non_multisig
            .get_opcheckmultisig_n_m()
            .is_err())
    }

    pub struct SignatureInfoTestcase {
        pub sig: String,
        pub length: usize,
        pub sighash: u8,
        pub low_r: bool,
        pub low_s: bool,
        pub der_encoded: bool,
    }

    #[test]
    fn schnorr_signature_info_test() {
        use super::Signature;
        use super::SignatureInfo;

        let testcases = vec![
            // #0 from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
            SignatureInfoTestcase {
                sig: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0".to_string(),
                length: 64,
                sighash: 0x01,
                low_s: true,
                low_r: false,
                der_encoded: false,
            },
            // #0 from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv with explicit sighash flag
            SignatureInfoTestcase {
                sig: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C001".to_string(),
                length: 65,
                sighash: 0x01,
                low_s: true,
                low_r: false,
                der_encoded: false,
            },
            // #0 from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv with non-default sighash flag
            SignatureInfoTestcase {
                sig: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C002".to_string(),
                length: 65,
                sighash: 0x02,
                low_s: true,
                low_r: false,
                der_encoded: false,
            },
            // just above r-threshold (not-low r) & half curve order (-> low s)
            SignatureInfoTestcase {
                sig: "80000000AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA67fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0".to_string(),
                length: 64,
                sighash: 0x01,
                low_s: true,
                low_r: false,
                der_encoded: false,
            },
            // just below r-threshold (low r) & half curve order + 1(-> not-low s)
            SignatureInfoTestcase {
                sig: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1".to_string(),
                length: 64,
                sighash: 0x01,
                low_s: false,
                low_r: true,
                der_encoded: false,
            },
        ];

        for testcase in testcases.iter() {
            let s = ScriptBuf::from_hex(&testcase.sig).unwrap().into_bytes();
            assert!(s.is_schnorr_signature());
            assert!(!s.is_ecdsa_signature(false));
            let si = SignatureInfo::from_u8_slice_schnorr(&s).unwrap();

            println!("test signature: {}", testcase.sig);
            assert_eq!(si.was_der_encoded, false); // always false for schnorr
            assert_eq!(si.length, testcase.length, "");
            assert_eq!(si.sig_hash, testcase.sighash, "sighash flag");
            assert_eq!(si.low_s(), testcase.low_s, "low s?");
            assert_eq!(si.low_r(), testcase.low_r, "low r?");
        }
    }

    #[test]
    fn ecdsa_signature_info_test() {
        use super::Signature;
        use super::SignatureInfo;

        let testcases = vec![
            // BIP 66 example 1 (DER encoded)
            SignatureInfoTestcase {
                sig: "30440220d7a0417c3f6d1a15094d1cf2a3378ca0503eb8a57630953a9e2987e21ddd0a6502207a6266d686c99090920249991d3d42065b6d43eb70187b219c0db82e4f94d1a201".to_string(),
                length: 71,
                sighash: 0x01,
                low_s: true,
                low_r: true,
                der_encoded: true,
            },
            SignatureInfoTestcase {
                sig: "30440220cad9530d55219cf16ed352385961288fb50f162f791dce23aafef91ede284fe60220a890a5608f42a2ece4c9e6d078f94ba7f93ff9f978ae4373abe97f1bd6c6af3201".to_string(),
                length: 71,
                sighash: 0x01,
                low_s: true,
                low_r: true,
                der_encoded: true,
            },
            // Input 0 of 39baeb3b2579dac22cec858be3a4d70d8d229206127b43fa4133ed63fb7b1b40
            SignatureInfoTestcase {
                sig: "304502200064ddabf1af28c21103cf61cf19dbef814aff2eba0440c5e5e20a605d16d780022100f45c4bc6a4ab317dc3a600129fc6a87a0df6329dbc71c5fcca9effdb30f1857901".to_string(),
                length: 72,
                sighash: 0x01,
                low_s: false,
                low_r: true,
                der_encoded: false,
            },
            // Input 0 of f4597ab5b6d45ba3a04486f3edf1a27f9f2cc3ab23300eb16d6b7067b8cf47dd
            SignatureInfoTestcase {
                sig: "3046022100eb232172f28bc933f8bd0b5c40c83f98d01792ed45c4832a887d4e95bff3322a022100f4d7ee1d3b8f71995f197ffcdd4e5b2327a735c5edca12724502051f33cb18c081".to_string(),
                length: 73,
                sighash: 0x81,
                low_s: false,
                low_r: false,
                der_encoded: true,
            },
        ];

        for testcase in testcases.iter() {
            println!("test signature: {}", testcase.sig);
            let s = ScriptBuf::from_hex(&testcase.sig).unwrap().into_bytes();
            assert!(s.is_ecdsa_signature(false));
            assert!(!s.is_schnorr_signature());
            let si = SignatureInfo::from_u8_slice_ecdsa(&s).unwrap();

            assert_eq!(si.was_der_encoded, testcase.der_encoded, "der encoded?");
            assert_eq!(si.length, testcase.length, "length");
            assert_eq!(si.sig_hash, testcase.sighash, "sighash flag");
            assert_eq!(si.low_s(), testcase.low_s, "low s?");
            assert_eq!(si.low_r(), testcase.low_r, "low r?");
        }
    }
}
