//! Information about Bitcoin PubKeys, Signatures and MultiSig constructs.

use crate::input::{InputType, InputTypeDetection, ScriptHashInput};
use crate::output::{OutputType, OutputTypeDetection};
use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script;
use bitcoin::secp256k1::{ecdsa, schnorr};
//use bitcoin::secp256k1;
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
    fn is_schnorr_pubkey(&self) -> bool;
}

impl PublicKey for script::Instruction<'_> {
    fn is_ecdsa_pubkey(&self) -> bool {
        match self {
            script::Instruction::PushBytes(bytes) => bytes.as_bytes().is_ecdsa_pubkey(),
            script::Instruction::Op(_) => false,
        }
    }

    fn is_schnorr_pubkey(&self) -> bool {
        match self {
            script::Instruction::PushBytes(bytes) => bytes.as_bytes().is_schnorr_pubkey(),
            script::Instruction::Op(_) => false,
        }
    }
}

impl PublicKey for [u8] {
    fn is_ecdsa_pubkey(&self) -> bool {
        // ECDSA Public keys should either be 33 bytes or 65 bytes long
        if self.len() != bitcoin::key::constants::PUBLIC_KEY_SIZE
            && self.len() != bitcoin::key::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE
        {
            return false;
        }
        bitcoin::PublicKey::from_slice(self).is_ok()
    }

    fn is_schnorr_pubkey(&self) -> bool {
        // Schnorr public keys should be 32 byte long
        if self.len() != bitcoin::key::constants::SCHNORR_PUBLIC_KEY_SIZE {
            return false;
        }
        bitcoin::key::XOnlyPublicKey::from_slice(self).is_ok()
    }
}

impl PublicKey for Vec<u8> {
    fn is_ecdsa_pubkey(&self) -> bool {
        // ECDSA Public keys should either be 33 bytes or 65 bytes long
        if self.len() != bitcoin::key::constants::PUBLIC_KEY_SIZE
            && self.len() != bitcoin::key::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE
        {
            return false;
        }
        bitcoin::PublicKey::from_slice(self).is_ok()
    }

    fn is_schnorr_pubkey(&self) -> bool {
        // Schnorr public keys should be 32 byte long
        if self.len() != bitcoin::key::constants::SCHNORR_PUBLIC_KEY_SIZE {
            return false;
        }
        bitcoin::key::XOnlyPublicKey::from_slice(self).is_ok()
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

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum PubkeyType {
    ECDSA,
    Schnorr,
}

/// Information about a Pubkey
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PubKeyInfo {
    /// If the pubkey is compressed. Only ECDSA pubkey can be uncompressed.
    pub compressed: bool,
    pub pubkey_type: PubkeyType,
}

impl PubKeyInfo {
    pub fn from_instruction_ecdsa(instruction: &script::Instruction) -> Option<PubKeyInfo> {
        match instruction {
            script::Instruction::PushBytes(bytes) => {
                PubKeyInfo::from_u8_slice_ecdsa(bytes.as_bytes())
            }
            script::Instruction::Op(_) => None,
        }
    }

    pub fn from_u8_slice_ecdsa(bytes: &[u8]) -> Option<PubKeyInfo> {
        if bytes.is_ecdsa_pubkey() {
            return Some(PubKeyInfo {
                compressed: bytes.len() == bitcoin::key::constants::PUBLIC_KEY_SIZE,
                pubkey_type: PubkeyType::ECDSA,
            });
        }
        None
    }

    pub fn from_input(input: &bitcoin::TxIn) -> Result<Vec<PubKeyInfo>, script::Error> {
        let input_type = input.get_type()?;

        let mut pubkey_infos = vec![];

        match input_type {
            // a P2PK script_sig consists of a single signature. No public key.
            InputType::P2pk | InputType::P2pkLaxDer => (),
            // a P2MS script_sig contains up to three signatures after an
            // initial OP_FALSE. No public key.
            InputType::P2ms | InputType::P2msLaxDer => (),
            InputType::P2pkh | InputType::P2pkhLaxDer => {
                // P2PKH inputs have a signature as the first element and a public key as the second element of the script_sig.
                pubkey_infos.push(
                    PubKeyInfo::from_instruction_ecdsa(&instructions_as_vec(&input.script_sig)?[1])
                        .unwrap(),
                );
            }
            InputType::P2shP2wpkh => {
                // P2SH wrapped P2WPKH inputs contain the signature as the first and
                // the pubkey as the second element of the witness.
                pubkey_infos
                    .push(PubKeyInfo::from_u8_slice_ecdsa(&input.witness.to_vec()[1]).unwrap());
            }
            InputType::P2wpkh => {
                // P2WPKH inputs contain the signature as the first and
                // the pubkey as the second element of the witness.
                pubkey_infos
                    .push(PubKeyInfo::from_u8_slice_ecdsa(&input.witness.to_vec()[1]).unwrap())
            }
            InputType::P2sh => {
                // P2SH inputs usually contain public keys in the witness redeem script
                if let Some(redeem_script) = input.redeem_script().unwrap() {
                    let instructions = instructions_as_vec(&redeem_script)?;
                    for instruction in instructions.iter() {
                        if let Some(pubkey_info) = PubKeyInfo::from_instruction_ecdsa(instruction) {
                            pubkey_infos.push(pubkey_info);
                        }
                    }
                }
            }
            InputType::P2shP2wsh => {
                // P2SH wrapped P2WSH inputs usually contain public keys in the witness redeem script
                if let Some(redeem_script) = input.redeem_script().unwrap() {
                    let instructions = instructions_as_vec(&redeem_script)?;
                    for instruction in instructions.iter() {
                        if let Some(pubkey_info) = PubKeyInfo::from_instruction_ecdsa(instruction) {
                            pubkey_infos.push(pubkey_info);
                        }
                    }
                }
            }
            InputType::P2wsh => {
                // P2WSH inputs usually contain public keys in the witness redeem script
                if let Some(redeem_script) = input.redeem_script().unwrap() {
                    let instructions = instructions_as_vec(&redeem_script)?;
                    for instruction in instructions.iter() {
                        if let Some(pubkey_info) = PubKeyInfo::from_instruction_ecdsa(instruction) {
                            pubkey_infos.push(pubkey_info);
                        }
                    }
                }
            }
            // P2TR key-path spends do not contain a public key.
            InputType::P2trkp => (),
            // TODO: there could be multiple public keys in the script path spent
            // However, this is currently not implemented here.
            InputType::P2trsp => (),
            // exhaustive so the compiler warns us if we forget to add an input
            // type here.
            InputType::Unknown => (),
            InputType::Coinbase => (),
            InputType::CoinbaseWitness => (),
        }

        Ok(pubkey_infos)
    }

    pub fn from_output(output: &bitcoin::TxOut) -> Result<Vec<PubKeyInfo>, script::Error> {
        let output_type = output.get_type();

        let mut pubkey_infos = vec![];

        match output_type {
            OutputType::P2pk => {
                if let Some(pk_info) = PubKeyInfo::from_instruction_ecdsa(
                    &instructions_as_vec(&output.script_pubkey)?[0],
                ) {
                    pubkey_infos.push(pk_info);
                }
            }
            OutputType::P2ms => {
                // There can be up to three ECDSA public keys in P2MS outputs
                for instruction in instructions_as_vec(&output.script_pubkey)?.iter() {
                    if let Some(pk_info) = PubKeyInfo::from_instruction_ecdsa(instruction) {
                        pubkey_infos.push(pk_info);
                    }
                }
            }
            OutputType::P2tr => {
                pubkey_infos.push(PubKeyInfo {
                    compressed: true,
                    pubkey_type: PubkeyType::Schnorr,
                });
            }
            OutputType::P2pkh
            | OutputType::P2wpkhV0
            | OutputType::P2wshV0
            | OutputType::P2sh
            | OutputType::OpReturn(_)
            | OutputType::Unknown => (),
        }

        Ok(pubkey_infos)
    }
}

#[cfg(test)]
mod tests {
    use super::Multisig;
    use crate::script::{PubkeyType, PublicKey};
    use crate::{input::InputInfo, output::OutputInfo, script::PubKeyInfo};
    use bitcoin::{ScriptBuf, Transaction};

    #[test]
    fn test_input_pubkey_info() {
        struct TestCase {
            rawtx: Vec<u8>,
            pkinfos_input: Vec<Vec<PubKeyInfo>>,
            pkinfos_output: Vec<Vec<PubKeyInfo>>,
        }

        let testcases = vec![
            TestCase{
                // mainnet f779186cfea652ef661c21a83c90ad680402ea12d440e18f86e3e5f55355c497
                // inputs: P2PKH, P2TR; outputs: P2PKH, P2TR
                // The P2PKH input has an ECDSA pubkey and the P2TR output has a
                // Schnorr pubkey
                rawtx: hex::decode("02000000000102ad4d1f661a4251621d23aa52abc9d21f3dabfac7de2d771a831a7263ebc47e14000000006a473044022066fa04395f3d595a45a7687ab4e0260035a4796f7f6f974046ca6628a275b54902206a5183122336252cc4aa63e54030d4f3f5eb12965889f8f9929cc36ca11bab0601210201973a41bb610e199a1fbb208398fbacc732c3658d132dbf9f3a394bedc9a7b5ffffffff028b130336c335a1049fde9115470610f00ec6e7199c8f1aa32dfcc7087faa730100000000ffffffff0222020000000000001976a914234f39022fa4372c0e41f484a8f80644094fc75088acd442030000000000225120aed85526197b4cc9913aa2715b52001131a83eadbdadd2d6bdd0d303362539bc000140d30ee1b9be7f27630c93056b13faa5745e73e9642d8e3d41fa3f37cd715901eef9a00d5df17752d80c3c2388e1a1246aa398c91f347f0517f219e66548aa2b8500000000").unwrap(),
                pkinfos_input: vec![vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], vec![]],
                pkinfos_output: vec![vec![], vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::Schnorr }]],
            },

            TestCase{
                // mainnet 581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510
                // inputs: P2PKH; outputs: P2MS
                // The P2PKH input has one uncompressed pubkey and the P2MS
                // output has three uncompressed pubkeys.
                rawtx: hex::decode("01000000014563f26698c0ea3ebd85d4767457370d7e2ebbe922a7736dbf70e1d0f8a9aa9c000000008a473044022039294d5c8843a6776d4a2032cf03549f41c634ba5e65898c7816973919e485b902205af1f61f6d7d6a5f32cbe46676303c141fe499288b1be0d8f0c4e80d4c0ecb5701410454ffbc96ef3c26acffa431066915308865d990e044c507e0ab3d26af34a8ba5b4cb3028fe7c91926bb8be47d652dc70ab300e3022f8259db5f79306b601fc66effffffff0190c9190000000000c9524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae00000000").unwrap(),
                pkinfos_input: vec![vec![PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }]],
                pkinfos_output: vec![vec![PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }, PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }, PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }]],
            },

            TestCase{
                // mainnet 60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1
                // inputs: P2PKH, P2PKH, P2PKH; outputs: P2MS, P2PKH, P2PKH
                // The three P2PKH inputs have one uncompressed pubkey each and
                // the P2MS output has two uncompressed pubkeys while the P2PKH
                // outputs have none.
                rawtx: hex::decode("010000000337bd40a022eea1edd40a678cddabe200b131afd5797b232ac21861d8e97eb367020000008a4730440220e8343f8ac7e96582d92a450ce314668db4f7a0e2c94a97aa6df026f93ebee2290220866b5728d4247688d91b4a30144762bc8bfd7f385de7f7d326d665ff5e3e900301410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342afffffffff96420befb14a9357181e5da089824a3e6ea5a95856ff74c06c7d5ea98d633cf9020000008a4730440220b7227a8f816f3810f97057102edf8be4434c1e00f48b4440976bcc478f1431030220af3cba150afdd44618de4369cdc65fea73e447d7b5fbe135d2f08f86d82aa85f01410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342afffffffff96420befb14a9357181e5da089824a3e6ea5a95856ff74c06c7d5ea98d633cf9010000008a47304402207d689e1a61e06440eab18d961517a97c49219a91f2c59d9630e902fcb2f4ea8b0220dcd274349ca264d8bd2bee5135664a92899e94a319a349d6d6e3660d04b564ad0141047a4c5d104002ebc203bef5cab6f13ff57ab624bb5f9f1186beb64c83a396da0d912e11a18ea15a2c784a62fed2bbd8258c3413c18bf4c3f2ba28f3d5565e328bffffffff0340420f000000000087514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af52ae50cec402000000001976a914c812a297b8e0e778d7a22bb2cd6d23c3e789472b88ac20a10700000000001976a914641ad5051edd97029a003fe9efb29359fcee409d88ac00000000").unwrap(),
                pkinfos_input: vec![vec![PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }], vec![PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }], vec![PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }]],
                pkinfos_output: vec![vec![PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }, PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }], vec![], vec![]],
            },

            TestCase{
                // mainnet f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd
                // inputs: P2WPKH; outputs: P2WPKH, P2WPKH, OP_RETURN
                // The P2WPKH input has one compressed pubkey and the P2WPKH outputs
                // have none. OP_RETURN neither.
                rawtx: hex::decode("01000000000101ad2bb91208eef398def3ed3e784d9ee9b7befeb56a3053c3561849b88bc4cedf0000000000ffffffff037a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa0075060cff7a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa0075060cff0000000000000000256a2342697462616e6b20496e632e204a6170616e20737570706f727473205365675769742102483045022100a6e33a7aff720ba9f33a0a8346a16fdd022196862796d511d31978c40c9ad48b02206fb8f67bd699a8c952b3386a81d122c366d2d36cd08e2de21207e6aa6f96ce9501210283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f44800000000").unwrap(),
                pkinfos_input: vec![vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }]],
                pkinfos_output: vec![vec![], vec![], vec![]],
            },

            TestCase{
                // mainnet b10c0000004da5a9d1d9b4ae32e09f0b3e62d21a5cce5428d4ad714fb444eb5d
                // inputs: all of them; outputs: all of them
                rawtx: hex::decode("0100000000010a9b9653ae4536f14723f5e7fdd730af3e41536a0c57807de8d67b1d2c96246ad40000000048473044022004f027ae0b19bb7a7aa8fcdf135f1da769d087342020359ef4099a9f0f0ba4ec02206a83a9b78df3fed89a3b6052e69963e1fb08d8f6d17d945e43b51b5214aa41e601f78c3201e36747271635683f16a2c9574cd79fac51f34af08e3a63fb293b0204ac479bcb000000006946304302204dc2939be89ab6626457fff40aec2cc4e6213e64bcb4d2c43bf6b49358ff638c021f33d2f8fdf6d54a2c82bb7cddc62becc2cbbaca6fd7f3ec927ea975f29ad8510221028b98707adfd6f468d56c1a6067a6f0c7fef43afbacad45384017f8be93a18d4087693201e36747271635683f16a2c9574cd79fac51f34af08e3a63fb293b0204ac479bcb010000008300453042021e4f6ff73d7b304a5cbf3bb7738abb5f81a4af6335962134ce27a1cc45fec702201b95e3acb7db93257b20651cdcb79af66bf0bb86a8ae5b4e0a5df4e3f86787e2033b303802153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63021f34793e2878497561e7616291ebdda3024b681cdacc8b863b5b0804cd30c2a481685e2d01d6ca61cbfb1bab46294999b8f5650861d71bb701c8cc101807cb9a5933cbe14500000000fdaa0100443041021d1313459a48bd1d0628eec635495f793e970729684394f9b814d2b24012022050be6d9918444e283da0136884f8311ec465d0fed2f8d24b75a8485ebdc13aea013a303702153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63021e78644ba72eab69fefb5fe50700671bfb91dda699f72ffbb325edc6a3c4ef8239303602153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63021d2c2db104e70720c39af43b6ba3edd930c26e0818aa59ff9c886281d8ba834ced532103e0a220d36f6f7ed5f3f58c279d055707c454135baf18fd00d798fec3cb52dfbc2103cf689db9313b9f7fc0b984dd9cac750be76041b392919b06f6bf94813da34cd421027f8af2eb6e904deddaa60d5af393d430575eb35e4dfd942a8a5882734b078906410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a34104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c55ae10000000e36747271635683f16a2c9574cd79fac51f34af08e3a63fb293b0204ac479bcb02000000171600149b27f072e4b972927c445d1946162a550b0914d88d000000e36747271635683f16a2c9574cd79fac51f34af08e3a63fb293b0204ac479bcb0300000023220020a18160de7291554f349c7d5cbee4ab97fb542e94cf302ce8d7e9747e4188ca75efbeaddee36747271635683f16a2c9574cd79fac51f34af08e3a63fb293b0204ac479bcb0400000000406f400101d08b572974320b3d3650d672b1e53776ee38c72df9812bb2b18f8a92b37d630000000000d9b4bef9412c98a33b0d9ae72b87c117287b5722ffeb89d1ac5baeeb625012df02db2000000000000055010000b4061297f91ef316f4ed912e45f6d48f97d317d02d8d1c4bb131c4f9ec41577900000000005601000009400200000000000023210261542eb020b36c1da48e2e607b90a8c1f2ccdbd06eaf5fb4bb0d7cc34293d32aac22020000000000001976a9140240539af6c68431e4ce9cc5ef464f12c1741b3c88ac4602000000000000255121028b45a50f795be0413680036665d17a3eca099648ea80637bc3a70a7d2b52ae2851ae1c0200000000000017a91449ed2c96e33b6134408af8484508bcc3248c8dbd872601000000000000160014c8e51cf6891c0a2101aecea8cd5ce9bbbfaf7bba4a01000000000000220020c485bbb80c4be276e77eac3a983a391cc8b1a1b5f160995a36c3dff18296385a4a01000000000000225120a7a42b268957a06c9de4d7260f1df392ce4d6e7b743f5adc27415ce2afceb3b9f0000000000000000451024e730000000000000000356a224e6f7420796f757220696e707574732c206e6f7420796f7572206f7574707574732e005152535455565758595a5b5c5d5e5f600000000002433040021c23902a01d4c5cff2c33c8bdb778a5aadea78a9a0d6d4db60aaa0fba1022069237d9dbf2db8cff9c260ba71250493682d01a746f4a45c5c7ea386e56d2bc902210240187acd3e2fd3d8e1acffefa85907b6550730c24f78dfd3301c829fc4daf3cc0342303f021c65aee6696e80be6e14545cfd64b44f17b0514c150eefdb090c0f0bd9021f3fef4aa95c252a225622aba99e4d5af5a6fe40d177acd593e64cf2f8557ccc032103b55c6f0749e0f3e2caeca05f68e3699f1b3c62a550730f704985a6a9aae437a18576a914db865fd920959506111079995f1e4017b489bfe38763ac6721024d560f7f5d28aae5e1a8aa2b7ba615d7fc48e4ea27e5d27336e6a8f5fa0f5c8c7c820120876475527c2103443e8834fa7d79d7b5e95e0e9d0847f6b03ac3ea977979858b4104947fca87ca52ae67a91446c3747322b220fdb925c9802f0e949c1feab99988ac68680241303e021c11f60486afd0f5d6573603fb2076ef2f676455b92ada257d2f25558a021e317719c946f951d49bf4df4285a618629cd9e554fcbf787c319a0c4dd2260121032467f24cc31664f0cf34ff8d5cbb590888ddc1dcfec724a32ae3dd5338b8508e0340303d021c32f9454db85cb1a4ca63a9883d4347c5e13f3654e884ae44e9efa3c8021d62f07fe452c06b084bc3e09afd3aac4039136549a465533bc1ca6696790201014c632102fd6db4de50399b2aa086edb23f8e140bbc823d6651e024a0eb871288068789cd67012ab27521034134a2bb35c3f83dab2489d96160741888b8b5589bb694dea6e7bc24486e9c6f68ac0140d822f203827852998cad370232e8c57294540a5da51107fa26cf466bdd2b8b0b3d161999cc80aed8de7386a2bd5d5313aea159a231cc26fa53aaa702b7fa21ed0940fe6eb715dceffefc067fdc787d250a9a9116682d216f6356ea38fc1f112bd74995faa90315e81981d2c2260b7eaca3c41a16b280362980f0d8faf4c05ebb82c541e34ad0ad33885a473831f8ba8d9339123cb19d0e642e156d8e0d6e2ab2691aedb30e55a35637a806927225e1aa72223d41e59f92c6579b819e7d331a7ada9d2e01412a4861fb4cb951c791bf6c93859ef65abccd90034f91b9b77abb918e13b6fce75d5fa3e2d2f6eeeae105315178c2cb9db2ef238fe89b282f691c06db43bc71ca0241fc97bb2be673c3bf388aaf58178ef14d354caf83c92aca8ef1831d619b8511e928f4f5fdea3962067b11e7cecfe094cd0f66a4ea9af9ec836d70d18f2b37df028141a5781a0adaa80ab7f7f164172dd1a1cb127e523daa0d6949aba074a15c589f12dfb8183182afec9230cb7947b7422a4abc1bb78173550d66274ea19f6c9dd92c820000f0205f4237bd7dae576b34abc8a9c6fa4f0e4787c04234ca963e9e96c8f9b67b56d1ac205f4237bd7f93c69403a30c6b641f27ccf5201090152fcf1596474221307831c3ba205ac8ff25ce63564963d1148b84627f614af1f3c77d7caa23adc61264fa5e4996ba20b210c83e6f5b3f866837112d023d9ae8da2a6412168d54968ab87860ab970690ba20d3ee3b7a8b8149122b3c886330b3241538ba4b935c4040f4a73ddab917241bc5ba20cdfabb9d0e5c8f09a83f19e36e100d8f5e882f1b60aa60dacd9e6d072c117bc0ba20aab038c238e95fb54cdd0a6705dc1b1f8d135a9e9b20ab9c7ff96eef0e9bf545ba559cfdc102c0b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f5534a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33bf4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e166f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48dd5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb46829a3efd3ef04f9153d47a990bd7b048a4b2d213daaa5fb8ed670fb85f13bdbcf54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713d29c9c0e8e4d2a9790922af73f0b8d51f0bd4bb19940d9cf910ead8fbe85bc9bbb41a757f405890fb0f5856228e23b715702d714d59bf2b1feb70d8b2b4e3e089fdbcf0ef9d8d00f66e47917f67cc5d78aec1ac786e2abb8d2facb4e4790aad6cc455ae816e6cdafdb58d54e35d4f46d860047458eacf1c7405dc634631c570d8d31992805518fd62daa3bdd2a5c4fd2cd3054c9b3dca1d78055e9528cff6adc8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1cb10c007c60e14f9d087e0291d4d0c7869697c6681d979c6639dbd960792b4d4133e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac9879903637777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8fd456524104a6674693c29946543f8a0befccce5a352bda55ec8559fc630f5f37393096d97bfee8660f4100ffd61874d62f9a65de9fb6acf740c4c386990ef7373be398c4bdc43709db7398106609eea2a7841aaf3a4fa2000dc18184faa2a7eb5a2af5845a8d3796308ff9840e567b14cf6bb158ff26c999e6f9a1f5448f9aa29ab5f49").unwrap(),
                pkinfos_input: vec![
                    vec![], // P2PK
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2PKH
                    vec![], // P2MS
                    vec![   // 3-of-5 P2SH
                        PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }, PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA },PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }, PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }, PubKeyInfo { compressed: false, pubkey_type: PubkeyType::ECDSA }],
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2SH
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }, PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2WPKH
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2WPKH
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }, PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2WSH
                    vec![], // P2TR key-path
                    vec![]  // P2TR script-path TODO: this tx pushes pubkey-like data, but that's not implemented here...
                ],
                pkinfos_output: vec![
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2PK
                    vec![], // P2PKH
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2MS
                    vec![], // P2SH
                    vec![], // P2WPKH
                    vec![], // P2WSH
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::Schnorr }], // P2TR
                    vec![], // Unknown!
                    vec![], // OP_RETURN
                ],
            },

            TestCase{
                // signet 9becb93a15ab4b47eaca85c852d4309f82a28677a0a557df3c0fa6b82ef9293d
                // inputs: P2WPKH; outputs: 1-of-3 P2MS (2x uncompressed, not-on-curve 'pubkeys' and a compressed pk), P2PKH
                rawtx: hex::decode("01000000000101cd49818bb48793b0f5a2445517f64665805dd934d5bb5fe3f2443db18c3f63450000000000ffffffff02a00f000000000000a95141044a6572656d6961682032390d0a0d0a313120466f722049206b6e6f77207468652074686f756768747320746861742049207468696e6b20746f7761726420796f4104752c20736169746820746865204c6f72642c2074686f7567687473206f662070656163652c20616e64206e6f74206f66206576696c2c20746f206769766520792103c0e0bf0bbcdc53be9542359aeb1dde7c6289743b7b3460c12e2d57a478c6e48953aef7300f00000000001976a9148c51ed42f050b1bde974fb6649e25b782d168f4088ac0247304402206b41bae6dcec9129276d3df71e7d1f1f41097b338111a8932e034ca8747fdfaa0220447ab24f6d8f66fc0cc5a8a8c61928b63469bb28d6f51b7fc55f987509c57460012103c0e0bf0bbcdc53be9542359aeb1dde7c6289743b7b3460c12e2d57a478c6e48900000000").unwrap(),
                pkinfos_input: vec![
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2WPKH
                ],
                pkinfos_output: vec![
                    vec![PubKeyInfo { compressed: true, pubkey_type: PubkeyType::ECDSA }], // P2MS (the two uncompressed pubkeys aren't on the curve..)
                    vec![], // P2PKH
                ],
            },

        ];

        for testcase in testcases {
            let tx: Transaction = bitcoin::consensus::deserialize(&testcase.rawtx).unwrap();
            assert_eq!(testcase.pkinfos_input.len(), tx.input.len());
            for (input, expected) in tx.input.iter().zip(testcase.pkinfos_input) {
                let input_info = InputInfo::new(input).unwrap();
                println!("--  info: {:?}\n\n", input_info);
                assert_eq!(input_info.pubkey_stats, expected);
            }
            assert_eq!(testcase.pkinfos_output.len(), tx.output.len());
            for (output, expected) in tx.output.iter().zip(testcase.pkinfos_output) {
                let output_info = OutputInfo::new(output).unwrap();
                println!("--  info: {:?}\n\n", output_info);
                assert_eq!(output_info.pubkey_stats, expected);
            }
        }
    }

    #[test]
    fn test_is_ecdsa_pubkey() {
        struct Testcase {
            raw: Vec<u8>,
            expected: bool,
        }

        let testcases = vec![
            Testcase { // not on curve (PK in P2MS output of signet 9becb93a15ab4b47eaca85c852d4309f82a28677a0a557df3c0fa6b82ef9293d)
                raw: hex::decode("044a6572656d6961682032390d0a0d0a313120466f722049206b6e6f77207468652074686f756768747320746861742049207468696e6b20746f7761726420796f").unwrap(),
                expected: false,
            },
            Testcase { // not on curve (PK in P2MS output of signet 9becb93a15ab4b47eaca85c852d4309f82a28677a0a557df3c0fa6b82ef9293d)
                raw: hex::decode("04752c20736169746820746865204c6f72642c2074686f7567687473206f662070656163652c20616e64206e6f74206f66206576696c2c20746f20676976652079").unwrap(),
                expected: false,
            },
            Testcase { // (PK in P2MS output of signet 9becb93a15ab4b47eaca85c852d4309f82a28677a0a557df3c0fa6b82ef9293d)
                raw: hex::decode("03c0e0bf0bbcdc53be9542359aeb1dde7c6289743b7b3460c12e2d57a478c6e489").unwrap(),
                expected: true,
            },
            Testcase { // Hal Finney's pubkey from f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
                raw: hex::decode("04ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84c").unwrap(),
                expected: true,
            },
            Testcase { // Satoshis pubkey from f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
                raw: hex::decode("0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3").unwrap(),
                expected: true,
            },
        ];

        for testcase in testcases {
            assert_eq!(testcase.raw.is_pubkey(), testcase.expected);
        }
    }

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
        assert_eq!(p2ms_output_1of3.get_opcheckmultisig_n_m(), Ok(Some((1, 3))))
    }

    #[test]
    fn multisig_opcheckmultisig_1of3_2() {
        // from mainnet 6e45ba2e4f71497291170c40e7161fb47675ff0a7d6c67c1fda485832ed7c923 output 1
        let p2ms_output_1of3 = ScriptBuf::from_hex("5121027f86d68a007dc5c214c67f964350136c69fa5c783f70b9e7e13935b3f4a1c60e21032e6d71977d2685a41eecdfc260c2463903bef6cc83eaaa77555d90ea7ba09e7a2103030303030303030303030303030303030303030303030303030303030303030353ae").unwrap();
        assert_eq!(p2ms_output_1of3.get_opcheckmultisig_n_m(), Ok(Some((1, 3))))
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
