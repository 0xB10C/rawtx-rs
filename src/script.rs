//! Information about Bitcoin PubKeys, Signatures and MultiSig constructs.

use crate::input::{InputType, InputTypeDetection};
use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script;

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
            script::Instruction::PushBytes(bytes) => bytes.to_vec().is_ecdsa_pubkey(),
            script::Instruction::Op(_) => false,
        }
    }
}

impl PublicKey for Vec<u8> {
    fn is_ecdsa_pubkey(&self) -> bool {
        // Public keys should either be 33 bytes or 65 bytes long
        if self.len() != 33 && self.len() != 65 {
            return false;
        }
        bitcoin::util::key::PublicKey::from_slice(self).is_ok()
    }
}

pub trait Signature {
    fn is_signature(&self) -> bool {
        self.is_ecdsa_signature(false)
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
            script::Instruction::PushBytes(bytes) => bytes.to_vec().is_ecdsa_signature(strict_der),
            script::Instruction::Op(_) => false,
        }
    }
    fn is_schnorr_signature(&self) -> bool {
        match self {
            script::Instruction::PushBytes(bytes) => bytes.to_vec().is_schnorr_signature(),
            script::Instruction::Op(_) => false,
        }
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
    Ecdsa,
    Schnorr,
}

// Contains information about a Bitcoin signature.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct SignatureInfo {
    pub sig_type: SignatureType,
    pub sig_hash: u8,
    pub length: usize,
}

impl SignatureInfo {
    // Returns Some(SignatureInfo) if the Instruction is a Bitcoin ECDSA Signature,
    // otherwise None is returned.
    pub fn from_instruction_ecdsa(
        instruction: &script::Instruction,
        strict_der: bool,
    ) -> Option<SignatureInfo> {
        if instruction.is_ecdsa_signature(strict_der) {
            match instruction {
                script::Instruction::PushBytes(bytes) => {
                    return SignatureInfo::from_u8_slice_ecdsa(bytes, strict_der);
                }
                script::Instruction::Op(_) => return None,
            }
        }
        None
    }

    // Returns Some(SignatureInfo) if the Instruction is a Bitcoin Schnorr Signature,
    // otherwise None is returned.
    pub fn from_instruction_schnorr(instruction: &script::Instruction) -> Option<SignatureInfo> {
        if instruction.is_schnorr_signature() {
            match instruction {
                script::Instruction::PushBytes(bytes) => {
                    return SignatureInfo::from_u8_slice_schnorr(bytes);
                }
                script::Instruction::Op(_) => return None,
            }
        }
        None
    }

    // Returns Some(SignatureInfo) if the Instruction is a Bitcoin ECDSA Signature,
    // otherwise None is returned.
    pub fn from_u8_slice_ecdsa(bytes: &[u8], strict_der: bool) -> Option<SignatureInfo> {
        if bytes.to_vec().is_ecdsa_signature(strict_der) {
            return Some(SignatureInfo {
                sig_type: SignatureType::Ecdsa,
                sig_hash: *bytes.last().unwrap(),
                length: bytes.len(),
            });
        }
        None
    }

    // Returns Some(SignatureInfo) if the Instruction is a Bitcoin ECDSA Signature,
    // otherwise None is returned.
    pub fn from_u8_slice_schnorr(bytes: &[u8]) -> Option<SignatureInfo> {
        if bytes.to_vec().is_schnorr_signature() {
            let sighash: u8;
            if bytes.len() == 64 {
                sighash = 0x01u8;
            } else {
                sighash = *bytes.last().unwrap();
            }
            return Some(SignatureInfo {
                sig_type: SignatureType::Schnorr,
                sig_hash: sighash,
                length: bytes.len(),
            });
        }
        None
    }

    // Constructs a vector of SignatureInfo for all Signatures in the input. If
    // the inputs script_sig and witness don't contain any signatures, an empty
    // vector is returned.
    pub fn all_from(
        input: &bitcoin::TxIn,
        strict_der: bool,
    ) -> Result<Vec<SignatureInfo>, script::Error> {
        let input_type = input.get_type()?;

        let mut signature_infos = vec![];

        match input_type {
            InputType::P2pk | InputType::P2pkLaxDer => {
                // a P2PK script_sig consists of a single signature. This means
                // the first byte is a PUSH_BYTES_XX followed by the bytes of the
                // signature.
                signature_infos.push(
                    SignatureInfo::from_u8_slice_ecdsa(&input.script_sig[1..], strict_der).unwrap(),
                );
            }
            InputType::P2ms | InputType::P2msLaxDer => {
                // a P2MS script_sig contains up to three signatures after an
                // initial OP_FALSE.
                for instruction in instructions_as_vec(&input.script_sig)?[1..].iter() {
                    signature_infos.push(
                        SignatureInfo::from_instruction_ecdsa(instruction, strict_der).unwrap(),
                    );
                }
            }
            InputType::P2pkh | InputType::P2pkhLaxDer => {
                // P2PKH inputs have a signature as the first element of the
                // script_sig.
                signature_infos.push(
                    SignatureInfo::from_instruction_ecdsa(
                        &instructions_as_vec(&input.script_sig)?[0],
                        strict_der,
                    )
                    .unwrap(),
                );
            }
            InputType::P2shP2wpkh => {
                // P2SH wrapped P2WPKH inputs contain the signature as the
                // first element of the witness.
                signature_infos.push(
                    SignatureInfo::from_u8_slice_ecdsa(&input.witness[0], strict_der).unwrap(),
                );
            }
            InputType::P2wpkh => {
                // P2WPKH inputs contain the signature as the first element of
                // the witness.
                signature_infos.push(
                    SignatureInfo::from_u8_slice_ecdsa(&input.witness[0], strict_der).unwrap(),
                )
            }
            InputType::P2sh => {
                // P2SH inputs can contain zero or multiple signatures in
                // the script sig. It's very uncommon that signatures are placed
                // in the redeem script.
                let instructions = instructions_as_vec(&input.script_sig)?;
                for instruction in instructions[..instructions.len() - 1].iter() {
                    if let Some(signature_info) =
                        SignatureInfo::from_instruction_ecdsa(instruction, strict_der)
                    {
                        signature_infos.push(signature_info);
                    }
                }
            }
            InputType::P2shP2wsh => {
                // P2SH wrapped P2WSH inputs can contain zero or multiple signatures in
                // the witness. It's very uncommon that signatures are placed
                // in the witness (redeem) script.
                for bytes in input.witness[..input.witness.len() - 1].iter() {
                    if let Some(signature_info) =
                        SignatureInfo::from_u8_slice_ecdsa(bytes, strict_der)
                    {
                        signature_infos.push(signature_info);
                    }
                }
            }
            InputType::P2wsh => {
                // P2WSH inputs can contain zero or multiple signatures in
                // the witness. It's very uncommon that signatures are placed
                // in the witness (redeem) script.
                for bytes in input.witness[..input.witness.len() - 1].iter() {
                    if let Some(signature_info) =
                        SignatureInfo::from_u8_slice_ecdsa(bytes, strict_der)
                    {
                        signature_infos.push(signature_info);
                    }
                }
            }
            InputType::P2trkp => {
                // P2TR key-path spends contain exactly one Schnorr signature in the
                // witness.
                signature_infos
                    .push(SignatureInfo::from_u8_slice_schnorr(&input.witness[0]).unwrap())
            }
            InputType::P2trsp => {
                // P2TR script-path spends contain zero or multiple signatures in the witness.
                // There can't be any signatures in the annex, control block or script part.
                // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules
                for bytes in input.witness[..input.witness.len() - 2].iter() {
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
            if *(last_byte) != opcodes::OP_CHECKMULTISIG.into_u8() {
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
            if op.into_u8() >= opcodes::OP_PUSHNUM_1.into_u8()
                && op.into_u8() <= opcodes::OP_PUSHNUM_16.into_u8()
            {
                n = (op.into_u8() - opcodes::OP_PUSHNUM_1.into_u8()) + 1;
            } else {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        if let script::Instruction::Op(op) = instructions[instructions.len() - 2] {
            if op.into_u8() >= opcodes::OP_PUSHNUM_1.into_u8()
                && op.into_u8() <= opcodes::OP_PUSHNUM_16.into_u8()
            {
                m = (op.into_u8() - opcodes::OP_PUSHNUM_1.into_u8()) + 1;
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

        // check that the instructions between OP_PUSHNUM_N and OP_PUSHNUM_M are
        // public keys
        if !instructions[1..instructions.len() - 2]
            .iter()
            .all(|inst| inst.is_ecdsa_pubkey())
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
    use bitcoin::Script;

    #[test]
    fn multisig_opcheckmultisig_2of2() {
        // from mainnet f72d52eaae494da7c438a8456a9b20d2791fdf2b1c818825458f8f707d7b8011 input 0
        let redeem_script_ms_2of2 = Script::from(hex::decode("522103a2ea7e0b94c48fd799bf123c1f19b50fb6d15da310db8223fd7a6afd8b03e6932102eba627e6ea5bb7e0f4c981596872d0a97d800fb836b5b3a585c3f2b99c77a0e552ae").unwrap());
        assert_eq!(
            redeem_script_ms_2of2.get_opcheckmultisig_n_m(),
            Ok(Some((2, 2)))
        )
    }

    #[test]
    fn multisig_opcheckmultisig_4of5() {
        // from mainnet 391f812dcce57d1b60669dfdc538d34fe25eec27134122d1fec8cd3208cb3ad4 input 0
        let redeem_script_ms_2of2 = Script::from(hex::decode("542102916d4144e950066e729b6142e6b0e24edeed8203303113c71bdf0fc8e1daad1e210236a7c19695857bacd26921ba932a287bfdc622498296166cd6ff5488525abf782103db287a99a4d208dd912e366494b1828c0046fd76cb2277f4a3abf4b43d9d6f6921034597594080142f4492f5f39a01c2ee203e1d9efedfebbccf77d0d5c6f54b92202102003af4953da0b10f848ce81c9564ff7cbe289fc9beda4e70d66176c12ec622e255ae").unwrap());
        assert_eq!(
            redeem_script_ms_2of2.get_opcheckmultisig_n_m(),
            Ok(Some((4, 5)))
        )
    }

    #[test]
    fn multisig_opcheckmultisig_non_multiscript_sig() {
        let redeem_script_non_multisig = Script::from(hex::decode("6382012088a820697ce4e1d91cdc96d53d1bc591367bd48855a076301972842aa5ffcb8fcb8b618876a9142c3a8a495c16839d5d975c1ca0ee504af825b52188ac6704c9191960b17576a9145a59f40f4ecb1f86efb13752b600ea3b8d4c633988ac68").unwrap());
        assert_eq!(
            redeem_script_non_multisig.get_opcheckmultisig_n_m(),
            Ok(None)
        )
    }

    #[test]
    fn multisig_opcheckmultisig_broken_2of3() {
        // A 2-of-2 script modified to have n = 2 and m = 3, but only 2 PubKeys
        let redeem_script_non_multisig = Script::from(hex::decode("522103a2ea7e0b94c48fd799bf123c1f19b50fb6d15da310db8223fd7a6afd8b03e6932102eba627e6ea5bb7e0f4c981596872d0a97d800fb836b5b3a585c3f2b99c77a0e553ae").unwrap());
        assert_eq!(
            redeem_script_non_multisig.get_opcheckmultisig_n_m(),
            Ok(None)
        )
    }

    #[test]
    fn multisig_opcheckmultisig_broken_2of1() {
        // A 2-of-1 script e.g. found twice in the testnet transaction 157c8495334e86b9422e656aa2c1a2fe977ed91fd27e2db71f6f64576f0456d9
        let redeem_script_non_multisig = Script::from(
            hex::decode(
                "5221021f5e6d618cf1beb74c79f42b0aae796094b3112bbe003209a2c1f757f1215bfd51ae",
            )
            .unwrap(),
        );
        assert_eq!(
            redeem_script_non_multisig.get_opcheckmultisig_n_m(),
            Ok(None)
        )
    }

    #[test]
    fn multisig_opcheckmultisig_invalid_script() {
        let redeem_script_non_multisig = Script::from(hex::decode("b10cabcdae").unwrap());
        assert!(redeem_script_non_multisig
            .get_opcheckmultisig_n_m()
            .is_err())
    }
}
