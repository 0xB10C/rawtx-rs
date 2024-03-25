//! Information about Bitcoin transaction inputs.

use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script;
use bitcoin::script::Instruction;
use bitcoin::{Sequence, TxIn};
use std::fmt;

use crate::script::{instructions_as_vec, Multisig, PublicKey, Signature, SignatureInfo};
pub const TAPROOT_ANNEX_INDICATOR: u8 = 0x50;
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
pub const ORDINALS_INSCRIPTION_MARKER: [u8; 3] = [0x6f, 0x72, 0x64]; // ASCII "ord"

#[derive(Debug)]
pub struct InputInfo {
    pub in_type: InputType,
    pub sequence: Sequence,
    pub multisig_info: Option<MultisigInputInfo>,
    pub signature_info: Vec<SignatureInfo>,
    // TODO: PubKeyStats vec
    // TODO: OpCodes vec?
    // TODO: is_ln_unilateral_closing: bool,
}

impl InputInfo {
    pub fn new(input: &TxIn) -> Result<InputInfo, script::Error> {
        Ok(InputInfo {
            sequence: input.sequence,
            in_type: input.get_type()?,
            multisig_info: input.multisig_info()?,
            signature_info: SignatureInfo::all_from(&input)?,
        })
    }

    /// Returns true if the input spends a SegWit output
    pub fn is_spending_segwit(&self) -> bool {
        match self.in_type {
            InputType::P2shP2wpkh
            | InputType::P2shP2wsh
            | InputType::P2wpkh
            | InputType::P2wsh
            | InputType::P2trkp
            | InputType::P2trsp => true,
            InputType::P2ms
            | InputType::P2msLaxDer
            | InputType::P2pk
            | InputType::P2pkLaxDer
            | InputType::P2pkh
            | InputType::P2pkhLaxDer
            | InputType::P2sh
            | InputType::Unknown
            | InputType::Coinbase
            | InputType::CoinbaseWitness => false,
        }
    }

    /// Returns true if the input spends Taproot either with a key-path or script-path spend.
    pub fn is_spending_taproot(&self) -> bool {
        match self.in_type {
            InputType::P2trkp | InputType::P2trsp => true,
            InputType::P2ms
            | InputType::P2msLaxDer
            | InputType::P2pk
            | InputType::P2pkLaxDer
            | InputType::P2pkh
            | InputType::P2pkhLaxDer
            | InputType::P2sh
            | InputType::Unknown
            | InputType::P2shP2wpkh
            | InputType::P2shP2wsh
            | InputType::P2wpkh
            | InputType::P2wsh
            | InputType::Coinbase
            | InputType::CoinbaseWitness => false,
        }
    }

    /// Returns true if the input spends either a P2SH-nested-P2WPKH or a P2SH-nested-P2WSH input
    pub fn is_spending_nested_segwit(&self) -> bool {
        match self.in_type {
            InputType::P2shP2wpkh | InputType::P2shP2wsh => true,
            InputType::P2pk
            | InputType::P2pkLaxDer
            | InputType::P2pkh
            | InputType::P2pkhLaxDer
            | InputType::P2ms
            | InputType::P2msLaxDer
            | InputType::P2wpkh
            | InputType::P2wsh
            | InputType::P2trkp
            | InputType::P2trsp
            | InputType::P2sh
            | InputType::Coinbase
            | InputType::Unknown
            | InputType::CoinbaseWitness => false,
        }
    }

    /// Returns true if the input spends either a native P2WPKH or a native P2WSH input
    pub fn is_spending_native_segwit(&self) -> bool {
        match self.in_type {
            InputType::P2wpkh | InputType::P2wsh | InputType::P2trkp | InputType::P2trsp => true,
            InputType::P2pk
            | InputType::P2pkLaxDer
            | InputType::P2pkh
            | InputType::P2pkhLaxDer
            | InputType::P2ms
            | InputType::P2msLaxDer
            | InputType::P2shP2wsh
            | InputType::P2shP2wpkh
            | InputType::P2sh
            | InputType::Coinbase
            | InputType::Unknown
            | InputType::CoinbaseWitness => false,
        }
    }

    /// Returns true if the input spends a legacy output.
    pub fn is_spending_legacy(&self) -> bool {
        match self.in_type {
            InputType::P2ms
            | InputType::P2msLaxDer
            | InputType::P2pk
            | InputType::P2pkLaxDer
            | InputType::P2pkh
            | InputType::P2pkhLaxDer
            | InputType::P2sh
            | InputType::Unknown => true,
            InputType::P2wpkh
            | InputType::P2wsh
            | InputType::P2trkp
            | InputType::P2trsp
            | InputType::P2shP2wpkh
            | InputType::P2shP2wsh
            | InputType::Coinbase
            | InputType::CoinbaseWitness => false,
        }
    }

    /// Returns true if the input spends a Multisig input.
    pub fn is_spending_multisig(&self) -> bool {
        self.multisig_info.is_some()
    }
}

/// Contains information about a multi-signature construct used in an input.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct MultisigInputInfo {
    /// Represents the number of needed signatures `m` from the possible
    /// signatures `n`. Example: In a 2-of-3 (m = 2, n = 3) multisig there must
    /// be signatures corresponding to two out of 3 possibly allowed Public Keys
    /// supplied.
    pub m_of_n: (u8, u8),
    /// For P2MS inputs the n value (number of possible signatures) can not be
    /// retrieved from the P2MS input. This is indicated by this boolean set to
    /// `true`.
    pub unknown_n: bool,
}

pub trait InputMultisigDetection {
    fn multisig_info(&self) -> Result<Option<MultisigInputInfo>, script::Error>;
}

impl InputMultisigDetection for TxIn {
    /// Returns Some([MultisigInputInfo]) when the input detectably spends a
    /// multisig, If the multisig spend is not detected, None() is returned.
    fn multisig_info(&self) -> Result<Option<MultisigInputInfo>, script::Error> {
        if self.is_scripthash_input()? {
            if let Ok(Some(redeemscript)) = self.redeem_script() {
                if let Ok(Some(multisig)) = redeemscript.get_opcheckmultisig_n_m() {
                    return Ok(Some(MultisigInputInfo {
                        m_of_n: multisig,
                        unknown_n: false,
                    }));
                }
            }
        } else if self.get_type()? == InputType::P2ms {
            if let Ok(instructions) = crate::script::instructions_as_vec(&self.script_sig) {
                // P2MS sigscripts consist of an OP_0 followed by up to 3 ECDSA signatures.
                let instructions_count = instructions.len();
                assert!(instructions_count <= 4);
                return Ok(Some(MultisigInputInfo {
                    m_of_n: ((instructions_count - 1) as u8, 0),
                    unknown_n: true,
                }));
            }
        }
        Ok(None)
    }
}

pub trait InputSigops {
    fn sigops(&self) -> Result<usize, script::Error>;
}

impl InputSigops for TxIn {
    fn sigops(&self) -> Result<usize, script::Error> {
        const SIGOPS_SCALE_FACTOR: usize = 4;
        let mut sigops: usize = 0;

        // in P2TR scripts and coinbase inputs, no sigops are counted
        if self.is_p2trkp() || self.is_p2trsp() || self.is_coinbase() || self.is_coinbase_witness()
        {
            return Ok(0);
        }

        // While very very seldom, there can be sigops in the inputs script_sig
        sigops += SIGOPS_SCALE_FACTOR * self.script_sig.count_sigops_legacy();

        match self.get_type()? {
            // sigops in P2SH redeem scripts (pre SegWit) are scaled by 4
            InputType::P2sh => {
                if let Some(redeem_script) = self.redeem_script()? {
                    sigops += SIGOPS_SCALE_FACTOR * redeem_script.count_sigops();
                }
            }
            InputType::P2shP2wsh | InputType::P2wsh => {
                if let Some(redeem_script) = self.redeem_script()? {
                    sigops += redeem_script.count_sigops();
                }
            }
            // P2SH-P2WPKH and P2WPKH always have one sigop
            InputType::P2shP2wpkh | InputType::P2wpkh => {
                sigops += 1;
            }
            _ => (),
        };

        return Ok(sigops);
    }
}

pub trait ScriptHashInput {
    fn redeem_script(&self) -> Result<Option<bitcoin::ScriptBuf>, script::Error>;
}

impl ScriptHashInput for TxIn {
    /// Returns the redeem script of the input. The caller must make sure the
    /// input is script hash based, otherwise None is returned.
    fn redeem_script(&self) -> Result<Option<bitcoin::ScriptBuf>, script::Error> {
        if !self.is_scripthash_input()? {
            return Ok(None);
        }

        match self.get_type()? {
            InputType::P2sh => {
                // redeem script is the last element of the script sig
                if let Some(instruction) = self.script_sig.instructions().last() {
                    if let script::Instruction::PushBytes(push_bytes) = instruction? {
                        return Ok(Some(bitcoin::ScriptBuf::from(
                            push_bytes.as_bytes().to_vec(),
                        )));
                    }
                }
                Ok(None)
            }
            InputType::P2shP2wsh => {
                // redeem script is the last element of the witness
                if let Some(bytes) = self.witness.last() {
                    return Ok(Some(bitcoin::ScriptBuf::from(bytes.to_vec())));
                }
                Ok(None)
            }
            InputType::P2wsh => {
                // redeem script is the last element of the witness
                if let Some(bytes) = self.witness.last() {
                    return Ok(Some(bitcoin::ScriptBuf::from(bytes.to_vec())));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

pub trait PubkeyInput {
    fn get_pubkey(&self) -> bitcoin::Script;
    fn get_signature(&self) -> bitcoin::Script;
}

pub trait InputTypeDetection {
    fn get_type(&self) -> Result<InputType, script::Error>;
    fn has_witness(&self) -> bool;

    fn is_scripthash_input(&self) -> Result<bool, script::Error>;

    // detection:
    fn is_p2ms(&self, strict_der_sig: bool) -> Result<bool, script::Error>;
    fn is_p2pk(&self, strict_der_sig: bool) -> Result<bool, script::Error>;
    fn is_p2pkh(&self, strict_der_sig: bool) -> Result<bool, script::Error>;
    fn is_p2sh(&self) -> Result<bool, script::Error>;
    fn is_nested_p2wpkh(&self) -> bool;
    fn is_nested_p2wsh(&self) -> bool;
    fn is_p2wpkh(&self) -> bool;
    fn is_p2wsh(&self) -> bool;
    fn is_p2trkp(&self) -> bool;
    fn is_p2trsp(&self) -> bool;
    fn is_coinbase(&self) -> bool;
    fn is_coinbase_witness(&self) -> bool;
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum InputType {
    /// Pay-to-Public-Key input
    P2pk,
    /// Pay-to-Public-Key input when parsing the signature with non-strict DER encoding rules.
    /// This should only appear in transactions created before [BIP-66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)
    /// activation in 2015.
    P2pkLaxDer,
    /// Pay-to-Public-Key-Hash input
    P2pkh,
    /// Pay-to-Public-Key-Hash input when parsing the signature with non-strict DER encoding rules.
    /// This should only appear in transactions created before [BIP-66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)
    /// activation in 2015.
    P2pkhLaxDer,
    /// Pay-to-Script-Hash wrapped Pay-to-Witness-Public-Key-Hash input
    P2shP2wpkh,
    /// Pay-to-Witness-Public-Key-Hash input
    P2wpkh,
    /// Pay-to-Multisig input
    P2ms,
    /// Pay-to-Multisig input when parsing the signature with non-strict DER encoding rules.
    /// This should only appear in transactions created before [BIP-66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)
    /// activation in 2015.
    P2msLaxDer,
    /// Pay-to-Script-Hash input
    P2sh,
    /// Pay-to-Script-Hash wrapped Pay-to-Witness-Script-Hash input
    P2shP2wsh,
    /// Pay-to-Witness-Script-Hash input
    P2wsh,
    /// Pay-to-Taproot key path input
    P2trkp,
    /// Pay-to-Taproot script path input
    P2trsp,
    /// Coinbase transaction input
    Coinbase,
    /// Coinbase transaction input with a witness
    CoinbaseWitness,
    /// Unknown or unhandled input
    Unknown,
}

impl fmt::Display for InputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputType::P2pk => write!(f, "P2PK"),
            InputType::P2pkLaxDer => write!(f, "P2PK (lax DER)"),
            InputType::P2pkh => write!(f, "P2PKH"),
            InputType::P2pkhLaxDer => write!(f, "P2PKH (lax DER)"),
            InputType::P2shP2wpkh => write!(f, "P2SH-P2WPKH"),
            InputType::P2wpkh => write!(f, "P2WPKH"),
            InputType::P2msLaxDer => write!(f, "P2MS (lax DER)"),
            InputType::P2ms => write!(f, "P2MS"),
            InputType::P2sh => write!(f, "P2SH"),
            InputType::P2shP2wsh => write!(f, "P2SH-P2WSH"),
            InputType::P2wsh => write!(f, "P2WSH"),
            InputType::P2trkp => write!(f, "P2TR key-path"),
            InputType::P2trsp => write!(f, "P2TR script-path"),
            InputType::Coinbase => write!(f, "Coinbase"),
            InputType::CoinbaseWitness => write!(f, "Coinbase with Witness"),
            InputType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl InputTypeDetection for TxIn {
    fn get_type(&self) -> Result<InputType, script::Error> {
        if self.has_witness() {
            if self.is_nested_p2wpkh() {
                return Ok(InputType::P2shP2wpkh);
            } else if self.is_p2wpkh() {
                return Ok(InputType::P2wpkh);
            } else if self.is_nested_p2wsh() {
                return Ok(InputType::P2shP2wsh);
            } else if self.is_p2wsh() {
                return Ok(InputType::P2wsh);
            } else if self.is_p2trkp() {
                return Ok(InputType::P2trkp);
            } else if self.is_p2trsp() {
                return Ok(InputType::P2trsp);
            } else if self.is_coinbase_witness() {
                return Ok(InputType::CoinbaseWitness);
            }
        } else if self.is_p2pkh(/* strict DER. */ true)? {
            return Ok(InputType::P2pkh);
        } else if self.is_p2pkh(/* strict DER. */ false)? {
            return Ok(InputType::P2pkhLaxDer);
        } else if self.is_p2sh()? {
            return Ok(InputType::P2sh);
        } else if self.is_p2pk(/* strict DER. */ true)? {
            return Ok(InputType::P2pk);
        } else if self.is_p2pk(/* strict DER. */ false)? {
            return Ok(InputType::P2pkLaxDer);
        } else if self.is_p2ms(/* strict DER. */ true)? {
            return Ok(InputType::P2ms);
        } else if self.is_p2ms(/* strict DER. */ false)? {
            return Ok(InputType::P2msLaxDer);
        } else if self.is_coinbase() {
            return Ok(InputType::Coinbase);
        }
        Ok(InputType::Unknown)
    }

    /// Indicates if the witness contains data.
    fn has_witness(&self) -> bool {
        !self.witness.is_empty()
    }

    /// Indicates if the input is script hash based.
    fn is_scripthash_input(&self) -> Result<bool, script::Error> {
        match self.get_type()? {
            InputType::P2sh | InputType::P2shP2wsh | InputType::P2wsh => Ok(true),
            _ => Ok(false),
        }
    }

    /// Checks if an input spends a P2PK output.
    ///
    /// The caller can decide if the signature must be strictly DER encoded.
    /// All transactions present in the blockchain after July 4th, 2015 have to
    /// be strictly DER encoded as per [BIP-66]. Setting this to `false` only
    /// makes sense when working with historical data.
    ///
    /// [BIP-66]: https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).
    ///
    /// A P2PK spend has only a signature in the script_sig and no witness.
    /// `script_sig: [ <ECDSA Signature> ]`
    /// `witness: [ ]`
    ///
    /// # Errors
    ///
    /// Returns a [`script::Error`] if the script_sig can't be parsed.
    fn is_p2pk(&self, strict_der_sig: bool) -> Result<bool, script::Error> {
        if self.has_witness() || self.script_sig.is_empty() {
            return Ok(false);
        }

        let instructions = crate::script::instructions_as_vec(&self.script_sig)?;
        if instructions.len() != 1 || !instructions[0].is_ecdsa_signature(strict_der_sig) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Checks if an input spends an P2MS output.
    ///
    /// The caller can decide if the signature must be strictly DER encoded.
    /// All transactions present in the blockchain after July 4th, 2015 have to
    /// be strictly DER encoded as per [BIP-66]. Setting this to `false` only
    /// makes sense when working with historical data.
    ///
    /// [BIP-66]: https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).
    ///
    /// A P2MS spend has a OP_0 followed by one to three signatures in the script_sig.
    /// It doesn't have a witness.
    /// `script_sig: [ OP_0 <ECDSA Signature> (<ECDSA Signature>) (<ECDSA Signature>) ]`
    /// `witness: [ ]`
    fn is_p2ms(&self, strict_der_sig: bool) -> Result<bool, script::Error> {
        if self.has_witness() {
            return Ok(false);
        }

        let instructions = crate::script::instructions_as_vec(&self.script_sig)?;

        if instructions.len() < 2 || instructions.len() > 4 {
            return Ok(false);
        }

        for (i, instruction) in instructions.iter().enumerate() {
            match i {
                0 => {
                    // checks that the first instruction is a OP_0
                    if let script::Instruction::PushBytes(bytes) = instruction {
                        if !bytes.is_empty() {
                            return Ok(false);
                        };
                    } else {
                        return Ok(false);
                    };
                }
                1..=3 => {
                    // and all following are ECDSA Signatures
                    if !instruction.is_ecdsa_signature(strict_der_sig) {
                        return Ok(false);
                    }
                }
                _ => return Ok(false),
            }
        }

        Ok(true)
    }

    /// Checks if an input spends a P2PKH output.
    ///
    /// The caller can decide if the signature must be strictly DER encoded.
    /// All transactions present in the blockchain after July 4th, 2015 have to
    /// be strictly DER encoded as per [BIP-66]. Setting this to `false` only
    /// makes sense when working with historical data.
    ///
    /// [BIP-66]: https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).
    ///
    /// A P2PKH spend has a public key and a signature in the script_sig. It
    /// doesn't have a witness.
    /// `script_sig: [ <ECDSA Signature> <PublicKey> ]`
    /// `witness: [ ]`
    ///
    /// # Errors
    ///
    /// Returns a [`script::Error`] if the script_sig can't be parsed.
    fn is_p2pkh(&self, strict_der_sig: bool) -> Result<bool, script::Error> {
        if self.has_witness() {
            return Ok(false);
        }

        let instructions = crate::script::instructions_as_vec(&self.script_sig)?;
        if instructions.len() != 2
            || !instructions[0].is_ecdsa_signature(strict_der_sig)
            || !instructions[1].is_pubkey()
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Checks if an input spends a P2SH output.
    ///
    /// A P2SH output has at least an redeem script as last script_sig element.
    /// We can test this by making sure The witness is empty.
    /// `script_sig: [ .. <redeem script> ]`
    /// `witness: [  ]`
    ///
    /// # Errors
    ///
    /// Returns a [`script::Error`] if the script can't be parsed.
    fn is_p2sh(&self) -> Result<bool, script::Error> {
        if self.has_witness()
            || self.is_p2pkh(false)?
            || self.is_p2pk(false)?
            || self.is_p2ms(false)?
            || self.is_p2pkh(true)?
            || self.is_p2pk(true)?
            || self.is_p2ms(true)?
            || self.is_coinbase()
            || self.script_sig.is_empty()
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Checks if an input spends a Nested P2WPKH output.
    ///
    /// A nested P2WPKH output has a OP_PUSHBYTES_22 in the script_sig. The
    /// pushed data contains an OP_0 and an OP_PUSHBYTES_20 pushing a 20 byte
    /// hash. The witness contains an ECDSA signature and a public key. The
    /// signature must be strictly DER encoded.
    /// `script_sig: [ <OP_PUSHBYTES_22 [<OP_0 OP_PUSHBYTES_20 [20-byte hash]>]>]`
    /// `witness: [ <ECDSA Signature> <PublicKey> ]`
    fn is_nested_p2wpkh(&self) -> bool {
        if self.script_sig.len() != 23 || self.witness.len() != 2 {
            return false;
        }

        let script_sig = self.script_sig.as_bytes();
        if script_sig[0] == opcodes::OP_PUSHBYTES_22.to_u8()
            && script_sig[1] == opcodes::OP_PUSHBYTES_0.to_u8()
            && script_sig[2] == opcodes::OP_PUSHBYTES_20.to_u8()
            && self.witness.to_vec()[0].is_ecdsa_signature(/* strict DER */ true)
            && self.witness.to_vec()[1].is_pubkey()
        {
            return true;
        }

        false
    }

    /// Checks if an input spends a nested P2WSH output.
    ///
    /// A nested P2WSH input has a single PUSH_BYTE_34 instruction which pushes
    /// a nested script containing two instructions: a OP_0 and a PUSH_BYTES_32.
    /// The witness contains at least the redeem script as last element.
    /// `script_sig: [ <OP_PUSH_BYTE_34> [OP_0 PUSH_BYTES_32 <32 byte hash>] ]`
    /// `witness: [ .. <redeem script> ]`
    ///
    /// Returns a [`script::Error`] if the script can't be parsed.
    fn is_nested_p2wsh(&self) -> bool {
        if self.script_sig.len() != 35 || self.witness.is_empty() {
            return false;
        }

        let script_sig = self.script_sig.as_bytes();
        if script_sig[0] == opcodes::OP_PUSHBYTES_34.to_u8()
            && script_sig[1] == opcodes::OP_PUSHBYTES_0.to_u8()
            && script_sig[2] == opcodes::OP_PUSHBYTES_32.to_u8()
        {
            return true;
        }
        false
    }

    /// Checks if an input spends a P2WPKH output.
    ///
    /// A P2WPKH output has an empty script_sig. The witness contains an ECDSA
    /// signature and a public key. The signature must be strictly DER encoded.
    /// `script_sig: [ ]`
    /// `witness: [ <ECDSA Signature> <PublicKey> ]`
    fn is_p2wpkh(&self) -> bool {
        if !self.script_sig.is_empty() || self.witness.len() != 2 {
            return false;
        }

        if self.witness.to_vec()[0].is_ecdsa_signature(/* strict DER */ true)
            && self.witness.to_vec()[1].is_pubkey()
        {
            return true;
        }

        false
    }

    /// Checks if an input spends a P2WSH output.
    ///
    /// A P2WSH output has an empty script_sig. The data is contained in the witness.
    /// `script_sig: [ ]`
    /// `witness: [ .. ]`
    fn is_p2wsh(&self) -> bool {
        if !self.script_sig.is_empty()
            || !self.has_witness()
            || self.is_p2wpkh()
            || self.is_p2trkp()
            || self.is_p2trsp()
        {
            return false;
        }

        true
    }

    /// Checks if an input spends a P2TR-keypath output.
    ///
    /// A P2TR output has an empty script_sig. The witness contains a Schnorr signature
    /// and optionally an annex.
    /// `script_sig: [ ]`
    /// `witness: [ <schnorr signature> (<annex>) ]`
    fn is_p2trkp(&self) -> bool {
        if !self.script_sig.is_empty() || !self.has_witness() || self.witness.len() > 2 {
            return false;
        }
        if self.witness.len() == 1 {
            // without annex
            return self.witness.to_vec()[0].is_schnorr_signature();
        } else if self.witness.len() == 2 {
            // with annex
            if !self.witness.to_vec()[1].is_empty()
                && self.witness.to_vec()[1][0] == TAPROOT_ANNEX_INDICATOR
            {
                return self.witness.to_vec()[0].is_schnorr_signature();
            }
        }
        false
    }

    /// Checks if an input spends a P2TR-scriptpath output.
    ///
    /// A P2TR output has an empty script_sig. The witness script-input-data (zero-to-many),
    /// a script, a control block, and optionally an annex.
    /// `script_sig: [ ]`
    /// `witness: [ (<script input data>, <script input data>, ...) <script> <control block> (<annex>) ]`
    fn is_p2trsp(&self) -> bool {
        if !self.script_sig.is_empty() || !self.has_witness() || self.witness.len() < 2 {
            return false;
        }

        let last_witness_element_index = self.witness.len() - 1;
        let mut control_block_index = last_witness_element_index;
        let witness_vec = self.witness.to_vec();

        // check for annex
        if !witness_vec[last_witness_element_index].is_empty()
            && witness_vec[last_witness_element_index][0] == TAPROOT_ANNEX_INDICATOR
        {
            control_block_index -= 1;
        }

        // check for control block
        let control_block = &witness_vec[control_block_index];
        if control_block.len() < 1 + 32 || (control_block.len() - 1) % 32 != 0 {
            return false;
        }

        if control_block[0] & TAPROOT_LEAF_MASK == TAPROOT_LEAF_TAPSCRIPT {
            return true;
        }

        false
    }

    /// Checks if an input is a coinbase without witness data.
    ///
    /// A coinbase has a an Outpoint with an all zero txid and an output index
    /// of 0xffffffff. The witness is empty.
    fn is_coinbase(&self) -> bool {
        if self.has_witness()
            || self.previous_output.vout != 0xffffffff
            || !self.previous_output.is_null()
        {
            return false;
        }
        true
    }

    /// Checks if an input is a coinbase with witness data. // TODO: since when are these to be expected?
    ///
    /// A coinbase has a an Outpoint with an all zero txid and an output index
    /// of 0xffffffff. The witness is not empty.
    fn is_coinbase_witness(&self) -> bool {
        if !self.has_witness()
            || self.previous_output.vout != 0xffffffff
            || !self.previous_output.is_null()
        {
            return false;
        }
        true
    }
}

pub trait InputInscriptionDetection {
    fn reveals_inscription(&self) -> Result<bool, script::Error>;
}

impl InputInscriptionDetection for TxIn {
    fn reveals_inscription(&self) -> Result<bool, script::Error> {
        if !self.is_p2trsp() {
            return Ok(false);
        }
        // Inscription reveals can be identified by inspecting the tapscript
        if let Some(tapscript) = self.witness.tapscript() {
            if let Ok(instructions) = instructions_as_vec(tapscript) {
                let mut instruction_iter = instructions.iter();
                while let Some(instruction) = instruction_iter.next() {
                    if matches!(instruction, Instruction::PushBytes(bytes) if bytes.is_empty()) {
                        if matches!(instruction_iter.next(), Some(Instruction::Op(op)) if op == &opcodes::OP_IF)
                        {
                            if matches!(instruction_iter.next(), Some(Instruction::PushBytes(bytes)) if bytes.as_bytes() == ORDINALS_INSCRIPTION_MARKER.to_vec())
                            {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InputInfo, InputInscriptionDetection, InputMultisigDetection, InputType,
        InputTypeDetection, MultisigInputInfo,
    };
    use bitcoin::Transaction;

    #[test]
    fn reveals_inscription() {
        // mainnet ba4f42037f92c2782ee3dd8c75ce0ce80d8a04b8d36e6ed6a36452f512e66dfd
        let rawtx = hex::decode("02000000000101da5159649742d35e069f74724bb72cbb116415d72e11771a17420e2201d4ecf30000000000fdffffff0122020000000000002251201e6960b35d5da5c6c9ce0a18d989518bf546b4968a4ad046d9d664f5585f50440340ad42d4bec479e22866603b11048a64a3e5d366046d494278336798a51fd5fe5166221949e3025b25b505433ed871e20399fd82ffc867b70de8acef8e86f91f857e20318de3d918b6ca5ce115f5b00b3ed0b9c85ca7ebe8f0ccbe9de0e05e45de9293ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800387b2270223a226272632d3230222c226f70223a227472616e73666572222c227469636b223a224d4d5353222c22616d74223a22323030227d6821c1318de3d918b6ca5ce115f5b00b3ed0b9c85ca7ebe8f0ccbe9de0e05e45de929300000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2trsp());
        assert!(in0.reveals_inscription().unwrap());

        // mainnet 8cf0e9c282233d72bae9b90a8f5b656d5decaa75c4a8ad54f457e45cd087d295
        let rawtx = hex::decode("02000000000101db7427b32d5755c1ea1fad429d87e6a641a2682e53c0c7cfaf3bec578c349b680000000000fdffffff022202000000000000225120f97a587234b7e22e7b5de2d61b1861e0c8774eedb9b48190fabe41b083d24926db06000000000000160014d02d8c6d6b2307d96bc2bf99e89acab7fb3a923003402817599a681318c55b335f5fb29e6755a4f23e345a8dc130cb1e478f2dec76f748378d279f5b82ca70587d91caff2f906146df28785931b09f186489f317c2add020287b98bfb98dd21a639ee15a8414e70f4bb5f8747961f4c2ef1596519d465db1ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d38004c897b2270223a2022746170222c20226f70223a2022646d742d6d696e74222c2022646570223a2022303161393235393934656563313435313261653935386466313761353231666437663835616636613731633132373061656332303432323866613661613336346930222c20227469636b223a20226e6174222c2022626c6b223a202231363934227d6821c1f7f702f2e97e53bd22500cc1207871e88abba8871df5495ad16f3c73a5d7460e00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2trsp());
        assert!(in0.reveals_inscription().unwrap());
    }

    #[test]
    fn input_type_detection_p2pk() {
        // mainnet ea44e97271691990157559d0bdd9959e02790c34db6c006d779e82fa5aee708e
        let rawtx = hex::decode("0100000001169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f400000000484730440220576497b7e6f9b553c0aba0d8929432550e092db9c130aae37b84b545e7f4a36c022066cb982ed80608372c139d7bb9af335423d5280350fe3e06bd510e695480914f01ffffffff0100ca9a3b000000001976a914340cfcffe029e6935f4e4e5839a2ff5f29c7a57188ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2pk(true).unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2pk);
    }

    #[test]
    fn input_type_detection_p2pkh() {
        // mainnet ab8358ee2d4573d975c5b693fcd349bd09a089327f5c12ca8a4abd350f18e670
        let rawtx = hex::decode("01000000013e536ab65e20de9b57dd2859abd7289fd0452c3f5ac672b956d9c787d1933466230000006a47304402201b6e925baff25e8f9fda211f4319a0d9bc5add80d285db5609b882a80b4c50d002200e797a1435838df602634dd69e829bc884bc995aac77ea57ddf5c92e44dacc6f012103b773940906913e962d81b6c4d7c405212bf91ae736123eba7970859edefba84effffffff0188f40000000000001976a91408653d83a8bff4c66edd72921659326bd6ef04cc88ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2pkh(true).unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2pkh);
    }

    #[test]
    fn input_type_detection_nested_p2wpkh() {
        // mainnet 9671f217d4d12b1717606403468fd0b1ed7362e33282f8834d4d38e67f85767b
        let rawtx = hex::decode("020000000001017287da3eef7369c13bacb9fb92e7b1c3aabe04ead8d76b620c3966623fb1da510000000017160014ace9fb5f9aab3d34f272775424bbacd1132ff00effffffff01614804000000000017a91431ab116fe54444ef21c7656f3bb4bfe2520210fe8702473044022053c98f1e2f3dad4ad3e53c1f2e78a833a9e3bb0a47e592dc840312d053805c4602200bb65ecf01cb49d7506df37ff61141584c731c127973d4a651ab0f5cc5de04c60121029b8741cc06f098df1fad8f1fb920e1d610024b9f0190708b0dd777ba9cd1a55300000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_nested_p2wpkh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2shP2wpkh);
    }

    #[test]
    fn input_type_detection_p2wpkh() {
        // mainnet 4aba5c7fe256a9997aa93cab91f1c0405074b30b34b6a5c0bbde425322d40ee7
        let rawtx = hex::decode("01000000000101ce73651d1ef6e687a66a76adbaf16741a205e7230bff0ae7259d36c478ec1a339a00000000ffffffff018a399c0000000000160014a14296a183d6e4c2f1696713a9db833e66fcb2d50247304402204da5741dab6897b961d996c0bdd0fed51f33afa54459769a81019d04a35fb1a802206f47143811a512a73b9d1112f5f0202740c554bf853fe18e2c72e58381c5452b012103e37b04cf32aa417e3ef25c0fe19faefcdbb6e6b2eaca38837dabc4c146cdc95000000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2wpkh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2wpkh);
    }

    #[test]
    fn input_type_detection_p2sh() {
        // mainnet 986e143fae33eb39bb2bdb2d5e0f6cb003ab8c6e638b4adf02b5a1ae8a81b4ec
        let rawtx = hex::decode("0200000001b5d093fa119005dbb1e6efe4abae8352b9be31999dd498e2a4242d12a1bcac8800000000910047304402203c3e5cb8e6dd567804efb6f26523229ea67ed1f4529a35fd92a64407db790cce02201ba1f5173e792cc9e63769700e8f7673eae8ac705b58caa5931ec614f56f1acc014751210377622563e0110914888b7dc9364d6d341804aa0d7f09b3dea04f14a7dad104452103c71b40231260e990938f1be55bbf8c580832bcfdcb60a4e64139f12b313fe35552aefeffffff0258c70d00000000001976a914bab670335c428fe202157fb867dd06acca4ac25388ac5c2d53000000000017a914ad69347daeb1811224627597d5d8ebffa78c4c3e8700000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2sh().unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2sh);
    }

    #[test]
    fn input_type_detection_nested_p2wsh() {
        // mainnet 716e81f6ac8cb5e11bcf7d850e6049fe2e8067a1650378b4045c8ad005cac76b
        let rawtx = hex::decode("0100000000010158cffd9e03ff81e25367b93c78fe57c9a47dfd50e3365a0a210d7a75068333340100000023220020779b3b5851cbe7c95c7b21cd919aaf3df20b1f62f1dfc13bf93e734b3c88443ffdffffff01fca10000000000001976a914ea800dbd672b26181f9858bc0abedf40be747f3688ac0400483045022100d602eb075e28221a1b4622f24fa0a60242c90742033f032d40856ce0caed097c022061d066b92311b9492def6e0cc8bc0b76f73050b607a6d268f35d18d636ec7b940147304402203335fa91e31b8ec4e3ac5ddeb7fb2546c55a7aa6ee9548844337007dd29fcaac02204fbb78515a7085a9342c97c55b4f948681c3c1c80f9b2be5c9bd8e77a8cb6c240169522102a7b58e322616b2ac3752f59349b941edb5e9913f70864fc94a927b7592fe6d952103416995a2564b1fae34f521ad6745ffd04291bbda7075105e04720879ad728da52102523aa65c4a392a2ea8d81b8cd3bc19bba4b62a152f94a83f428c9b018dfc42d553ae00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_nested_p2wsh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2shP2wsh);
    }

    #[test]
    fn input_type_detection_p2ms_1of2() {
        // mainnet 99cb2139052dc88508f2fe35235c1c5685229a45bef3db70413c5ac43c41ca0a 1-of-2 P2MS input
        let rawtx = hex::decode("01000000013de6aff69d5ebeca70a84d1dcef768bbcadbad210084012f8cda24233c8db278000000004b00493046022100a41a9015c847f404a14fcc81bf711ee2ce57583987948d54ebe540aafca97e0d022100d4e30d1ca42f77df8290b8975aa8fc0733d7c0cfdd5067ca516bac6c4012b47a01ffffffff01607d860500000000475121037953dbf08030f67352134992643d033417eaa6fcfb770c038f364ff40d7615882100dd28dfb81abe444429c466a1e3ab7c22365c48f234ef0f8d40397202969d4e9552ae00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2ms(true).unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2ms);
        assert_eq!(
            in0.multisig_info().unwrap().unwrap(),
            MultisigInputInfo {
                m_of_n: (1, 0),
                unknown_n: true
            }
        );
    }

    #[test]
    fn input_type_detection_p2ms_2of3() {
        // mainnet 949591ad468cef5c41656c0a502d9500671ee421fadb590fbc6373000039b693 2-of-3 P2MS input
        let rawtx = hex::decode("010000000110a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58000000009300483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801ffffffff0180a21900000000001976a914971802edf585cdbc4e57017d6e5142515c1e502888ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2ms(true).unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2ms);
        assert_eq!(
            in0.multisig_info().unwrap().unwrap(),
            MultisigInputInfo {
                m_of_n: (2, 0),
                unknown_n: true
            }
        );
    }

    #[test]
    fn input_type_detection_p2wsh_2of2() {
        // mainnet f72d52eaae494da7c438a8456a9b20d2791fdf2b1c818825458f8f707d7b8011
        let rawtx = hex::decode("01000000000101ec2ad0604a0e708963a39d16936118ab5fb36dcb5d5e07f3dc2ca149412500eb0100000000ffffffff0233cc08000000000017a9147f152249241d7320a80a013fd46907c1a1eff5a4879a3a5c15000000002200202ceaf557137c8f1f8ac2c8ee4a6656f9533c250c62b40006956ecb44e5c2357e040047304402201489d616c691fb1a4dd86caa495991463d88e049fdc6e316bd09877cb4bc17de02201ebba0c182a6e28024944e63638788f44b77acbd85fbea60b1225f180def8fc901483045022100c00674b0810fe3e5db048bdd231f7a50edc1cc2ffd75a68497d43fae7853277802200a9422b26290b7521574a5c161e2116ef3e906030f6ed08ca38b6ee6c5690ddb0147522103a2ea7e0b94c48fd799bf123c1f19b50fb6d15da310db8223fd7a6afd8b03e6932102eba627e6ea5bb7e0f4c981596872d0a97d800fb836b5b3a585c3f2b99c77a0e552ae00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2wsh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2wsh);
        assert_eq!(
            in0.multisig_info().unwrap().unwrap(),
            MultisigInputInfo {
                m_of_n: (2, 2),
                unknown_n: false
            }
        );
    }

    #[test]
    fn input_type_detection_p2wsh_non_multisig() {
        // mainnet 41f18d932642a396b3469072860a10b193c53116d869dce9e2619b23555311cc
        let rawtx = hex::decode("02000000000101d29021fae716cbc98333fa1a88fa2a5cf6fd2db642a94ff33d7dfff2ad361fc30100000000ffffffff01ffdc0b00000000001600142c3a8a495c16839d5d975c1ca0ee504af825b52105483045022100d45ed56c316849b6ff15a568608aa887be0f5a09ad89d76f686949f320509d5902204e61db9bf6bb965b2de1ee0bb6d687a28579b0f725bde9d0e6c9a1c0a8cb6a0f0121020251be8c4c748fce671be54e247534f34d4c1b7f7784e3fc08ef41b3805a4af820535692b33b9f226fd70cd5571c68df7bfa5463d4a334a5ceb4d200fd0663f06a0101636382012088a820697ce4e1d91cdc96d53d1bc591367bd48855a076301972842aa5ffcb8fcb8b618876a9142c3a8a495c16839d5d975c1ca0ee504af825b52188ac6704c9191960b17576a9145a59f40f4ecb1f86efb13752b600ea3b8d4c633988ac6800000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2wsh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2wsh);
        assert_eq!(in0.multisig_info().unwrap(), None);
    }

    #[test]
    fn coinbase_input_detection() {
        // mainnet b39fa6c39b99683ac8f456721b270786c627ecb246700888315991877024b983 coinbase @ 300000
        let rawtx = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4803e09304062f503253482f0403c86d53087ceca141295a00002e522cfabe6d6d7561cf262313da1144026c8f7a43e3899c44f6145f39a36507d36679a8b7006104000000000000000000000001c8704095000000001976a91480ad90d403581fa3bf46086a91b2d9d4125db6c188ac00000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_coinbase());
        assert_eq!(in0.get_type().unwrap(), InputType::Coinbase);
    }

    #[test]
    fn p2trkp_input_detection() {
        // signet 75a1a2488770ba0506b9899b1d03dc232f5b22f00dffc3ca3ea6640a53de8403
        let rawtx = hex::decode("0200000000010232b1c6063448c8089d4e7a500399555daec6bc1f3fef281016518c1de3d154cb0000000000feffffff32b1c6063448c8089d4e7a500399555daec6bc1f3fef281016518c1de3d154cb0100000000feffffff02301b0f00000000002251204b03959143386c56a1646c9d1002314c6acecd79ee0f0976fb9fa0f1f0837b1be31f0000000000001600140af8bb24c9504e8740076bb07b755237d4af6e67014159f6076cc04503a9bc72f137aa4af523ab05f5805b5fcb9e0b0b0f258a86afd30c7298e11203f6f27a1408385ec5b9fc1d16be738d628a4aac62eef1cfdac10b0102473044022044d39c6b67334c5e1aa0be056b2200221f8ec84e7319ba1b1cbe6df4dc2f6b1d02207289dd7e3d362355f22ff1df76965391ccd9c4d529a216947d2434f16dfd9b7901210338008b55bf51d06440c64129665a56c2eb828fdad50cca74191d29f92475e962b5680000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2trkp());
        assert_eq!(in0.get_type().unwrap(), InputType::P2trkp);
        assert!(InputInfo::new(in0).unwrap().is_spending_taproot());
        assert!(InputInfo::new(in0).unwrap().is_spending_segwit());
    }

    #[test]
    fn p2trsp_input_detection() {
        // signet 692937bb7864cfcce9f7a5171d6af3646bf479204ffb9356a0d6ce8a4a7952f1
        let rawtx = hex::decode("02000000000101e1e91316b8780879bf5ac7559cbb3da5c65f19e57ed822615d832c53b2eeb5360000000000ffffffff01905f010000000000160014734e7298bfe985c5e0148a5a37179b66d9ad0b0804400d1e89bad817848056c3f32b4226f70946b84d358ff5a635b70f7ce40a43a94eba9b8ce213bc56d8ab6f9bb2f90d700cfed82fd93d91f41e7b3cf27c5b3ea77b20107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_p2trsp());
        assert_eq!(in0.get_type().unwrap(), InputType::P2trsp);
        assert!(InputInfo::new(in0).unwrap().is_spending_taproot());
        assert!(InputInfo::new(in0).unwrap().is_spending_segwit());
        assert!(!in0.reveals_inscription().unwrap());
    }

    #[test]
    fn coinbase_witness_input_detection() {
        // mainnet d229b92da09f3abac4f22ceee35e0e55fc43375a62cc575f445431340d9e1732 coinbase @ 668692
        let rawtx = hex::decode("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5b0314340a41d806348bf412e341d806348bafbbed2f45324d2026204254432e544f502ffabe6d6d2c7a0f4d5f67376109bb4e6e78904381170ee6ee0715344da30602c49d869cf68000000000000000e60086988fb8000000000000ffffffff023e740b2c000000001976a9140b904a4a8590d0ccff680bb8adc4ae4fe49f890a88ac0000000000000000266a24aa21a9ed165dbbf9c556629ce3b8f2e748f7ca8372131ca6cf47e95736efd8f73dcea77d0120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&rawtx).unwrap();
        let in0 = &tx.input[0];
        assert!(in0.is_coinbase_witness());
        assert_eq!(in0.get_type().unwrap(), InputType::CoinbaseWitness);
    }
}
