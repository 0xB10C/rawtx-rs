//! Information about Bitcoin transaction inputs.

use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script;
use bitcoin::script::Instruction;
use bitcoin::{Sequence, TxIn};
use std::{error, fmt};

use crate::script::{
    instructions_as_vec, Multisig, PubKeyInfo, PublicKey, Signature, SignatureInfo,
};

pub const TAPROOT_ANNEX_INDICATOR: u8 = 0x50;
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
pub const ORDINALS_INSCRIPTION_MARKER: [u8; 3] = [0x6f, 0x72, 0x64]; // ASCII "ord"

#[derive(Clone, Debug)]
pub enum InputError {
    TypeInfo(script::Error),
    MultisigInfo(script::Error),
    SignatureInfo(script::Error),
    PubkeyInfo(script::Error),
    SigOpsInfo(script::Error),
    ScriptHashInfo(script::Error),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InputError::TypeInfo(e) => write!(f, "Could not determine type of input: {}", e),
            InputError::MultisigInfo(e) => {
                write!(f, "Could not extract multisig infos from input: {}", e)
            }
            InputError::SignatureInfo(e) => {
                write!(f, "Could not extract signature infos from input: {}", e)
            }
            InputError::PubkeyInfo(e) => {
                write!(f, "Could not extract pubkey infos from input: {}", e)
            }
            InputError::SigOpsInfo(e) => {
                write!(f, "Could not extract sigops infos from input: {}", e)
            }
            InputError::ScriptHashInfo(e) => {
                write!(f, "Could not extract sighash infos from input: {}", e)
            }
        }
    }
}

impl error::Error for InputError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            InputError::TypeInfo(ref e) => Some(e),
            InputError::MultisigInfo(ref e) => Some(e),
            InputError::SignatureInfo(ref e) => Some(e),
            InputError::PubkeyInfo(ref e) => Some(e),
            InputError::SigOpsInfo(ref e) => Some(e),
            InputError::ScriptHashInfo(ref e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct InputInfo {
    pub in_type: InputType,
    pub sequence: Sequence,
    pub multisig_info: Option<MultisigInputInfo>,
    pub signature_info: Vec<SignatureInfo>,
    pub pubkey_stats: Vec<PubKeyInfo>,
    // TODO: OpCodes vec?
    // TODO: is_ln_unilateral_closing: bool,
}

impl InputInfo {
    pub fn new(input: &TxIn) -> Result<InputInfo, InputError> {
        let in_type = input.get_type()?;
        Ok(InputInfo {
            sequence: input.sequence,
            multisig_info: input.multisig_info_with_type(in_type)?,
            signature_info: SignatureInfo::all_from_with_type(input, in_type)?,
            pubkey_stats: PubKeyInfo::from_input_with_type(input, in_type)?,
            in_type,
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
            | InputType::P2trsp
            | InputType::P2a => true,
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
            | InputType::P2a
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
            | InputType::P2a
            | InputType::Coinbase
            | InputType::Unknown
            | InputType::CoinbaseWitness => false,
        }
    }

    /// Returns true if the input spends either a native P2WPKH, a native P2WSH, a P2TR or P2A input
    pub fn is_spending_native_segwit(&self) -> bool {
        match self.in_type {
            InputType::P2wpkh
            | InputType::P2wsh
            | InputType::P2trkp
            | InputType::P2trsp
            | InputType::P2a => true,
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
            | InputType::P2a
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
    fn multisig_info(&self) -> Result<Option<MultisigInputInfo>, InputError>;
    fn multisig_info_with_type(
        &self,
        in_type: InputType,
    ) -> Result<Option<MultisigInputInfo>, InputError>;
}

impl InputMultisigDetection for TxIn {
    /// Returns Some([MultisigInputInfo]) when the input detectably spends a
    /// multisig, If the multisig spend is not detected, None() is returned.
    fn multisig_info(&self) -> Result<Option<MultisigInputInfo>, InputError> {
        self.multisig_info_with_type(self.get_type()?)
    }

    fn multisig_info_with_type(
        &self,
        in_type: InputType,
    ) -> Result<Option<MultisigInputInfo>, InputError> {
        let is_scripthash = matches!(
            in_type,
            InputType::P2sh | InputType::P2shP2wsh | InputType::P2wsh
        );
        if is_scripthash {
            if let Ok(Some(redeemscript)) = self.redeem_script_with_type(in_type) {
                if let Ok(Some(multisig)) = redeemscript.get_opcheckmultisig_n_m() {
                    return Ok(Some(MultisigInputInfo {
                        m_of_n: multisig,
                        unknown_n: false,
                    }));
                }
            }
        } else if in_type == InputType::P2ms {
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
    fn sigops(&self) -> Result<usize, InputError>;
}

impl InputSigops for TxIn {
    fn sigops(&self) -> Result<usize, InputError> {
        const SIGOPS_SCALE_FACTOR: usize = 4;
        let mut sigops: usize = 0;

        // in P2TR and P2A scripts and coinbase inputs, no sigops are counted
        if self.is_p2a()
            || self.is_p2trkp()
            || self.is_p2trsp()
            || self.is_coinbase()
            || self.is_coinbase_witness()
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

        Ok(sigops)
    }
}

pub trait ScriptHashInput {
    fn redeem_script(&self) -> Result<Option<bitcoin::ScriptBuf>, InputError>;
    fn redeem_script_with_type(
        &self,
        in_type: InputType,
    ) -> Result<Option<bitcoin::ScriptBuf>, InputError>;
}

impl ScriptHashInput for TxIn {
    /// Returns the redeem script of the input. The caller must make sure the
    /// input is script hash based, otherwise None is returned.
    fn redeem_script(&self) -> Result<Option<bitcoin::ScriptBuf>, InputError> {
        self.redeem_script_with_type(self.get_type()?)
    }

    fn redeem_script_with_type(
        &self,
        in_type: InputType,
    ) -> Result<Option<bitcoin::ScriptBuf>, InputError> {
        match in_type {
            InputType::P2sh => {
                // redeem script is the last element of the script sig
                if let Some(instruction_result) = self.script_sig.instructions().last() {
                    let instruction = match instruction_result {
                        Ok(ins) => ins,
                        Err(e) => return Err(InputError::ScriptHashInfo(e)),
                    };
                    if let script::Instruction::PushBytes(push_bytes) = instruction {
                        return Ok(Some(bitcoin::ScriptBuf::from(
                            push_bytes.as_bytes().to_vec(),
                        )));
                    }
                }
                Ok(None)
            }
            InputType::P2shP2wsh | InputType::P2wsh => {
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
    fn get_type(&self) -> Result<InputType, InputError>;
    fn has_witness(&self) -> bool;

    fn is_scripthash_input(&self) -> Result<bool, InputError>;

    // detection:
    fn is_p2ms(&self, strict_der_sig: bool) -> Result<bool, InputError>;
    fn is_p2pk(&self, strict_der_sig: bool) -> Result<bool, InputError>;
    fn is_p2pkh(&self, strict_der_sig: bool) -> Result<bool, InputError>;
    fn is_p2sh(&self) -> Result<bool, InputError>;
    fn is_nested_p2wpkh(&self) -> bool;
    fn is_nested_p2wsh(&self) -> bool;
    fn is_p2wpkh(&self) -> bool;
    fn is_p2wsh(&self) -> bool;
    fn is_p2trkp(&self) -> bool;
    fn is_p2trsp(&self) -> bool;
    fn is_p2a(&self) -> bool;
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
    /// Pay-to-Anchor input
    P2a,
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
            InputType::P2a => write!(f, "P2A"),
            InputType::Coinbase => write!(f, "Coinbase"),
            InputType::CoinbaseWitness => write!(f, "Coinbase with Witness"),
            InputType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl InputTypeDetection for TxIn {
    fn get_type(&self) -> Result<InputType, InputError> {
        if self.has_witness() {
            // check for coinbase_wittness first as coinbases can have weird
            // input scripts which might cause an EarlyEndOfScript error in the
            // other checks.
            if self.is_coinbase_witness() {
                return Ok(InputType::CoinbaseWitness);
            } else if self.is_nested_p2wpkh() {
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
            }
            return Ok(InputType::Unknown);
        }

        // check for coinbase first as coinbases can have weird input scripts
        // which might cause an EarlyEndOfScript error in the other checks.
        if self.is_coinbase() {
            return Ok(InputType::Coinbase);
        }

        if self.script_sig.is_empty() {
            if self.is_p2a() {
                return Ok(InputType::P2a);
            }
            return Ok(InputType::Unknown);
        }

        // Parse script_sig instructions once and classify from the result,
        // avoiding redundant parsing in each is_p2* method.
        let instructions = match crate::script::instructions_as_vec(&self.script_sig) {
            Ok(ins) => ins,
            Err(e) => return Err(InputError::TypeInfo(e)),
        };

        // P2PKH: [ <ECDSA Signature> <PublicKey> ]
        if instructions.len() == 2 && instructions[1].is_pubkey() {
            if instructions[0].is_ecdsa_signature(/* strict DER */ true) {
                return Ok(InputType::P2pkh);
            }
            if instructions[0].is_ecdsa_signature(/* strict DER */ false) {
                return Ok(InputType::P2pkhLaxDer);
            }
        }

        // P2PK: [ <ECDSA Signature> ]
        if instructions.len() == 1 {
            if instructions[0].is_ecdsa_signature(/* strict DER */ true) {
                return Ok(InputType::P2pk);
            }
            if instructions[0].is_ecdsa_signature(/* strict DER */ false) {
                return Ok(InputType::P2pkLaxDer);
            }
        }

        // P2MS: [ OP_0 <ECDSA Signature> (<ECDSA Signature>) (<ECDSA Signature>) ]
        if instructions.len() >= 2 && instructions.len() <= 4 {
            if let script::Instruction::PushBytes(bytes) = &instructions[0] {
                if bytes.is_empty() {
                    let sigs = &instructions[1..];
                    if sigs
                        .iter()
                        .all(|i| i.is_ecdsa_signature(/* strict DER */ true))
                    {
                        return Ok(InputType::P2ms);
                    }
                    if sigs
                        .iter()
                        .all(|i| i.is_ecdsa_signature(/* strict DER */ false))
                    {
                        return Ok(InputType::P2msLaxDer);
                    }
                }
            }
        }

        // P2SH: anything else with a non-empty script_sig and no witness
        // (already ruled out P2PKH, P2PK, P2MS, coinbase above)
        Ok(InputType::P2sh)
    }

    /// Indicates if the witness contains data.
    fn has_witness(&self) -> bool {
        !self.witness.is_empty()
    }

    /// Indicates if the input is script hash based.
    fn is_scripthash_input(&self) -> Result<bool, InputError> {
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
    fn is_p2pk(&self, strict_der_sig: bool) -> Result<bool, InputError> {
        if self.has_witness() || self.script_sig.is_empty() {
            return Ok(false);
        }

        let instructions = match crate::script::instructions_as_vec(&self.script_sig) {
            Ok(ins) => ins,
            Err(e) => return Err(InputError::TypeInfo(e)),
        };
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
    fn is_p2ms(&self, strict_der_sig: bool) -> Result<bool, InputError> {
        if self.has_witness() {
            return Ok(false);
        }

        let instructions = match crate::script::instructions_as_vec(&self.script_sig) {
            Ok(ins) => ins,
            Err(e) => return Err(InputError::TypeInfo(e)),
        };

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
    fn is_p2pkh(&self, strict_der_sig: bool) -> Result<bool, InputError> {
        if self.has_witness() {
            return Ok(false);
        }

        let instructions = match crate::script::instructions_as_vec(&self.script_sig) {
            Ok(ins) => ins,
            Err(e) => return Err(InputError::TypeInfo(e)),
        };
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
    fn is_p2sh(&self) -> Result<bool, InputError> {
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
            && self
                .witness
                .nth(0)
                .unwrap()
                .is_ecdsa_signature(/* strict DER */ true)
            && self.witness.nth(1).unwrap().is_pubkey()
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

        if self
            .witness
            .nth(0)
            .unwrap()
            .is_ecdsa_signature(/* strict DER */ true)
            && self.witness.nth(1).unwrap().is_pubkey()
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
            return self.witness.nth(0).unwrap().is_schnorr_signature();
        } else if self.witness.len() == 2 {
            // with annex
            let second = self.witness.nth(1).unwrap();
            if !second.is_empty() && second[0] == TAPROOT_ANNEX_INDICATOR {
                return self.witness.nth(0).unwrap().is_schnorr_signature();
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

        // check for annex
        let last_element = self.witness.nth(last_witness_element_index).unwrap();
        if !last_element.is_empty() && last_element[0] == TAPROOT_ANNEX_INDICATOR {
            control_block_index -= 1;
        }

        // check for control block
        let control_block = self.witness.nth(control_block_index).unwrap();
        if control_block.len() < 1 + 32 || !(control_block.len() - 1).is_multiple_of(32) {
            return false;
        }

        if control_block[0] & TAPROOT_LEAF_MASK == TAPROOT_LEAF_TAPSCRIPT {
            return true;
        }

        false
    }

    /// Checks if an input spends a P2A output.
    ///
    /// A P2A output has an empty script_sig and an empty witness.
    fn is_p2a(&self) -> bool {
        self.script_sig.is_empty() && !self.has_witness()
    }

    /// Checks if an input is a coinbase without witness data.
    ///
    /// A coinbase has a an Outpoint with an all zero txid and an output index
    /// of 0xffffffff. The witness is empty.
    fn is_coinbase(&self) -> bool {
        !self.has_witness()
            && self.previous_output.vout == 0xffffffff
            && self.previous_output.is_null()
    }

    /// Checks if an input is a coinbase with witness data. On mainnet, this
    /// input type is expected after SegWit activation at height 481824
    /// (24 August 2017).
    ///
    /// A coinbase has a an Outpoint with an all zero txid and an output index
    /// of 0xffffffff. The witness is not empty.
    fn is_coinbase_witness(&self) -> bool {
        self.has_witness()
            && self.previous_output.vout == 0xffffffff
            && self.previous_output.is_null()
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
        if let Some(tapscript) = self.witness.taproot_leaf_script() {
            if let Ok(instructions) = instructions_as_vec(tapscript.script) {
                let mut instruction_iter = instructions.iter();
                while let Some(instruction) = instruction_iter.next() {
                    if matches!(instruction, Instruction::PushBytes(bytes) if bytes.is_empty())
                        && matches!(instruction_iter.next(), Some(Instruction::Op(op)) if op == &opcodes::OP_IF)
                        && matches!(instruction_iter.next(), Some(Instruction::PushBytes(bytes)) if bytes.as_bytes() == ORDINALS_INSCRIPTION_MARKER.to_vec())
                    {
                        return Ok(true);
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
        InputInfo, InputInscriptionDetection, InputMultisigDetection, InputSigops, InputType,
        InputTypeDetection, MultisigInputInfo,
    };
    use crate::testdata;
    use bitcoin::Transaction;

    fn decode_tx(hex: &str) -> Transaction {
        bitcoin::consensus::deserialize(&hex::decode(hex).unwrap()).unwrap()
    }

    #[test]
    fn reveals_inscription() {
        let tx = decode_tx(testdata::TX_INSCRIPTION);
        let in0 = &tx.input[0];
        assert!(in0.is_p2trsp());
        assert!(in0.reveals_inscription().unwrap());

        let tx = decode_tx(testdata::TX_INSCRIPTION_2);
        let in0 = &tx.input[0];
        assert!(in0.is_p2trsp());
        assert!(in0.reveals_inscription().unwrap());
    }

    #[test]
    fn input_type_detection_p2pk() {
        let tx = decode_tx(testdata::TX_P2PK);
        let in0 = &tx.input[0];
        assert!(in0.is_p2pk(true).unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2pk);
    }

    #[test]
    fn input_type_detection_p2pkh() {
        let tx = decode_tx(testdata::TX_P2PKH);
        let in0 = &tx.input[0];
        assert!(in0.is_p2pkh(true).unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2pkh);
    }

    #[test]
    fn input_type_detection_nested_p2wpkh() {
        let tx = decode_tx(testdata::TX_P2SH_P2WPKH);
        let in0 = &tx.input[0];
        assert!(in0.is_nested_p2wpkh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2shP2wpkh);
    }

    #[test]
    fn input_type_detection_p2wpkh() {
        let tx = decode_tx(testdata::TX_P2WPKH);
        let in0 = &tx.input[0];
        assert!(in0.is_p2wpkh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2wpkh);
    }

    #[test]
    fn input_type_detection_p2sh() {
        let tx = decode_tx(testdata::TX_P2SH);
        let in0 = &tx.input[0];
        assert!(in0.is_p2sh().unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2sh);
    }

    #[test]
    fn input_sigops_nonstandard_rsk_p2sh() {
        let tx = decode_tx(testdata::TX_P2SH_RSK);
        let in0 = &tx.input[0];
        assert!(in0.is_p2sh().unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2sh);
        assert_eq!(in0.sigops().unwrap(), 80);
    }

    #[test]
    fn input_type_detection_nested_p2wsh() {
        let tx = decode_tx(testdata::TX_P2SH_P2WSH);
        let in0 = &tx.input[0];
        assert!(in0.is_nested_p2wsh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2shP2wsh);
    }

    #[test]
    fn input_type_detection_p2ms_1of2() {
        let tx = decode_tx(testdata::TX_P2MS_1OF2);
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
        let tx = decode_tx(testdata::TX_P2MS_2OF3);
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
    fn input_type_detection_unknown() {
        let tx = decode_tx(testdata::TX_UNKNOWN_INPUT);
        let in0 = &tx.input[0];
        assert!(in0.is_p2sh().unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2sh);
    }

    #[test]
    fn input_type_detection_p2wsh_2of2() {
        let tx = decode_tx(testdata::TX_P2WSH);
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
        let tx = decode_tx(testdata::TX_P2WSH_NON_MULTISIG);
        let in0 = &tx.input[0];
        assert!(in0.is_p2wsh());
        assert_eq!(in0.get_type().unwrap(), InputType::P2wsh);
        assert_eq!(in0.multisig_info().unwrap(), None);
    }

    #[test]
    fn coinbase_input_detection() {
        let tx = decode_tx(testdata::TX_COINBASE);
        let in0 = &tx.input[0];
        assert!(in0.is_coinbase());
        assert_eq!(in0.get_type().unwrap(), InputType::Coinbase);
    }

    #[test]
    fn coinbase_input_detection2() {
        let tx = decode_tx(testdata::TX_COINBASE_2);
        let in0 = &tx.input[0];
        assert!(in0.is_coinbase());
        assert_eq!(in0.get_type().unwrap(), InputType::Coinbase);
    }

    #[test]
    fn p2trkp_input_detection() {
        let tx = decode_tx(testdata::TX_P2TRKP);
        let in0 = &tx.input[0];
        assert!(in0.is_p2trkp());
        assert_eq!(in0.get_type().unwrap(), InputType::P2trkp);
        assert!(InputInfo::new(in0).unwrap().is_spending_taproot());
        assert!(InputInfo::new(in0).unwrap().is_spending_segwit());
    }

    #[test]
    fn p2trsp_input_detection() {
        let tx = decode_tx(testdata::TX_P2TRSP);
        let in0 = &tx.input[0];
        assert!(in0.is_p2trsp());
        assert_eq!(in0.get_type().unwrap(), InputType::P2trsp);
        assert!(InputInfo::new(in0).unwrap().is_spending_taproot());
        assert!(InputInfo::new(in0).unwrap().is_spending_segwit());
        assert!(!in0.reveals_inscription().unwrap());
    }

    #[test]
    fn p2a_input_detection() {
        let tx = decode_tx(testdata::TX_P2A);
        let in0 = &tx.input[0];
        assert!(in0.is_p2a());
        assert_eq!(in0.get_type().unwrap(), InputType::P2a);
        assert!(!InputInfo::new(in0).unwrap().is_spending_taproot());
        assert!(InputInfo::new(in0).unwrap().is_spending_segwit());
        assert!(!in0.reveals_inscription().unwrap());
    }

    #[test]
    fn coinbase_witness_input_detection() {
        let tx = decode_tx(testdata::TX_COINBASE_WITNESS);
        let in0 = &tx.input[0];
        assert!(in0.is_coinbase_witness());
        assert_eq!(in0.get_type().unwrap(), InputType::CoinbaseWitness);
    }

    #[test]
    fn non_der_sig_p2pkh_input_detection() {
        let tx = decode_tx(testdata::TX_P2PKH_LAX_DER);
        let in0 = &tx.input[0];
        assert!(in0.is_p2pkh(false).unwrap());
        assert_eq!(in0.get_type().unwrap(), InputType::P2pkhLaxDer);
    }
}
