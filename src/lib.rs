//! rawtx-rs makes information about Bitcoin transactions accessible.
//!
//! # Examples
//!
//! ```
//! # use bitcoin::Transaction;
//! # use bitcoin::consensus::deserialize;
//! # use rawtx_rs::{tx, input, output};
//! // The first Bitcoin mainnet transaction between Satoshi and Hal
//! // f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
//! // as rust-bitcoin's bitcoin::Transaction.
//! # let tx_bytes = hex::decode("0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000").unwrap();
//! # let tx: Transaction = deserialize(&tx_bytes).unwrap();
//! let tx_info = tx::TxInfo::new(&tx).unwrap();
//!
//! assert_eq!(tx_info.input_infos[0].in_type, input::InputType::P2pk);
//! assert_eq!(tx_info.output_infos[0].out_type, output::OutputType::P2pk);
//! assert_eq!(tx_info.output_infos[1].out_type, output::OutputType::P2pk);
//!
//! assert!(!tx_info.is_spending_segwit());
//! assert!(tx_info.is_bip69_compliant());
//! ```
//!
//! ```
//! # use bitcoin::Transaction;
//! # use bitcoin::consensus::deserialize;
//! # use rawtx_rs::{tx, input, output};
//! // Random mainnet transaction spending SegWit and MultiSig
//! // 7874eb36dfff6d4d38f9dbe013bceed0c31de4da1dee4a507b9abd0540aa0af4
//! // as rust-bitcoin's bitcoin::Transaction.
//! # let tx_bytes = hex::decode("01000000000101c5633dd78147d06d9ef22da883c3f35cd1d6546218854a24b6da908d1650e052010000002322002090a0daaae7ab4d2fe9737db9ea7f9b5a63dfa083cc457adf1e324167d78f1dedfdffffff02103812000000000017a914652d1b1ffc7b5216adc7fa4d0ad4c66d3108b62a879d650e2d0000000017a914d926964e36a008a5e31c6c89f3abb9c7382b6f228704004830450221008005a978a9181739691770d6e483b6c15111a8e15218b2d542c5e1e03329c08c022021bff99948a14e2517ac2f735fed1c2d4b8bc4f614d37809a5c62ac4a471c13b0148304502210097cdd57f3aef21e4b3d0910c34bf5cb9799b206a97b79a1eac5719bf1520f63c02207f0f1afe378f3d0c57914814536e82a81d8d5454a4acfef3da3722d2a859d72f018b5221025be8b2946f6e86c16b65ed1f055980940dd67931029af24a5719ba8be779a9df21025d28dc125e50efff8767536c11e7119b578d2138000b43dd12969282792a06f92102ef98444f928b2fc9dc4d248bf5c550ead2e4527eaf0fb4ac2864f267c830d60f21034434478a4a7b6963d678468bc996304316ff953c266a18051898fda11d1c511454ae00000000").unwrap();
//! # let tx: Transaction = deserialize(&tx_bytes).unwrap();
//! let tx_info = tx::TxInfo::new(&tx).unwrap();
//!
//! assert_eq!(tx_info.input_infos[0].in_type, input::InputType::P2shP2wsh);
//! assert_eq!(tx_info.output_infos[0].out_type, output::OutputType::P2sh);
//! assert_eq!(tx_info.output_infos[1].out_type, output::OutputType::P2sh);
//!
//! assert!(tx_info.is_spending_segwit());
//! assert!(tx_info.is_bip69_compliant());
//! assert!(tx_info.is_signaling_explicit_rbf_replicability());
//! assert!(tx_info.is_spending_multisig());
//!
//! let multisig_info = tx_info.input_infos[0].multisig_info.as_ref().unwrap();
//!
//! // 2 of 4 multisig
//! assert_eq!(multisig_info.m_of_n, (2, 4));
//! ```

pub mod input;
pub mod output;
pub mod script;
pub mod timelock;
pub mod tx;

pub extern crate bitcoin;
