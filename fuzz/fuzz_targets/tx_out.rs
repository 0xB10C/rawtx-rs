#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rawtx_rs_fuzz::fuzz_tx_out(data));
