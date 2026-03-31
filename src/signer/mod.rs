//! Native signing via ARM64 emulation of libmetasec_ml.so
//! Uses Unicorn Engine to execute the signing code from the dumped SO.

mod emulator;

use std::collections::HashMap;

/// Sign a request URL, returns headers (X-Helios, X-Medusa, etc.)
pub fn sign_request(url: &str) -> HashMap<String, String> {
    emulator::sign(url)
}
