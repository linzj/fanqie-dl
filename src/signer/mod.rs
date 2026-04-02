//! Signing implementation: Rust for known crypto, Unicorn only for Helios CFF code.
//!
//! Known parts (pure Rust):
//! - MD5(URL params) → H0
//! - Random R, MD5(R+"1967") → H1
//! - MD5(session_uuid+"0") → H2
//! - MD5("1967"+magic+"1967") → H3 = AES key
//! - AES-128 key expand + ECB×17 → Medusa keystream
//! - SHA-1(AES_out[0:4] + "1967" + magic)
//! - MD5(constant1) → H4, MD5(constant2) → H5
//! - Medusa header + body assembly
//! - Base64 encoding
//!
//! Unknown part (Unicorn emulation):
//! - Helios part1/part2 generation (CFF inline code)

pub mod emulator;
mod native_exec;

use std::collections::HashMap;

pub fn sign_request(url_query: &str) -> HashMap<String, String> {
    emulator::sign(url_query)
}
