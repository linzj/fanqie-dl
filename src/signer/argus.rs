//! X-Argus signature algorithm.
//!
//! Reverse-engineered from libmetasec_ml.so (Fanqie Novel v7.1.3.32).
//! Key differences from TikTok community algorithm:
//! - Uses SHA-256 instead of SM3 for hashing
//! - Uses AES-128-ECB instead of Simon-128/256 for inner protobuf encryption

use super::protobuf::{self, ProtoValue};
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use aes::cipher::{BlockEncrypt, KeyInit};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::Rng;
use sha2::{Digest, Sha256};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

const SIGN_KEY: [u8; 32] = [
    0xac, 0x1a, 0xda, 0xae, 0x95, 0xa7, 0xaf, 0x94, 0xa5, 0x11, 0x4a, 0xb3, 0xb3, 0xa9, 0x7d,
    0xd8, 0x00, 0x50, 0xaa, 0x0a, 0x39, 0x31, 0x4c, 0x40, 0x52, 0x8c, 0xae, 0xc9, 0x52, 0x56,
    0xc2, 0x8c,
];

/// Compute SHA-256(SIGN_KEY + salt + SIGN_KEY) for AES inner encryption key derivation.
/// This replaces the SM3-based key derivation used in the TikTok community algorithm.
fn derive_inner_key() -> [u8; 32] {
    let salt: [u8; 4] = [0xf2, 0x81, 0x61, 0x6f]; // b'\xf2\x81ao'
    let mut hasher = Sha256::new();
    hasher.update(&SIGN_KEY);
    hasher.update(&salt);
    hasher.update(&SIGN_KEY);
    hasher.finalize().into()
}

fn get_bodyhash(stub: Option<&str>) -> Vec<u8> {
    match stub {
        Some(s) if !s.is_empty() => {
            let bytes = hex::decode(s).unwrap_or_else(|_| vec![0u8; 16]);
            let hash = Sha256::digest(&bytes);
            hash[..6].to_vec()
        }
        _ => {
            let hash = Sha256::digest(&[0u8; 16]);
            hash[..6].to_vec()
        }
    }
}

fn get_queryhash(query: Option<&str>) -> Vec<u8> {
    match query {
        Some(s) if !s.is_empty() => {
            let hash = Sha256::digest(s.as_bytes());
            hash[..6].to_vec()
        }
        _ => {
            let hash = Sha256::digest(&[0u8; 16]);
            hash[..6].to_vec()
        }
    }
}

fn encrypt_enc_pb(data: &[u8], l: usize) -> Vec<u8> {
    let mut d = data.to_vec();
    let xor_array: Vec<u8> = d[..8].to_vec();
    for i in 8..l {
        d[i] ^= xor_array[i % 8];
    }
    d.reverse();
    d
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut result = data.to_vec();
    result.resize(data.len() + pad_len, pad_len as u8);
    result
}

fn encrypt_argus(xargus_bean: &[(u32, ProtoValue)]) -> String {
    let pb_bytes = protobuf::encode_dict(xargus_bean);
    let protobuf_padded = pkcs7_pad(&pb_bytes, 16);
    let new_len = protobuf_padded.len();

    // Derive the inner encryption key using SHA-256 (replaces SM3)
    let derived_key = derive_inner_key();

    // AES-128-ECB encrypt each 16-byte block (replaces Simon-128/256)
    // Use first 16 bytes of SHA-256 output as AES-128 key
    let aes_inner_key = aes::Aes128::new_from_slice(&derived_key[..16]).unwrap();

    let mut enc_pb = vec![0u8; new_len];
    for i in 0..(new_len / 16) {
        let mut block = aes::Block::clone_from_slice(&protobuf_padded[i * 16..(i + 1) * 16]);
        aes_inner_key.encrypt_block(&mut block);
        enc_pb[i * 16..(i + 1) * 16].copy_from_slice(&block);
    }

    // XOR transform
    let mut prefixed = Vec::with_capacity(8 + new_len);
    prefixed.extend_from_slice(&[0xf2, 0xf7, 0xfc, 0xff, 0xf2, 0xf7, 0xfc, 0xff]);
    prefixed.extend_from_slice(&enc_pb);
    let b_buffer_inner = encrypt_enc_pb(&prefixed, new_len + 8);

    let mut b_buffer = Vec::new();
    b_buffer.extend_from_slice(&[0xa6, 0x6e, 0xad, 0x9f, 0x77, 0x01, 0xd0, 0x0c, 0x18]);
    b_buffer.extend_from_slice(&b_buffer_inner);
    b_buffer.extend_from_slice(b"ao");

    // AES-CBC encrypt with MD5-derived key and IV (same as community)
    let aes_key = md5::compute(&SIGN_KEY[..16]);
    let aes_iv = md5::compute(&SIGN_KEY[16..]);

    let cipher = Aes128CbcEnc::new(aes_key.as_slice().into(), aes_iv.as_slice().into());
    let padded_buf = pkcs7_pad(&b_buffer, 16);
    let encrypted = cipher.encrypt_padded_vec_mut::<Pkcs7>(&padded_buf);

    let mut result = Vec::with_capacity(2 + encrypted.len());
    result.extend_from_slice(&[0xf2, 0x81]);
    result.extend_from_slice(&encrypted);

    STANDARD.encode(&result)
}

/// Generate X-Argus header value.
pub fn get_sign(
    queryhash: &str,
    data: Option<&str>,
    timestamp: u64,
    aid: u32,
    device_id: &str,
    version_name: &str,
) -> String {
    let mut rng = rand::thread_rng();
    let rand_val: u32 = rng.gen_range(0..0x7FFFFFFF);
    let license_id: u64 = 1611921764;

    let fields: Vec<(u32, ProtoValue)> = vec![
        (1, ProtoValue::Varint(0x20200929u64 << 1)), // magic
        (2, ProtoValue::Varint(2)),                   // version
        (3, ProtoValue::Varint(rand_val as u64)),     // rand
        (4, ProtoValue::Utf8(aid.to_string())),       // msAppID
        (5, ProtoValue::Utf8(device_id.to_string())), // deviceID
        (6, ProtoValue::Utf8(license_id.to_string())), // licenseID
        (7, ProtoValue::Utf8(version_name.to_string())), // appVersion
        (
            8,
            ProtoValue::Utf8("v04.04.05-ov-android".to_string()),
        ), // sdkVersionStr
        (9, ProtoValue::Varint(134744640)),           // sdkVersion
        (10, ProtoValue::Bytes(vec![0u8; 8])),        // envcode
        (11, ProtoValue::Varint(0)),                  // platform (android=0)
        (12, ProtoValue::Varint(timestamp << 1)),     // createTime
        (13, ProtoValue::Bytes(get_bodyhash(data))),  // bodyHash (SHA-256)
        (
            14,
            ProtoValue::Bytes(get_queryhash(Some(queryhash))),
        ), // queryHash (SHA-256)
        (
            15,
            ProtoValue::Dict(vec![
                (1, ProtoValue::Varint(1)),          // signCount
                (2, ProtoValue::Varint(1)),          // reportCount
                (3, ProtoValue::Varint(1)),          // settingCount
                (7, ProtoValue::Varint(3348294860)), // ?
            ]),
        ),
        (16, ProtoValue::Utf8(String::new())), // secDeviceToken
        (20, ProtoValue::Utf8("none".to_string())), // pskVersion
        (21, ProtoValue::Varint(738)),         // callType
        (
            23,
            ProtoValue::Dict(vec![
                (1, ProtoValue::Utf8("NX551J".to_string())),
                (2, ProtoValue::Varint(8196)),
                (4, ProtoValue::Varint(2162219008)),
            ]),
        ),
        (25, ProtoValue::Varint(2)),
    ];

    encrypt_argus(&fields)
}
