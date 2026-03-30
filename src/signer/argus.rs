//! X-Argus signature algorithm.

use super::protobuf::{self, ProtoValue};
use super::simon;
use super::sm3;
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::Rng;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

const SIGN_KEY: [u8; 32] = [
    0xac, 0x1a, 0xda, 0xae, 0x95, 0xa7, 0xaf, 0x94, 0xa5, 0x11, 0x4a, 0xb3, 0xb3, 0xa9, 0x7d, 0xd8,
    0x00, 0x50, 0xaa, 0x0a, 0x39, 0x31, 0x4c, 0x40, 0x52, 0x8c, 0xae, 0xc9, 0x52, 0x56, 0xc2, 0x8c,
];

// Precomputed: SM3(SIGN_KEY + b'\xf2\x81ao' + SIGN_KEY)
const SM3_OUTPUT: [u8; 32] = [
    0xfc, 0x78, 0xe0, 0xa9, 0x65, 0x7a, 0x0c, 0x74, 0x8c, 0xe5, 0x15, 0x59, 0x90, 0x3c, 0xcf, 0x03,
    0x51, 0x0e, 0x51, 0xd3, 0xcf, 0xf2, 0x32, 0xd7, 0x13, 0x43, 0xe8, 0x8a, 0x32, 0x1c, 0x53, 0x04,
];

fn get_bodyhash(stub: Option<&str>) -> Vec<u8> {
    match stub {
        Some(s) if !s.is_empty() => {
            let bytes = hex::decode(s).unwrap_or_else(|_| vec![0u8; 16]);
            sm3::sm3_hash(&bytes)[..6].to_vec()
        }
        _ => sm3::sm3_hash(&[0u8; 16])[..6].to_vec(),
    }
}

fn get_queryhash(query: Option<&str>) -> Vec<u8> {
    match query {
        Some(s) if !s.is_empty() => sm3::sm3_hash(s.as_bytes())[..6].to_vec(),
        _ => sm3::sm3_hash(&[0u8; 16])[..6].to_vec(),
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

    // Simon encrypt each 16-byte block
    let key = &SM3_OUTPUT[..32];
    let mut key_list = [0u64; 4];
    for i in 0..2 {
        key_list[i * 2] = u64::from_le_bytes(key[i * 16..i * 16 + 8].try_into().unwrap());
        key_list[i * 2 + 1] = u64::from_le_bytes(key[i * 16 + 8..i * 16 + 16].try_into().unwrap());
    }

    let mut enc_pb = vec![0u8; new_len];
    for i in 0..(new_len / 16) {
        let pt = [
            u64::from_le_bytes(protobuf_padded[i * 16..i * 16 + 8].try_into().unwrap()),
            u64::from_le_bytes(protobuf_padded[i * 16 + 8..i * 16 + 16].try_into().unwrap()),
        ];
        let ct = simon::simon_enc(pt, &key_list);
        enc_pb[i * 16..i * 16 + 8].copy_from_slice(&ct[0].to_le_bytes());
        enc_pb[i * 16 + 8..i * 16 + 16].copy_from_slice(&ct[1].to_le_bytes());
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

    // AES-CBC encrypt with MD5-derived key and IV
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
        (1, ProtoValue::Varint(0x20200929u64 << 1)),     // magic
        (2, ProtoValue::Varint(2)),                      // version
        (3, ProtoValue::Varint(rand_val as u64)),        // rand
        (4, ProtoValue::Utf8(aid.to_string())),          // msAppID
        (5, ProtoValue::Utf8(device_id.to_string())),    // deviceID
        (6, ProtoValue::Utf8(license_id.to_string())),   // licenseID
        (7, ProtoValue::Utf8(version_name.to_string())), // appVersion
        (8, ProtoValue::Utf8("v04.04.05-ov-android".to_string())), // sdkVersionStr
        (9, ProtoValue::Varint(134744640)),              // sdkVersion
        (10, ProtoValue::Bytes(vec![0u8; 8])),           // envcode
        (11, ProtoValue::Varint(0)),                     // platform (android=0)
        (12, ProtoValue::Varint(timestamp << 1)),        // createTime
        (13, ProtoValue::Bytes(get_bodyhash(data))),     // bodyHash
        (14, ProtoValue::Bytes(get_queryhash(Some(queryhash)))), // queryHash
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
