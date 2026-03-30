//! X-Ladon signature algorithm (Speck-like cipher).

use base64::{engine::general_purpose::STANDARD, Engine};
use rand::Rng;

fn ror64(value: u64, count: u32) -> u64 {
    let count = count % 64;
    (value >> count) | (value << (64 - count))
}

fn validate(num: u64) -> u64 {
    num & 0xFFFFFFFFFFFFFFFF
}

fn encrypt_ladon_input(hash_table: &[u8], input_data: &[u8]) -> Vec<u8> {
    let mut data0 = u64::from_le_bytes(input_data[..8].try_into().unwrap());
    let mut data1 = u64::from_le_bytes(input_data[8..16].try_into().unwrap());

    for i in 0..0x22u64 {
        let hash = u64::from_le_bytes(
            hash_table[i as usize * 8..(i as usize + 1) * 8]
                .try_into()
                .unwrap(),
        );
        data1 = validate(hash ^ data0.wrapping_add(ror64(data1, 8)));
        data0 = validate(data1 ^ ror64(data0, 0x3D));
    }

    let mut output = vec![0u8; 26]; // Python uses 26 but only fills 16
    output[..8].copy_from_slice(&data0.to_le_bytes());
    output[8..16].copy_from_slice(&data1.to_le_bytes());
    output
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut result = data.to_vec();
    result.resize(data.len() + pad_len, pad_len as u8);
    result
}

fn padding_size(size: usize) -> usize {
    let m = size % 16;
    if m > 0 {
        size + (16 - m)
    } else {
        size
    }
}

fn encrypt_ladon(md5hex: &[u8], data: &[u8], size: usize) -> Vec<u8> {
    let mut hash_table = vec![0u8; 272 + 16];
    hash_table[..32].copy_from_slice(&md5hex[..32]);

    let mut temp: Vec<u64> = Vec::new();
    for i in 0..4 {
        temp.push(u64::from_le_bytes(
            hash_table[i * 8..(i + 1) * 8].try_into().unwrap(),
        ));
    }

    let mut buffer_b0 = temp[0];
    let mut buffer_b8 = temp[1];
    temp.remove(0);
    temp.remove(0);

    for i in 0..0x22u64 {
        let x9 = buffer_b0;
        let mut x8 = buffer_b8;
        x8 = validate(ror64(x8, 8));
        x8 = validate(x8.wrapping_add(x9));
        x8 = validate(x8 ^ i);
        temp.push(x8);
        x8 = validate(x8 ^ ror64(x9, 61));
        hash_table[(i as usize + 1) * 8..(i as usize + 2) * 8].copy_from_slice(&x8.to_le_bytes());
        buffer_b0 = x8;
        buffer_b8 = temp[0];
        temp.remove(0);
    }

    let new_size = padding_size(size);
    let padded = pkcs7_pad(data, 16);

    let mut output = vec![0u8; new_size];
    for i in 0..(new_size / 16) {
        let block = encrypt_ladon_input(&hash_table, &padded[i * 16..(i + 1) * 16]);
        output[i * 16..i * 16 + 16].copy_from_slice(&block[..16]);
    }

    output
}

/// Generate X-Ladon header value.
pub fn encrypt(khronos: u64, lc_id: u64, aid: u32) -> String {
    let data = format!("{}-{}-{}", khronos, lc_id, aid);

    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 4] = rng.gen();

    let mut keygen = random_bytes.to_vec();
    keygen.extend_from_slice(aid.to_string().as_bytes());

    let md5hex = format!("{:x}", md5::compute(&keygen));

    let size = data.len();
    let new_size = padding_size(size);

    let encrypted = encrypt_ladon(md5hex.as_bytes(), data.as_bytes(), size);

    let mut output = Vec::with_capacity(new_size + 4);
    output.extend_from_slice(&random_bytes);
    output.extend_from_slice(&encrypted);

    STANDARD.encode(&output)
}
