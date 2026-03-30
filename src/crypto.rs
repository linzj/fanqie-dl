use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::read::ZlibDecoder;
use std::io::Read;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const HARDCODED_KEY: &str = "ac25c67ddd8f38c1b37a2348828e222e";

/// po4.a.g(): hex string → byte array
fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s.to_lowercase()).expect("invalid hex string")
}

/// po4.a.a(): byte array → uppercase hex string
fn bytes_to_hex_upper(bytes: &[u8]) -> String {
    hex::encode(bytes).to_uppercase()
}

/// po4.a.b(): IV string → pad/truncate to 16 bytes UTF-8
fn make_iv_from_string(s: &str) -> [u8; 16] {
    let mut buf = String::with_capacity(16);
    buf.push_str(s);
    while buf.len() < 16 {
        buf.push('0');
    }
    buf.truncate(16);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&buf.as_bytes()[..16]);
    iv
}

/// po4.a.h(): long → 8 bytes LITTLE-ENDIAN (as per app behavior)
fn long_to_bytes(v: i64) -> [u8; 8] {
    v.to_le_bytes()
}

/// po4.a.f(): AES/CBC/PKCS5 encrypt
fn aes_encrypt(data: &[u8], hex_key: &str, iv_str: &str) -> Vec<u8> {
    let key_bytes = hex_to_bytes(hex_key);
    let iv = make_iv_from_string(iv_str);
    let cipher = Aes128CbcEnc::new(key_bytes[..16].into(), &iv.into());
    cipher.encrypt_padded_vec_mut::<Pkcs7>(data)
}

/// po4.a.e(): AES/CBC/PKCS5 decrypt with raw IV bytes
fn aes_decrypt(data: &[u8], hex_key: &str, iv_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key_bytes = hex_to_bytes(hex_key);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_bytes[..16]);
    let cipher = Aes128CbcDec::new(key_bytes[..16].into(), &iv.into());
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|e| anyhow::anyhow!("AES decrypt failed: {}", e))
}

/// md5.i.n(): Build register key request content field
pub fn build_register_content(device_id: &str, user_id: &str) -> String {
    let did: i64 = device_id.parse().unwrap_or(0);
    let uid: i64 = user_id.parse().unwrap_or(0);

    // po4.a.h() + po4.a.i(): little-endian bytes concat
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&long_to_bytes(did));
    payload.extend_from_slice(&long_to_bytes(uid));

    // po4.a.d(): UUID first 16 chars
    let uuid_str = uuid::Uuid::new_v4().to_string();
    let iv_text = &uuid_str[..16];

    // AES encrypt
    let ciphertext = aes_encrypt(&payload, HARDCODED_KEY, iv_text);

    // Prepend IV bytes + ciphertext, then Base64
    let iv_bytes = iv_text.as_bytes();
    let mut result = Vec::with_capacity(iv_bytes.len() + ciphertext.len());
    result.extend_from_slice(iv_bytes);
    result.extend_from_slice(&ciphertext);

    STANDARD.encode(&result)
}

/// md5.i.k() + po4.a.a(): Decrypt server-returned V1 key
pub fn decrypt_server_key(encrypted_key: &str) -> anyhow::Result<String> {
    let decoded = STANDARD.decode(encrypted_key)?;
    if decoded.len() < 17 {
        anyhow::bail!("encrypted key too short: {} bytes", decoded.len());
    }
    let iv = &decoded[..16];
    let ciphertext = &decoded[16..];
    let plaintext = aes_decrypt(ciphertext, HARDCODED_KEY, iv)?;
    Ok(bytes_to_hex_upper(&plaintext))
}

/// Decrypt chapter content
pub fn decrypt_content(encrypted_content: &str, v1_key: &str) -> anyhow::Result<Vec<u8>> {
    let decoded = STANDARD.decode(encrypted_content)?;
    if decoded.len() < 17 {
        anyhow::bail!("encrypted content too short: {} bytes", decoded.len());
    }
    let iv = &decoded[..16];
    let ciphertext = &decoded[16..];
    aes_decrypt(ciphertext, v1_key, iv)
}

/// Zlib decompress
pub fn decompress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_content_with_known_iv() {
        // Test vector from frida extraction:
        // device_id=643680972856619, user_id=0, iv="1234567890123456"
        // Expected encrypted_b64 = "ZP2XdeSDM3KDRSNUkLymVJLIwszXgyVkcy+1SDlZP+I="
        // Expected content = "MTIzNDU2Nzg5MDEyMzQ1NmT9l3XkgzNyg0UjVJC8plSSyMLM14MlZHMvtUg5WT/i"

        let did: i64 = 643680972856619;
        let uid: i64 = 0;
        let mut payload = Vec::new();
        payload.extend_from_slice(&did.to_le_bytes());
        payload.extend_from_slice(&uid.to_le_bytes());

        assert_eq!(hex::encode(&payload), "2b5dbca76c4902000000000000000000");

        let encrypted = aes_encrypt(&payload, HARDCODED_KEY, "1234567890123456");
        assert_eq!(
            hex::encode(&encrypted),
            "64fd9775e48333728345235490bca65492c8c2ccd7832564732fb54839593fe2"
        );

        let iv_bytes = "1234567890123456".as_bytes();
        let mut combined = Vec::new();
        combined.extend_from_slice(iv_bytes);
        combined.extend_from_slice(&encrypted);
        let content = STANDARD.encode(&combined);
        assert_eq!(
            content,
            "MTIzNDU2Nzg5MDEyMzQ1NmT9l3XkgzNyg0UjVJC8plSSyMLM14MlZHMvtUg5WT/i"
        );
    }
}
