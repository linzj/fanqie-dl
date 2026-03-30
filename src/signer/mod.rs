//! Pure Rust request signing (X-Gorgon, X-Argus, X-Ladon, X-Khronos).
//! Replaces the previous Python subprocess signer.

mod argus;
mod gorgon;
mod ladon;
mod protobuf;
mod simon;
mod sm3;

use std::collections::HashMap;

/// Sign request parameters, returns headers map.
pub fn sign_request(
    params: &str,
    body: Option<&str>,
    timestamp: u64,
    device_id: &str,
    version_name: &str,
) -> HashMap<String, String> {
    let mut headers = HashMap::new();

    // X-Gorgon
    let data_str = body.unwrap_or("");
    headers.insert(
        "X-Gorgon".to_string(),
        gorgon::get_xgorgon(params, data_str, "", timestamp),
    );

    // X-Khronos
    headers.insert("X-Khronos".to_string(), timestamp.to_string());

    // X-SS-REQ-TICKET
    headers.insert(
        "X-SS-REQ-TICKET".to_string(),
        (timestamp * 1000).to_string(),
    );

    // X-SS-STUB (MD5 of body)
    let stub = if let Some(b) = body {
        if !b.is_empty() {
            let hash = format!("{:x}", md5::compute(b.as_bytes()));
            headers.insert("X-SS-STUB".to_string(), hash.clone());
            Some(hash)
        } else {
            None
        }
    } else {
        None
    };

    // X-Argus
    headers.insert(
        "X-Argus".to_string(),
        argus::get_sign(
            params,
            stub.as_deref(),
            timestamp,
            1967,
            device_id,
            version_name,
        ),
    );

    // X-Ladon
    headers.insert(
        "X-Ladon".to_string(),
        ladon::encrypt(timestamp, 1611921764, 1967),
    );

    headers
}
