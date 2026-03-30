//! Request signing via embedded Python signer.
//! Calls python_signer/sign.py as subprocess.

use std::collections::HashMap;
use std::process::Command;

/// Sign request parameters, returns headers map.
pub fn sign_request(params: &str, body: Option<&str>, _timestamp: u64) -> HashMap<String, String> {
    // Build JSON input for Python signer
    let mut input = serde_json::json!({
        "params": params,
        "aid": 1967,
    });
    if let Some(b) = body {
        input["body"] = serde_json::Value::String(b.to_string());
    }

    let input_str = input.to_string();

    // Find python_signer/sign.py relative to executable
    let signer_paths = [
        "python_signer/sign.py".to_string(),
        "../python_signer/sign.py".to_string(),
        format!(
            "{}/python_signer/sign.py",
            std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
        ),
    ];

    let signer_path = signer_paths
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .cloned()
        .unwrap_or_else(|| "python_signer/sign.py".to_string());

    // Call Python signer
    let signer_dir = std::path::Path::new(&signer_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));

    match Command::new("python3")
        .arg(&signer_path)
        .current_dir(signer_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = writeln!(stdin, "{}", input_str);
            }

            match child.wait_with_output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    match serde_json::from_str::<HashMap<String, String>>(stdout.trim()) {
                        Ok(headers) => return headers,
                        Err(e) => {
                            eprintln!("[signer] JSON parse error: {}", e);
                        }
                    }
                }
                Err(e) => eprintln!("[signer] process error: {}", e),
            }
        }
        Err(e) => {
            // Fallback: try "python" instead of "python3"
            if let Ok(mut child) = Command::new("python")
                .arg(&signer_path)
                .current_dir(signer_dir)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = writeln!(stdin, "{}", input_str);
                }
                if let Ok(output) = child.wait_with_output() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if let Ok(headers) =
                        serde_json::from_str::<HashMap<String, String>>(stdout.trim())
                    {
                        return headers;
                    }
                }
            }
            eprintln!("[signer] failed to run python: {}", e);
        }
    }

    // Empty fallback
    HashMap::new()
}
