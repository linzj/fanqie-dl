use crate::crypto;
use crate::device::DeviceConfig;
use anyhow::Result;
use rand::Rng;
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// User-Agent per ISSUE.md (matches emulator app)
const USER_AGENT: &str = "com.dragon.read/71332 (Linux; U; Android 15; zh_CN; sdk_gphone64_arm64; Build/AP3A.241105.008;tt-ok/3.12.13.20)";

pub struct FanqieClient {
    client: Client,
    base_url: String,
    pub config: DeviceConfig,
}

impl FanqieClient {
    pub async fn new() -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .gzip(true)
            .timeout(Duration::from_secs(30))
            .build()?;

        let mut config = DeviceConfig::load_or_create()?;

        // Register device if needed
        if config.device_id.is_empty() || config.device_id == "0" {
            println!("注册设备...");
            let (did, iid) = Self::register_device(&client, &config).await?;
            config.device_id = did;
            config.iid = iid;
            config.save()?;
            println!("  device_id: {}", config.device_id);
        } else {
            println!("已有设备: {}", config.device_id);
        }

        let mut me = Self {
            client,
            base_url: "https://api5-normal-sinfonlinec.fqnovel.com".into(),
            config,
        };

        // Register encryption key if needed
        if me.config.v1_key.is_empty() {
            println!("注册密钥...");
            match me.register_encryption_key().await {
                Ok(key) => {
                    me.config.v1_key = key;
                    me.config.save()?;
                    println!(
                        "  v1_key: {}...",
                        &me.config.v1_key[..8.min(me.config.v1_key.len())]
                    );
                }
                Err(e) => eprintln!("  密钥注册失败: {}", e),
            }
        } else {
            println!(
                "已有密钥: {}...",
                &me.config.v1_key[..8.min(me.config.v1_key.len())]
            );
        }

        Ok(me)
    }

    pub fn v1_key(&self) -> &str {
        &self.config.v1_key
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Register device with ByteDance (no signing needed)
    async fn register_device(client: &Client, config: &DeviceConfig) -> Result<(String, String)> {
        let body = serde_json::json!({
            "magic_tag": "ss_app_log",
            "header": {
                "display_name": "novelapp",
                "update_version_code": 71332, "manifest_version_code": 71332,
                "aid": 1967, "channel": "googleplay", "package": "com.dragon.read",
                "app_name": "novelapp", "version_code": 71332, "version_name": "7.1.3.32",
                "device_model": "sdk_gphone64_arm64", "device_brand": "google",
                "device_manufacturer": "Google", "os_version": "15", "os_api": 35,
                "device_platform": "android", "language": "zh", "region": "CN",
                "resolution": "1080x2160", "dpi": 420,
                "rom_version": "PQ3B.190801.002",
                "cdid": &config.cdid, "openudid": &config.openudid,
            },
            "_gen_time": Self::now_secs(),
        });

        for &url in &[
            "https://log.snssdk.com/service/2/device_register/",
            "https://log.isnssdk.com/service/2/device_register/",
        ] {
            match client.post(url).json(&body).send().await {
                Ok(resp) => {
                    let v: serde_json::Value = resp.json().await?;
                    let did = extract_id(&v, "device_id");
                    let iid = extract_id(&v, "install_id");
                    if did != "0" && !did.is_empty() {
                        return Ok((did, iid));
                    }
                }
                Err(_) => continue,
            }
        }
        anyhow::bail!("设备注册失败")
    }

    /// Register encryption key
    async fn register_encryption_key(&self) -> Result<String> {
        let content = crypto::build_register_content(&self.config.device_id, "0");
        let body = serde_json::json!({ "content": content, "keyver": 1 });
        let body_str = serde_json::to_string(&body)?;

        let params = self.common_query_string();
        let full_url = format!("{}/reading/crypt/registerkey?{}", self.base_url, params);
        let ts_ms = Self::now_millis();

        let mut req = self.client.post(&full_url).body(body_str);
        req = req
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("sdk-version", "2")
            .header("lc", "101")
            .header("X-SS-REQ-TICKET", ts_ms.to_string());

        let raw_resp = req.send().await?;
        let status = raw_resp.status();
        let text = raw_resp.text().await?;
        if text.is_empty() {
            anyhow::bail!("registerkey 返回空响应 (status={})", status);
        }
        let resp: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!("JSON parse: {} body={}", e, &text[..text.len().min(200)])
        })?;
        let code = resp["code"].as_i64().unwrap_or(-1);
        if code != 0 {
            anyhow::bail!(
                "code={}, msg={}",
                code,
                resp["message"].as_str().unwrap_or("?")
            );
        }

        let enc_key = resp["data"]["key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing key"))?;
        crypto::decrypt_server_key(enc_key)
    }

    fn common_query_string(&self) -> String {
        let ts = Self::now_millis().to_string();
        let pairs = [
            ("ac", "wifi"),
            ("aid", "1967"),
            ("app_name", "novelapp"),
            ("version_code", "71332"),
            ("version_name", "7.1.3.32"),
            ("device_platform", "android"),
            ("os", "android"),
            ("ssmix", "a"),
            ("device_type", "sdk_gphone64_arm64"),
            ("device_brand", "google"),
            ("os_api", "35"),
            ("os_version", "15"),
            ("device_id", &self.config.device_id),
            ("iid", &self.config.iid),
            ("_rticket", &ts),
            ("cdid", &self.config.cdid),
            ("openudid", &self.config.openudid),
        ];
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// GET request with common headers (no signing yet)
    pub async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        extra_params: &[(&str, &str)],
    ) -> Result<T> {
        let mut qs = self.common_query_string();
        for (k, v) in extra_params {
            qs.push('&');
            qs.push_str(&format!("{}={}", k, urlencoding::encode(v)));
        }

        let full_url = format!("{}{}?{}", self.base_url, path, qs);
        let ts_ms = Self::now_millis();

        let random_hex: String = format!("{:08x}", rand::thread_rng().gen::<u32>());

        let mut last_err = None;
        for attempt in 0..3u32 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt))).await;
            }

            let req = self
                .client
                .get(&full_url)
                .header("Accept", "application/json")
                .header("sdk-version", "2")
                .header("lc", "101")
                .header("passport-sdk-version", "5051451")
                .header("x-tt-store-region", "cn-gd")
                .header("x-tt-store-region-src", "did")
                .header("X-SS-REQ-TICKET", ts_ms.to_string())
                .header(
                    "x-reading-request",
                    format!("{}-{}", ts_ms, random_hex),
                );

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await?;
                    if text.is_empty() {
                        last_err = Some(anyhow::anyhow!("空响应 (status={})", status));
                        continue;
                    }
                    match serde_json::from_str::<T>(&text) {
                        Ok(parsed) => {
                            let delay = rand::thread_rng().gen_range(800..1200);
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            return Ok(parsed);
                        }
                        Err(e) => return Err(anyhow::anyhow!("JSON: {} body={}", e, &text[..text.len().min(200)])),
                    }
                }
                Err(e) => last_err = Some(e.into()),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("重试超限")))
    }
}

fn extract_id(resp: &serde_json::Value, field: &str) -> String {
    let str_field = format!("{}_str", field);
    if let Some(s) = resp[&str_field].as_str() {
        if !s.is_empty() && s != "0" {
            return s.to_string();
        }
    }
    if let Some(n) = resp[field].as_u64() {
        if n != 0 {
            return n.to_string();
        }
    }
    "0".to_string()
}
