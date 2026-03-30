use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceConfig {
    pub device_id: String,
    pub iid: String,
    pub v1_key: String,
    /// Persistent openudid for device registration
    #[serde(default = "gen_openudid")]
    pub openudid: String,
    /// Persistent client device id (UUID format)
    #[serde(default = "gen_cdid")]
    pub cdid: String,
}

fn gen_openudid() -> String {
    format!("{:016x}", rand::thread_rng().gen::<u64>())
}

fn gen_cdid() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl DeviceConfig {
    fn config_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".fanqie-dl")
            .join("config.json")
    }

    pub fn load_or_create() -> Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let config: Self = serde_json::from_str(&data)?;
            if !config.device_id.is_empty() && config.device_id != "0" {
                return Ok(config);
            }
            // device_id invalid but keep openudid/cdid for re-registration
            return Ok(Self {
                device_id: String::new(),
                iid: String::new(),
                v1_key: String::new(),
                openudid: config.openudid,
                cdid: config.cdid,
            });
        }
        let config = Self {
            device_id: String::new(),
            iid: String::new(),
            v1_key: String::new(),
            openudid: gen_openudid(),
            cdid: gen_cdid(),
        };
        config.save()?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}
