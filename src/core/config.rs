use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoltConfig {
    #[serde(default = "default_case_dir")]
    pub cases_dir: PathBuf,

    #[serde(default = "default_hardware_profile")]
    pub default_hardware_profile: String,

    #[serde(default = "default_screenshot_interval_secs")]
    pub screenshot_interval_secs: u64,

    #[serde(default = "default_pcap_rotate_mb")]
    pub pcap_rotate_mb: u64,

    #[serde(default = "default_disk_warning_pct")]
    pub disk_warning_pct: u8,

    #[serde(default = "default_disk_emergency_seal_pct")]
    pub disk_emergency_seal_pct: u8,
}

fn default_case_dir() -> PathBuf {
    if let Ok(val) = std::env::var("VOLT_CASES_DIR") {
        PathBuf::from(val)
    } else {
        PathBuf::from("./cases")
    }
}

fn default_hardware_profile() -> String {
    "vm-virtualbox".to_string()
}

fn default_screenshot_interval_secs() -> u64 {
    30
}

fn default_pcap_rotate_mb() -> u64 {
    100
}

fn default_disk_warning_pct() -> u8 {
    80
}

fn default_disk_emergency_seal_pct() -> u8 {
    95
}

impl Default for VoltConfig {
    fn default() -> Self {
        Self {
            cases_dir: default_case_dir(),
            default_hardware_profile: default_hardware_profile(),
            screenshot_interval_secs: default_screenshot_interval_secs(),
            pcap_rotate_mb: default_pcap_rotate_mb(),
            disk_warning_pct: default_disk_warning_pct(),
            disk_emergency_seal_pct: default_disk_emergency_seal_pct(),
        }
    }
}

impl VoltConfig {
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file at {:?}", path))?;
            let config: VoltConfig = toml::from_str(&content)
                .with_context(|| format!("Failed to parse TOML config at {:?}", path))?;
            Ok(config)
        } else {
            let config = VoltConfig::default();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let toml_str = toml::to_string_pretty(&config)?;
            fs::write(path, toml_str)?;
            Ok(config)
        }
    }
}
