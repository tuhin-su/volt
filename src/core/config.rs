use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

/// Resolve the home directory of a user by username
pub fn resolve_user_home(username: &str) -> Option<PathBuf> {
    if let Ok(Some(user)) = nix::unistd::User::from_name(username) {
        return Some(user.dir);
    }
    let fallback = PathBuf::from("/home").join(username);
    if fallback.exists() {
        return Some(fallback);
    }
    None
}

/// Expands leading `~` into the user's `$HOME` directory if present (respecting SUDO_USER)
pub fn expand_tilde<P: AsRef<Path>>(path: P) -> PathBuf {
    let p = path.as_ref();
    if let Ok(stripped) = p.strip_prefix("~") {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if let Some(user_home) = resolve_user_home(&sudo_user) {
                return user_home.join(stripped);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    p.to_path_buf()
}

/// Default global cases storage directory (~/.cases), respecting SUDO_USER
pub fn default_case_dir() -> PathBuf {
    if let Ok(val) = std::env::var("VOLT_CASES_DIR") {
        expand_tilde(val)
    } else if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if let Some(user_home) = resolve_user_home(&sudo_user) {
            user_home.join(".cases")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".cases")
        } else {
            PathBuf::from("./cases")
        }
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cases")
    } else {
        PathBuf::from("./cases")
    }
}

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
            let mut config: VoltConfig = toml::from_str(&content)
                .with_context(|| format!("Failed to parse TOML config at {:?}", path))?;
            config.cases_dir = expand_tilde(&config.cases_dir);
            Ok(config)
        } else {
            let config = VoltConfig::default();
            // Attempt to write config if parent directory is writable
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(toml_str) = toml::to_string_pretty(&config) {
                let _ = fs::write(path, toml_str);
            }
            Ok(config)
        }
    }
}
