use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::Result;
use crate::utils::timestamps::now_rfc3339;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub case_name: String,
    pub session_id: String,
    pub started_at: String,
    pub pid: u32,
    pub container_pid: Option<u32>,
    pub hardware_profile: String,
    pub operation_mode: String,
    pub tcpdump_pid: Option<u32>,
    pub pty_active: bool,
    #[serde(default)]
    pub active_terminals: Vec<String>,
}

impl SessionInfo {
    pub fn new(
        case_name: &str,
        session_id: &str,
        pid: u32,
        hw_profile: &str,
        mode: &str,
    ) -> Self {
        Self {
            case_name: case_name.to_string(),
            session_id: session_id.to_string(),
            started_at: now_rfc3339(),
            pid,
            container_pid: None,
            hardware_profile: hw_profile.to_string(),
            operation_mode: mode.to_string(),
            tcpdump_pid: None,
            pty_active: true,
            active_terminals: vec!["term_0".to_string()],
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let info = serde_json::from_str(&content)?;
        Ok(info)
    }

    pub fn session_file(case_dir: &Path) -> PathBuf {
        case_dir.join(".active_session.json")
    }
}
