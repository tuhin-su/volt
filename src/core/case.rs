use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::utils::crypto::sha256_bytes;
use crate::utils::timestamps::now_rfc3339;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMetadata {
    pub case_name: String,
    pub investigator: String,
    pub agency: Option<String>,
    pub warrant_ref: Option<String>,
    pub evidence_id: Option<String>,
    pub operation_mode: String,
    pub created_at: String,
    pub hardware_profile: String,
    pub status: CaseStatus,
    pub genesis_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseStatus {
    Active,
    Sealed,
    Exported,
}

#[derive(Debug, Clone)]
pub struct Case {
    pub dir: PathBuf,
    pub metadata: CaseMetadata,
}

impl Case {
    /// Initialize a new evidence case directory
    pub fn init<P: AsRef<Path>>(
        base_dir: P,
        case_name: &str,
        investigator: &str,
        hardware_profile: &str,
        operation_mode: &str,
        agency: Option<String>,
        warrant_ref: Option<String>,
        evidence_id: Option<String>,
    ) -> Result<Self> {
        let case_dir = base_dir.as_ref().join(case_name);
        if case_dir.exists() {
            anyhow::bail!("Case directory {:?} already exists!", case_dir);
        }

        // Create case subdirectories
        fs::create_dir_all(case_dir.join("evidence"))?;
        fs::create_dir_all(case_dir.join("pcaps"))?;
        fs::create_dir_all(case_dir.join("screenshots"))?;
        fs::create_dir_all(case_dir.join("logs"))?;
        fs::create_dir_all(case_dir.join("reports"))?;
        fs::create_dir_all(case_dir.join("overlay/upper"))?;
        fs::create_dir_all(case_dir.join("overlay/work"))?;
        fs::create_dir_all(case_dir.join("overlay/merged"))?;

        let created_at = now_rfc3339();
        let genesis_input = format!(
            "{}:{}:{}:{}:{}",
            case_name, investigator, hardware_profile, operation_mode, created_at
        );
        let genesis_hash = sha256_bytes(genesis_input.as_bytes());

        let metadata = CaseMetadata {
            case_name: case_name.to_string(),
            investigator: investigator.to_string(),
            agency,
            warrant_ref,
            evidence_id,
            operation_mode: operation_mode.to_string(),
            created_at,
            hardware_profile: hardware_profile.to_string(),
            status: CaseStatus::Active,
            genesis_hash,
        };

        let meta_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(case_dir.join("case.json"), meta_json)?;

        Ok(Self {
            dir: case_dir,
            metadata,
        })
    }

    /// Load an existing case from directory
    pub fn open<P: AsRef<Path>>(case_dir: P) -> Result<Self> {
        let case_dir = case_dir.as_ref().to_path_buf();
        let meta_file = case_dir.join("case.json");
        if !meta_file.exists() {
            anyhow::bail!("No case.json found in {:?}", case_dir);
        }
        let content = fs::read_to_string(&meta_file)
            .with_context(|| format!("Failed to read {:?}", meta_file))?;
        let metadata: CaseMetadata =
            serde_json::from_str(&content).with_context(|| "Failed to parse case.json")?;

        Ok(Self {
            dir: case_dir,
            metadata,
        })
    }

    pub fn save_metadata(&self) -> Result<()> {
        let meta_json = serde_json::to_string_pretty(&self.metadata)?;
        fs::write(self.dir.join("case.json"), meta_json)?;
        Ok(())
    }

    pub fn evidence_dir(&self) -> PathBuf {
        self.dir.join("evidence")
    }

    pub fn pcaps_dir(&self) -> PathBuf {
        self.dir.join("pcaps")
    }

    pub fn screenshots_dir(&self) -> PathBuf {
        self.dir.join("screenshots")
    }

    pub fn reports_dir(&self) -> PathBuf {
        self.dir.join("reports")
    }

    pub fn overlay_merged_dir(&self) -> PathBuf {
        self.dir.join("overlay/merged")
    }

    pub fn overlay_upper_dir(&self) -> PathBuf {
        self.dir.join("overlay/upper")
    }

    pub fn overlay_work_dir(&self) -> PathBuf {
        self.dir.join("overlay/work")
    }

    pub fn shared_env_file(&self) -> PathBuf {
        self.dir.join("overlay/upper/.volt_env")
    }
}
