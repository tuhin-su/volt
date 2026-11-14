use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::Result;
use crate::utils::crypto::sha256_file;
use crate::utils::timestamps::now_rfc3339;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifest {
    pub case_name: String,
    pub investigator: String,
    pub sealed_at: String,
    pub hardware_profile: String,
    pub chain_tip_hash: String,
    pub total_artifacts: usize,
    pub total_bytes: u64,
    pub artifacts: HashMap<String, ArtifactEntry>,
}

impl EvidenceManifest {
    pub fn build(
        case_dir: &Path,
        case_name: &str,
        investigator: &str,
        hardware_profile: &str,
        chain_tip_hash: &str,
    ) -> Result<Self> {
        let mut artifacts = HashMap::new();
        let mut total_bytes = 0u64;

        let scan_dirs = ["evidence", "pcaps", "screenshots", "logs"];

        for sub in scan_dirs {
            let dir = case_dir.join(sub);
            if !dir.exists() {
                continue;
            }
            for entry in walk_dir(&dir)? {
                let metadata = entry.metadata()?;
                if metadata.is_file() {
                    let rel = entry.strip_prefix(case_dir)?.to_string_lossy().to_string();
                    let size = metadata.len();
                    let hash = sha256_file(&entry)?;

                    total_bytes += size;
                    artifacts.insert(
                        rel.clone(),
                        ArtifactEntry {
                            relative_path: rel,
                            size_bytes: size,
                            sha256: hash,
                        },
                    );
                }
            }
        }

        Ok(Self {
            case_name: case_name.to_string(),
            investigator: investigator.to_string(),
            sealed_at: now_rfc3339(),
            hardware_profile: hardware_profile.to_string(),
            chain_tip_hash: chain_tip_hash.to_string(),
            total_artifacts: artifacts.len(),
            total_bytes,
            artifacts,
        })
    }
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                files.extend(walk_dir(&path)?);
            } else {
                files.push(path);
            }
        }
    }
    Ok(files)
}
