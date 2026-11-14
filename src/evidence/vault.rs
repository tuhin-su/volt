use anyhow::{bail, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::core::case::{Case, CaseStatus};
use crate::evidence::hashchain::HashChain;
use crate::evidence::manifest::EvidenceManifest;
use crate::utils::crypto::sha256_file;

pub struct EvidenceVault {
    pub case_dir: PathBuf,
    pub chain: Arc<HashChain>,
}

impl EvidenceVault {
    pub fn open(case: &Case) -> Result<Self> {
        let chain_file = case.evidence_dir().join("chain.jsonl");
        let chain = HashChain::open_or_init(&chain_file, &case.metadata.genesis_hash)?;
        Ok(Self {
            case_dir: case.dir.clone(),
            chain: Arc::new(chain),
        })
    }

    /// Record an event into the hash chain
    pub fn record_event(&self, event_type: &str, payload_hash: &str) -> Result<String> {
        let block = self.chain.append(event_type, payload_hash)?;
        Ok(block.block_hash)
    }

    /// Record a file into the evidence vault and hash chain
    pub fn record_file<P: AsRef<Path>>(&self, path: P, event_type: &str) -> Result<String> {
        let path = path.as_ref();
        if !path.exists() {
            bail!("File {:?} does not exist to record in vault", path);
        }
        let file_hash = sha256_file(path)?;
        self.record_event(event_type, &file_hash)
    }

    /// Seal the case, verify chain, and produce manifest
    pub fn seal(&self, case: &mut Case) -> Result<EvidenceManifest> {
        // 1. Verify chain integrity before sealing
        let chain_file = case.evidence_dir().join("chain.jsonl");
        let blocks = HashChain::verify_file(&chain_file)?;
        tracing::info!("Hash chain verified: {} total blocks intact", blocks);

        // 2. Build final manifest
        let tip = self.chain.current_tip();
        let manifest = EvidenceManifest::build(
            &case.dir,
            &case.metadata.case_name,
            &case.metadata.investigator,
            &case.metadata.hardware_profile,
            &tip,
        )?;

        // 3. Write manifest.json
        let manifest_path = case.dir.join("evidence_manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(&manifest_path, manifest_json)?;

        // 4. Update case status
        case.metadata.status = CaseStatus::Sealed;
        case.save_metadata()?;

        Ok(manifest)
    }
}
