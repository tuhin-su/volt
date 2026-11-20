use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::utils::crypto::sha256_bytes;
use crate::utils::timestamps::now_rfc3339;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBlock {
    pub index: u64,
    pub timestamp: String,
    pub event_type: String,
    pub payload_hash: String,
    pub prev_hash: String,
    pub block_hash: String,
}

pub struct HashChain {
    file_path: PathBuf,
    last_block: Mutex<Option<ChainBlock>>,
}

impl HashChain {
    pub fn open_or_init<P: AsRef<Path>>(file_path: P, genesis_seed: &str) -> Result<Self> {
        let path = file_path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut last_block = None;

        if path.exists() {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line_str = line?;
                if line_str.trim().is_empty() {
                    continue;
                }
                let block: ChainBlock = serde_json::from_str(&line_str)?;
                last_block = Some(block);
            }
        }

        // If file was empty or didn't exist, create Genesis Block 0
        if last_block.is_none() {
            let timestamp = now_rfc3339();
            let genesis_hash = sha256_bytes(genesis_seed.as_bytes());
            let prev_hash = "0".repeat(64);
            let block_hash =
                sha256_bytes(format!("0:{}:{}:{}", timestamp, "GENESIS", genesis_hash).as_bytes());

            let genesis = ChainBlock {
                index: 0,
                timestamp,
                event_type: "GENESIS".to_string(),
                payload_hash: genesis_hash,
                prev_hash,
                block_hash,
            };

            let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
            let json = serde_json::to_string(&genesis)?;
            writeln!(file, "{}", json)?;
            file.sync_all()?;
            last_block = Some(genesis);
        }

        Ok(Self {
            file_path: path,
            last_block: Mutex::new(last_block),
        })
    }

    /// Append a new event to the chain
    pub fn append(&self, event_type: &str, payload_hash: &str) -> Result<ChainBlock> {
        let mut last_guard = self.last_block.lock().unwrap();
        let prev = last_guard.as_ref().expect("Genesis block must exist");

        let index = prev.index + 1;
        let timestamp = now_rfc3339();
        let prev_hash = prev.block_hash.clone();

        let raw = format!(
            "{}:{}:{}:{}:{}",
            index, timestamp, event_type, payload_hash, prev_hash
        );
        let block_hash = sha256_bytes(raw.as_bytes());

        let new_block = ChainBlock {
            index,
            timestamp,
            event_type: event_type.to_string(),
            payload_hash: payload_hash.to_string(),
            prev_hash,
            block_hash,
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;
        let json = serde_json::to_string(&new_block)?;
        writeln!(file, "{}", json)?;
        file.sync_all()?; // Immediate fsync for evidence integrity

        *last_guard = Some(new_block.clone());
        Ok(new_block)
    }

    /// Get current tip hash of the chain
    pub fn current_tip(&self) -> String {
        self.last_block
            .lock()
            .unwrap()
            .as_ref()
            .map(|b| b.block_hash.clone())
            .unwrap_or_default()
    }

    /// Verify an entire chain file on disk
    pub fn verify_file<P: AsRef<Path>>(file_path: P) -> Result<u64> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut count = 0u64;
        let mut expected_prev_hash: Option<String> = None;

        for (line_idx, line) in reader.lines().enumerate() {
            let line_str = line?;
            if line_str.trim().is_empty() {
                continue;
            }
            let block: ChainBlock = serde_json::from_str(&line_str)?;

            // Check index
            if block.index != count {
                bail!(
                    "Chain verification failed at line {}: expected block index {} but found {}",
                    line_idx + 1,
                    count,
                    block.index
                );
            }

            // Check previous hash link
            if let Some(prev) = expected_prev_hash {
                if block.prev_hash != prev {
                    bail!(
                        "Chain verification failed at block {}: prev_hash mismatch! Found {} vs expected {}",
                        block.index,
                        block.prev_hash,
                        prev
                    );
                }
            } else if block.index == 0 {
                // Genesis block
                let expected_genesis = sha256_bytes(
                    format!("0:{}:{}:{}", block.timestamp, "GENESIS", block.payload_hash)
                        .as_bytes(),
                );
                if block.block_hash != expected_genesis {
                    bail!("Corrupted Genesis block hash at line {}", line_idx + 1);
                }
            }

            // Recalculate block hash for non-genesis
            if block.index > 0 {
                let raw = format!(
                    "{}:{}:{}:{}:{}",
                    block.index,
                    block.timestamp,
                    block.event_type,
                    block.payload_hash,
                    block.prev_hash
                );
                let computed = sha256_bytes(raw.as_bytes());
                if computed != block.block_hash {
                    bail!(
                        "Tampering detected at block {}: hash mismatch! Expected {} but calculated {}",
                        block.index,
                        block.block_hash,
                        computed
                    );
                }
            }

            expected_prev_hash = Some(block.block_hash.clone());
            count += 1;
        }

        Ok(count)
    }
}
