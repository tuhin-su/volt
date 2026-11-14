use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::evidence::EvidenceVault;
use crate::utils::crypto::sha256_file;

pub struct TcpdumpManager {
    pcaps_dir: PathBuf,
    rotate_mb: u64,
}

impl TcpdumpManager {
    pub fn new<P: AsRef<Path>>(pcaps_dir: P, rotate_mb: u64) -> Self {
        Self {
            pcaps_dir: pcaps_dir.as_ref().to_path_buf(),
            rotate_mb,
        }
    }

    /// Spawn background tcpdump process capturing all network interfaces
    pub fn spawn(&self) -> Result<Child> {
        let pcap_pattern = self.pcaps_dir.join("capture_%Y%m%d_%H%M%S.pcap");
        let pcap_str = pcap_pattern.to_string_lossy().to_string();

        let mut child = Command::new("tcpdump")
            .arg("-i")
            .arg("any")
            .arg("-U") // Packet-buffered output
            .arg("-C")
            .arg(self.rotate_mb.to_string()) // File rotation in MB
            .arg("-G")
            .arg("3600") // Rotate every hour if size not reached
            .arg("-w")
            .arg(pcap_str)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .with_context(|| "Failed to spawn background tcpdump capture process")?;

        std::thread::sleep(Duration::from_millis(150));
        if let Ok(Some(exit_status)) = child.try_wait() {
            tracing::warn!("tcpdump exited ({}); live packet capture requires CAP_NET_RAW or running with sudo", exit_status);
        } else {
            tracing::info!("Started always-on tcpdump (PID: {}) writing to {:?}", child.id(), self.pcaps_dir);
        }

        Ok(child)
    }

    /// Background monitor to hash rotated PCAP files into evidence vault
    pub async fn monitor_and_hash(
        pcaps_dir: PathBuf,
        vault: Arc<EvidenceVault>,
        running: Arc<AtomicBool>,
    ) {
        let mut seen = std::collections::HashSet::new();

        while running.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(5)).await;
            if let Ok(entries) = std::fs::read_dir(&pcaps_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && path.extension().map(|e| e == "pcap").unwrap_or(false) {
                        let path_str = path.to_string_lossy().to_string();
                        if !seen.contains(&path_str) {
                            if let Ok(hash) = sha256_file(&path) {
                                let _ = vault.record_event("PCAP_ROTATED", &hash);
                                seen.insert(path_str);
                                tracing::debug!("Hashed PCAP chunk {:?}", path);
                            }
                        }
                    }
                }
            }
        }

        // Final pass when session ends
        if let Ok(entries) = std::fs::read_dir(&pcaps_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let path_str = path.to_string_lossy().to_string();
                    if !seen.contains(&path_str) {
                        if let Ok(hash) = sha256_file(&path) {
                            let _ = vault.record_event("PCAP_FINAL", &hash);
                            seen.insert(path_str);
                        }
                    }
                }
            }
        }
    }
}
