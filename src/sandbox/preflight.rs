use anyhow::{bail, Result};
use std::path::Path;

pub struct Preflight;

impl Preflight {
    /// Run all safety checks before starting a VOLT session.
    /// If ANY check fails, the session REFUSES to start.
    pub fn check_safety(case_dir: &Path) -> Result<()> {
        // 1. Verify case directory is writable
        if !case_dir.exists() {
            bail!(
                "Preflight failed: Case directory {:?} does not exist",
                case_dir
            );
        }

        let test_write = case_dir.join(".preflight_test");
        if let Err(e) = std::fs::write(&test_write, b"preflight") {
            bail!("Preflight failed: Case directory is not writable: {}", e);
        }
        let _ = std::fs::remove_file(test_write);

        // 2. Check bwrap (bubblewrap) availability
        let bwrap_check = std::process::Command::new("bwrap")
            .arg("--version")
            .output();

        match bwrap_check {
            Ok(output) if output.status.success() => {
                tracing::debug!("Preflight: bubblewrap binary detected");
            }
            _ => {
                bail!("Preflight failed: 'bwrap' (bubblewrap) is required for container isolation but was not found in PATH");
            }
        }

        // 3. Check tcpdump availability
        let tcpdump_check = std::process::Command::new("tcpdump")
            .arg("--version")
            .output();

        match tcpdump_check {
            Ok(_) => {
                tracing::debug!("Preflight: tcpdump binary detected");
            }
            _ => {
                tracing::warn!("Preflight notice: tcpdump not found or lacks permissions; packet capture may be limited");
            }
        }

        tracing::info!("Preflight checks passed successfully — safe to launch isolated session");
        Ok(())
    }
}
