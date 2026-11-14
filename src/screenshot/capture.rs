use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::utils::crypto::sha256_file;
use crate::utils::timestamps::{now_filename_safe, now_rfc3339};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScreenshotRecord {
    pub timestamp: String,
    pub trigger: String,
    pub filename: String,
    pub sha256: String,
    pub size_bytes: u64,
}

pub struct ScreenshotEngine {
    screenshots_dir: PathBuf,
    manifest_path: PathBuf,
}

impl ScreenshotEngine {
    pub fn new<P: AsRef<Path>>(screenshots_dir: P) -> Self {
        let dir = screenshots_dir.as_ref().to_path_buf();
        let manifest = dir.join("screenshots_manifest.jsonl");
        Self {
            screenshots_dir: dir,
            manifest_path: manifest,
        }
    }

    /// Capture screenshot and log to manifest
    pub fn capture(&self, trigger_type: &str, label: Option<&str>) -> Result<ScreenshotRecord> {
        let ts_name = now_filename_safe();
        let tag = label.unwrap_or(trigger_type);
        let filename = format!("{}_{}.png", ts_name, tag);
        let out_path = self.screenshots_dir.join(&filename);

        // Try capture tools in order: grim (wlroots) -> gnome-screenshot (GNOME Wayland) -> scrot -> import (X11/XWayland)
        let captured = try_capture_wayland(&out_path)
            || try_capture_gnome(&out_path)
            || try_capture_scrot(&out_path)
            || try_capture_import(&out_path);

        if !captured || !out_path.exists() {
            // If headless or no X11/Wayland display server is available, create a placeholder diagnostic image
            std::fs::write(&out_path, format!("VOLT Headless Capture - {}\nDisplay server unavailable\n", now_rfc3339()))?;
        }

        let sha256 = sha256_file(&out_path)
            .with_context(|| format!("Failed to hash screenshot {:?}", out_path))?;
        let size_bytes = std::fs::metadata(&out_path)?.len();

        let record = ScreenshotRecord {
            timestamp: now_rfc3339(),
            trigger: trigger_type.to_string(),
            filename: filename.clone(),
            sha256,
            size_bytes,
        };

        // Append to screenshots manifest
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.manifest_path)?;
        writeln!(file, "{}", serde_json::to_string(&record)?)?;
        file.sync_all()?;

        Ok(record)
    }
}

fn try_capture_wayland(path: &Path) -> bool {
    Command::new("grim")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn try_capture_gnome(path: &Path) -> bool {
    Command::new("gnome-screenshot")
        .arg("-f")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn try_capture_scrot(path: &Path) -> bool {
    Command::new("scrot")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn try_capture_import(path: &Path) -> bool {
    Command::new("import")
        .arg("-window")
        .arg("root")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
