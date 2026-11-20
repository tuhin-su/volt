use crate::utils::crypto::sha256_file;
use crate::utils::timestamps::{now_filename_safe, now_rfc3339};
use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

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

    /// Capture screenshot across any Linux desktop environment and display server
    pub fn capture(&self, trigger_type: &str, label: Option<&str>) -> Result<ScreenshotRecord> {
        let ts_name = now_filename_safe();
        let tag = label.unwrap_or(trigger_type);
        let filename = format!("{}_{}.png", ts_name, tag);
        let out_path = self.screenshots_dir.join(&filename);

        // Multi-tier cascade across all desktop environments and display protocols:
        // 1. Wayland (wlroots: Sway, Hyprland, Wayfire, River)
        // 2. GNOME Wayland / X11 (Ubuntu, Fedora, Debian)
        // 3. KDE Plasma Wayland / X11 (Spectacle)
        // 4. Deepin Desktop Environment (DDE)
        // 5. XFCE (xfce4-screenshooter)
        // 6. MATE (mate-screenshot)
        // 7. Modern X11 / Arch (maim)
        // 8. Standard X11 (scrot)
        // 9. ImageMagick X11 / XWayland (import)
        let captured = try_capture_wayland(&out_path)
            || try_capture_gnome(&out_path)
            || try_capture_kde(&out_path)
            || try_capture_deepin(&out_path)
            || try_capture_xfce(&out_path)
            || try_capture_mate(&out_path)
            || try_capture_maim(&out_path)
            || try_capture_scrot(&out_path)
            || try_capture_import(&out_path);

        if !captured || !out_path.exists() {
            // Headless / server fallback
            std::fs::write(
                &out_path,
                format!(
                    "VOLT Headless Capture - {}\nDisplay server unavailable\n",
                    now_rfc3339()
                ),
            )?;
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

/// wlroots Wayland: Sway, Hyprland, Wayfire
fn try_capture_wayland(path: &Path) -> bool {
    Command::new("grim")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// GNOME Wayland and X11
fn try_capture_gnome(path: &Path) -> bool {
    Command::new("gnome-screenshot")
        .arg("-f")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// KDE Plasma Wayland and X11 (Spectacle)
fn try_capture_kde(path: &Path) -> bool {
    Command::new("spectacle")
        .arg("-b")
        .arg("-n")
        .arg("-o")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Deepin Desktop Environment (DDE)
fn try_capture_deepin(path: &Path) -> bool {
    if Command::new("deepin-screen-recorder")
        .arg("-s")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return true;
    }
    Command::new("deepin-screenshot")
        .arg("-s")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// XFCE Desktop
fn try_capture_xfce(path: &Path) -> bool {
    Command::new("xfce4-screenshooter")
        .arg("-f")
        .arg("-s")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// MATE Desktop
fn try_capture_mate(path: &Path) -> bool {
    Command::new("mate-screenshot")
        .arg("-f")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Modern X11 (maim)
fn try_capture_maim(path: &Path) -> bool {
    Command::new("maim")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Classic X11 (scrot)
fn try_capture_scrot(path: &Path) -> bool {
    Command::new("scrot")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// ImageMagick X11 / XWayland (import)
fn try_capture_import(path: &Path) -> bool {
    Command::new("import")
        .arg("-window")
        .arg("root")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
