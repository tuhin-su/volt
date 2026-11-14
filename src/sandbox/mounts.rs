use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::hwgen::HardwareProfile;

pub struct SandboxMounts {
    pub spoof_dir: PathBuf,
    pub shim_bin_dir: PathBuf,
}

impl SandboxMounts {
    pub fn prepare(case_dir: &Path, profile: &HardwareProfile) -> Result<Self> {
        let spoof_dir = case_dir.join("spoof");
        profile.write_spoof_tree(&spoof_dir)?;

        // Prepare transparent application shims in case shims directory
        let shim_bin_dir = case_dir.join("shims/bin");
        fs::create_dir_all(&shim_bin_dir)?;

        // 1. Transparent sudo shim — user is already UID 0 inside sandbox
        Self::write_executable_shim(
            &shim_bin_dir.join("sudo"),
            "#!/bin/sh\n# VOLT transparent sudo shim — user is already UID 0 inside sandbox\nexec \"$@\"\n",
        )?;

        // 2. Firefox and Gecko browser shims (disables internal nested namespaces that fail with EPERM in containers)
        let firefox_binaries = [
            "/usr/bin/firefox",
            "/usr/lib/firefox/firefox",
            "/usr/bin/firefox-esr",
            "/usr/lib/firefox-esr/firefox-esr",
            "/opt/firefox/firefox",
        ];
        Self::write_browser_shim(&shim_bin_dir, "firefox", &firefox_binaries, true)?;
        Self::write_browser_shim(&shim_bin_dir, "firefox-esr", &firefox_binaries, true)?;
        Self::write_browser_shim(&shim_bin_dir, "librewolf", &["/usr/bin/librewolf", "/usr/lib/librewolf/librewolf"], true)?;

        // 3. Chromium family shims across all distros and packages
        let chrome_binaries = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/opt/google/chrome/chrome",
            "/opt/google/chrome/google-chrome",
        ];
        Self::write_browser_shim(&shim_bin_dir, "google-chrome", &chrome_binaries, false)?;
        Self::write_browser_shim(&shim_bin_dir, "google-chrome-stable", &chrome_binaries, false)?;

        let chromium_binaries = [
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/lib/chromium/chromium",
            "/usr/lib/chromium-browser/chromium-browser",
            "/opt/chromium/chromium",
        ];
        Self::write_browser_shim(&shim_bin_dir, "chromium", &chromium_binaries, false)?;
        Self::write_browser_shim(&shim_bin_dir, "chromium-browser", &chromium_binaries, false)?;

        let brave_binaries = [
            "/usr/bin/brave-browser",
            "/usr/bin/brave",
            "/opt/brave.com/brave/brave-browser",
            "/opt/brave/brave",
        ];
        Self::write_browser_shim(&shim_bin_dir, "brave-browser", &brave_binaries, false)?;
        Self::write_browser_shim(&shim_bin_dir, "brave", &brave_binaries, false)?;

        let edge_binaries = [
            "/usr/bin/microsoft-edge",
            "/usr/bin/microsoft-edge-stable",
            "/opt/microsoft/msedge/msedge",
        ];
        Self::write_browser_shim(&shim_bin_dir, "microsoft-edge", &edge_binaries, false)?;
        Self::write_browser_shim(&shim_bin_dir, "microsoft-edge-stable", &edge_binaries, false)?;

        Self::write_browser_shim(&shim_bin_dir, "vivaldi", &["/usr/bin/vivaldi", "/opt/vivaldi/vivaldi"], false)?;
        Self::write_browser_shim(&shim_bin_dir, "opera", &["/usr/bin/opera", "/usr/lib/x86_64-linux-gnu/opera/opera"], false)?;

        // 4. Electron application shim (VS Code, etc.)
        let code_binaries = ["/usr/bin/code", "/usr/share/code/code", "/opt/visual-studio-code/code"];
        Self::write_browser_shim(&shim_bin_dir, "code", &code_binaries, false)?;

        // Prepare clean interactive root environment (.bashrc)
        let root_dir = case_dir.join("overlay/upper");
        fs::create_dir_all(&root_dir)?;

        // Comprehensive Xauthority discovery across GDM, SDDM, LightDM, DDE, and user environments
        let mut xauth_candidates = Vec::new();
        if let Ok(val) = std::env::var("XAUTHORITY") {
            xauth_candidates.push(PathBuf::from(val));
        }
        if let Ok(home) = std::env::var("HOME") {
            xauth_candidates.push(PathBuf::from(&home).join(".Xauthority"));
        }
        if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
            let r = PathBuf::from(&runtime);
            xauth_candidates.push(r.join(".Xauthority"));
            xauth_candidates.push(r.join("gdm/Xauthority"));
            xauth_candidates.push(r.join("Xauthority"));
        }
        for src in &xauth_candidates {
            if src.is_file() {
                let _ = fs::copy(src, root_dir.join(".Xauthority"));
                break;
            }
        }

        let bashrc = root_dir.join(".bashrc");
        let bashrc_content = format!(
            "# VOLT Universal Linux Terminal Environment (GNOME, KDE Plasma, DDE, XFCE, Wayland & X11)\n\
             export PS1='\\[\\033[01;32m\\][VOLT:{} \\W]#\\[\\033[00m\\] '\n\
             alias ls='ls --color=auto'\n\
             alias ll='ls -alF'\n\
             alias la='ls -A'\n\
             alias l='ls -CF'\n\
             alias firefox='MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_SANDBOX=1 firefox'\n\
             alias firefox-esr='MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_SANDBOX=1 firefox-esr'\n\
             alias librewolf='MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_SANDBOX=1 librewolf'\n\
             alias chromium='chromium --no-sandbox --disable-dev-shm-usage'\n\
             alias google-chrome='google-chrome --no-sandbox --disable-dev-shm-usage'\n\
             alias brave='brave-browser --no-sandbox --disable-dev-shm-usage'\n\
             alias brave-browser='brave-browser --no-sandbox --disable-dev-shm-usage'\n\
             alias code='code --no-sandbox'\n\
             export MOZ_DISABLE_CONTENT_SANDBOX=1\n\
             export MOZ_DISABLE_SANDBOX=1\n\
             export NO_SANDBOX=1\n\
             export ELECTRON_DISABLE_SANDBOX=1\n\
             export NO_AT_SPI_BUS=1\n\
             unset SESSION_MANAGER\n\
             export HISTFILE=/root/.volt_history\n\
             export HISTSIZE=10000\n\
             export HISTFILESIZE=20000\n\
             shopt -s histappend\n",
            profile.name
        );
        fs::write(&bashrc, bashrc_content)?;

        Ok(Self {
            spoof_dir,
            shim_bin_dir,
        })
    }

    fn write_browser_shim(dir: &Path, name: &str, binaries: &[&str], is_firefox: bool) -> Result<()> {
        let bin_list = binaries.iter().map(|b| format!("\"{}\"", b)).collect::<Vec<_>>().join(" ");
        let content = if is_firefox {
            format!(
                "#!/bin/sh\n\
                 # VOLT Application Shim: Disable nested container namespaces for {name}\n\
                 export MOZ_DISABLE_CONTENT_SANDBOX=1\n\
                 export MOZ_DISABLE_SANDBOX=1\n\
                 export NO_AT_SPI_BUS=1\n\
                 unset SESSION_MANAGER\n\
                 for bin in {bin_list}; do\n\
                     if [ -x \"$bin\" ] && [ \"$bin\" != \"$0\" ]; then\n\
                         exec \"$bin\" \"$@\"\n\
                     fi\n\
                 done\n\
                 NEW_PATH=$(echo \"$PATH\" | tr ':' '\\n' | grep -v \"/volt-shims\" | paste -sd:)\n\
                 PATH=\"$NEW_PATH\" exec {name} \"$@\"\n"
            )
        } else {
            format!(
                "#!/bin/sh\n\
                 # VOLT Application Shim: Disable nested container sandbox for {name}\n\
                 export NO_SANDBOX=1\n\
                 export ELECTRON_DISABLE_SANDBOX=1\n\
                 export NO_AT_SPI_BUS=1\n\
                 unset SESSION_MANAGER\n\
                 for bin in {bin_list}; do\n\
                     if [ -x \"$bin\" ] && [ \"$bin\" != \"$0\" ]; then\n\
                         exec \"$bin\" --no-sandbox --disable-dev-shm-usage \"$@\"\n\
                     fi\n\
                 done\n\
                 NEW_PATH=$(echo \"$PATH\" | tr ':' '\\n' | grep -v \"/volt-shims\" | paste -sd:)\n\
                 PATH=\"$NEW_PATH\" exec {name} --no-sandbox --disable-dev-shm-usage \"$@\"\n"
            )
        };
        Self::write_executable_shim(&dir.join(name), &content)
    }

    fn write_executable_shim(path: &Path, content: &str) -> Result<()> {
        fs::write(path, content)?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }
}
