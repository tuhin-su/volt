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

        // 2. Firefox shim — disables internal nested user namespaces that fail with EPERM in containers
        Self::write_executable_shim(
            &shim_bin_dir.join("firefox"),
            "#!/bin/sh\n\
             # VOLT Application Shim: Disable internal nested namespaces for Firefox\n\
             export MOZ_DISABLE_CONTENT_SANDBOX=1\n\
             export MOZ_DISABLE_SANDBOX=1\n\
             export NO_AT_SPI_BUS=1\n\
             unset SESSION_MANAGER\n\
             for bin in /usr/bin/firefox /usr/lib/firefox/firefox /usr/bin/firefox-esr /usr/lib/firefox-esr/firefox-esr; do\n\
                 if [ -x \"$bin\" ] && [ \"$bin\" != \"$0\" ]; then\n\
                     exec \"$bin\" \"$@\"\n\
                 fi\n\
             done\n\
             NEW_PATH=$(echo \"$PATH\" | tr ':' '\\n' | grep -v \"/volt-shims\" | paste -sd:)\n\
             PATH=\"$NEW_PATH\" exec firefox \"$@\"\n",
        )?;

        // Also shim firefox-esr
        Self::write_executable_shim(
            &shim_bin_dir.join("firefox-esr"),
            "#!/bin/sh\n\
             # VOLT Application Shim: Disable internal nested namespaces for Firefox ESR\n\
             export MOZ_DISABLE_CONTENT_SANDBOX=1\n\
             export MOZ_DISABLE_SANDBOX=1\n\
             export NO_AT_SPI_BUS=1\n\
             unset SESSION_MANAGER\n\
             for bin in /usr/bin/firefox-esr /usr/lib/firefox-esr/firefox-esr /usr/bin/firefox; do\n\
                 if [ -x \"$bin\" ] && [ \"$bin\" != \"$0\" ]; then\n\
                     exec \"$bin\" \"$@\"\n\
                 fi\n\
             done\n\
             NEW_PATH=$(echo \"$PATH\" | tr ':' '\\n' | grep -v \"/volt-shims\" | paste -sd:)\n\
             PATH=\"$NEW_PATH\" exec firefox-esr \"$@\"\n",
        )?;

        // 3. Chromium shim — disables internal nested sandbox in container
        Self::write_executable_shim(
            &shim_bin_dir.join("chromium"),
            "#!/bin/sh\n\
             # VOLT Application Shim: Disable internal nested sandbox for Chromium\n\
             export NO_SANDBOX=1\n\
             export NO_AT_SPI_BUS=1\n\
             unset SESSION_MANAGER\n\
             for bin in /usr/bin/chromium /usr/bin/chromium-browser /usr/lib/chromium/chromium; do\n\
                 if [ -x \"$bin\" ] && [ \"$bin\" != \"$0\" ]; then\n\
                     exec \"$bin\" --no-sandbox --disable-dev-shm-usage \"$@\"\n\
                 fi\n\
             done\n\
             NEW_PATH=$(echo \"$PATH\" | tr ':' '\\n' | grep -v \"/volt-shims\" | paste -sd:)\n\
             PATH=\"$NEW_PATH\" exec chromium --no-sandbox --disable-dev-shm-usage \"$@\"\n",
        )?;

        // 4. Google Chrome shim
        Self::write_executable_shim(
            &shim_bin_dir.join("google-chrome"),
            "#!/bin/sh\n\
             # VOLT Application Shim: Disable internal nested sandbox for Google Chrome\n\
             export NO_SANDBOX=1\n\
             export NO_AT_SPI_BUS=1\n\
             unset SESSION_MANAGER\n\
             for bin in /usr/bin/google-chrome /usr/bin/google-chrome-stable /opt/google/chrome/chrome; do\n\
                 if [ -x \"$bin\" ] && [ \"$bin\" != \"$0\" ]; then\n\
                     exec \"$bin\" --no-sandbox --disable-dev-shm-usage \"$@\"\n\
                 fi\n\
             done\n\
             NEW_PATH=$(echo \"$PATH\" | tr ':' '\\n' | grep -v \"/volt-shims\" | paste -sd:)\n\
             PATH=\"$NEW_PATH\" exec google-chrome --no-sandbox --disable-dev-shm-usage \"$@\"\n",
        )?;

        // Prepare clean interactive root environment (.bashrc)
        let root_dir = case_dir.join("overlay/upper");
        fs::create_dir_all(&root_dir)?;

        // Copy host .Xauthority into upper overlay if present
        let xauth_sources = [
            std::env::var("XAUTHORITY").ok().map(PathBuf::from),
            std::env::var("HOME").ok().map(|h| Path::new(&h).join(".Xauthority")),
        ];
        for src in xauth_sources.iter().flatten() {
            if src.is_file() {
                let _ = fs::copy(src, root_dir.join(".Xauthority"));
                break;
            }
        }

        let bashrc = root_dir.join(".bashrc");
        let bashrc_content = format!(
            "# VOLT Interactive Terminal Environment\n\
             export PS1='\\[\\033[01;32m\\][VOLT:{} \\W]#\\[\\033[00m\\] '\n\
             alias ls='ls --color=auto'\n\
             alias ll='ls -alF'\n\
             alias la='ls -A'\n\
             alias l='ls -CF'\n\
             alias firefox='MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_SANDBOX=1 firefox'\n\
             alias firefox-esr='MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_SANDBOX=1 firefox-esr'\n\
             alias chromium='chromium --no-sandbox --disable-dev-shm-usage'\n\
             alias google-chrome='google-chrome --no-sandbox --disable-dev-shm-usage'\n\
             export MOZ_DISABLE_CONTENT_SANDBOX=1\n\
             export MOZ_DISABLE_SANDBOX=1\n\
             export NO_SANDBOX=1\n\
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

    fn write_executable_shim(path: &Path, content: &str) -> Result<()> {
        fs::write(path, content)?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }
}
