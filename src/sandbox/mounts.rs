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

        // Prepare transparent sudo shim
        let shim_bin_dir = case_dir.join("shims/bin");
        fs::create_dir_all(&shim_bin_dir)?;

        let sudo_shim = shim_bin_dir.join("sudo");
        fs::write(
            &sudo_shim,
            "#!/bin/sh\n# VOLT transparent sudo shim — user is already UID 0 inside sandbox\nexec \"$@\"\n",
        )?;

        // Make executable
        let mut perms = fs::metadata(&sudo_shim)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&sudo_shim, perms)?;

        // Prepare clean interactive root environment (.bashrc)
        let root_dir = case_dir.join("overlay/upper");
        fs::create_dir_all(&root_dir)?;
        let bashrc = root_dir.join(".bashrc");
        let bashrc_content = format!(
            "# VOLT Interactive Terminal Environment\n\
             export PS1='\\[\\033[01;32m\\][VOLT:{} \\W]#\\[\\033[00m\\] '\n\
             alias ls='ls --color=auto'\n\
             alias ll='ls -alF'\n\
             alias la='ls -A'\n\
             alias l='ls -CF'\n\
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
}
