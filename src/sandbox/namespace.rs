use std::path::Path;

use crate::hwgen::HardwareProfile;
use crate::sandbox::mounts::SandboxMounts;

pub struct SandboxLauncher {
    pub case_dir: std::path::PathBuf,
    pub profile: HardwareProfile,
}

impl SandboxLauncher {
    pub fn new(case_dir: &Path, profile: HardwareProfile) -> Self {
        Self {
            case_dir: case_dir.to_path_buf(),
            profile,
        }
    }

    /// Build the bwrap command argument list
    pub fn build_bwrap_args(&self, mounts: &SandboxMounts, user_command: Option<&str>) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();

        // 1. Unshare all namespaces EXCEPT network (retains host network)
        args.push("--unshare-all".to_string());
        args.push("--share-net".to_string());

        // 2. Map inside sandbox to root UID 0 / GID 0
        args.push("--uid".to_string());
        args.push("0".to_string());
        args.push("--gid".to_string());
        args.push("0".to_string());

        // 3. Fake hostname from hardware profile
        args.push("--hostname".to_string());
        args.push(self.profile.hostname.clone());

        // 4. Base filesystem mounts (read-only host tools)
        args.push("--ro-bind".to_string());
        args.push("/usr".to_string());
        args.push("/usr".to_string());

        args.push("--ro-bind-try".to_string());
        args.push("/lib".to_string());
        args.push("/lib".to_string());

        args.push("--ro-bind-try".to_string());
        args.push("/lib64".to_string());
        args.push("/lib64".to_string());

        args.push("--ro-bind-try".to_string());
        args.push("/etc/resolv.conf".to_string());
        args.push("/etc/resolv.conf".to_string());

        args.push("--ro-bind-try".to_string());
        args.push("/etc/ssl".to_string());
        args.push("/etc/ssl".to_string());

        // Symlinks for merged /bin and /sbin
        args.push("--symlink".to_string());
        args.push("usr/bin".to_string());
        args.push("/bin".to_string());

        args.push("--symlink".to_string());
        args.push("usr/sbin".to_string());
        args.push("/sbin".to_string());

        // Devices and proc
        args.push("--dev".to_string());
        args.push("/dev".to_string());
        args.push("--proc".to_string());
        args.push("/proc".to_string());

        // 5. Mount identity spoofing layers
        let spoof = &mounts.spoof_dir;
        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("etc/hostname").to_string_lossy().to_string());
        args.push("/etc/hostname".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("etc/os-release").to_string_lossy().to_string());
        args.push("/etc/os-release".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("etc/passwd").to_string_lossy().to_string());
        args.push("/etc/passwd".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("etc/shadow").to_string_lossy().to_string());
        args.push("/etc/shadow".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("etc/machine-id").to_string_lossy().to_string());
        args.push("/etc/machine-id".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("proc/cpuinfo").to_string_lossy().to_string());
        args.push("/proc/cpuinfo".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("proc/version").to_string_lossy().to_string());
        args.push("/proc/version".to_string());

        // Sysfs DMI spoofing
        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("sys/class/dmi/id").to_string_lossy().to_string());
        args.push("/sys/class/dmi/id".to_string());

        // 6. Injected sudo shim
        args.push("--ro-bind-try".to_string());
        args.push(mounts.shim_bin_dir.join("sudo").to_string_lossy().to_string());
        args.push("/usr/local/bin/sudo".to_string());

        // 7. Writable scratch spaces (tmpfs and case overlay)
        args.push("--tmpfs".to_string());
        args.push("/tmp".to_string());

        let overlay_upper = self.case_dir.join("overlay/upper");
        args.push("--bind".to_string());
        args.push(overlay_upper.to_string_lossy().to_string());
        args.push("/root".to_string());

        // 8. Environment variables
        args.push("--setenv".to_string());
        args.push("USER".to_string());
        args.push("root".to_string());

        args.push("--setenv".to_string());
        args.push("HOME".to_string());
        args.push("/root".to_string());

        args.push("--setenv".to_string());
        args.push("SHELL".to_string());
        args.push("/bin/bash".to_string());

        args.push("--setenv".to_string());
        args.push("PATH".to_string());
        args.push("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string());

        let host_term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
        args.push("--setenv".to_string());
        args.push("TERM".to_string());
        args.push(host_term);

        args.push("--chdir".to_string());
        args.push("/root".to_string());

        // 9. Command to execute inside sandbox
        if let Some(cmd) = user_command {
            args.push("/bin/sh".to_string());
            args.push("-c".to_string());
            args.push(cmd.to_string());
        } else {
            // Proper interactive shell with rcfile and job control
            args.push("/bin/bash".to_string());
            args.push("--rcfile".to_string());
            args.push("/root/.bashrc".to_string());
            args.push("-i".to_string());
        }

        args
    }
}
