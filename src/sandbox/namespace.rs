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

    /// Build the bwrap command argument list with universal support for any Linux OS and Desktop Environment
    pub fn build_bwrap_args(
        &self,
        mounts: &SandboxMounts,
        user_command: Option<&str>,
    ) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();

        // Retain capabilities if running as root or privileged
        let is_root = nix::unistd::geteuid().is_root();

        if is_root {
            // When running as root (e.g. sudo volt start), do NOT unshare the user namespace.
            // In the Linux kernel, unsharing the user namespace while sharing the host network namespace
            // creates a child user namespace that forfeits CAP_NET_RAW / CAP_NET_ADMIN over the host network stack.
            // This causes raw socket operations (socket(AF_PACKET, SOCK_RAW), socket(AF_INET, SOCK_RAW))
            // like nmap SYN/UDP scans, masscan, and hping3 to fail with EPERM (Error 1: Operation not permitted).
            // Keeping the root process in the initial user namespace (init_user_ns) retains all network
            // capabilities (--cap-add ALL) over the host network namespace while still isolating PID,
            // IPC, UTS, and filesystem mounts.
            args.push("--unshare-pid".to_string());
            args.push("--unshare-ipc".to_string());
            args.push("--unshare-uts".to_string());
            args.push("--unshare-cgroup-try".to_string());
            args.push("--cap-add".to_string());
            args.push("ALL".to_string());
        } else {
            // Unprivileged rootless sandbox: unshare all namespaces including user namespace,
            // mapping the user to UID 0 / GID 0 inside the sandbox.
            args.push("--unshare-all".to_string());
            args.push("--share-net".to_string());
            args.push("--uid".to_string());
            args.push("0".to_string());
            args.push("--gid".to_string());
            args.push("0".to_string());
        }

        // 3. Fake hostname from hardware profile
        args.push("--hostname".to_string());
        args.push(self.profile.hostname.clone());

        // 4. Base filesystem mounts (read-only host tools, libraries, and third-party tools in /opt)
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
        args.push("/lib32".to_string());
        args.push("/lib32".to_string());

        // Third-party software directory (Chrome, Brave, VS Code, Burp Suite, etc.)
        args.push("--ro-bind-try".to_string());
        args.push("/opt".to_string());
        args.push("/opt".to_string());

        // Symlinks for merged /bin and /sbin
        args.push("--symlink".to_string());
        args.push("usr/bin".to_string());
        args.push("/bin".to_string());

        args.push("--symlink".to_string());
        args.push("usr/sbin".to_string());
        args.push("/sbin".to_string());

        // Devices, POSIX shared memory, and proc
        args.push("--dev".to_string());
        args.push("/dev".to_string());
        args.push("--proc".to_string());
        args.push("/proc".to_string());

        // POSIX shared memory (/dev/shm) tmpfs — required for X11 MIT-SHM, Wayland wl_shm, and Chromium/Firefox
        args.push("--dir".to_string());
        args.push("/dev/shm".to_string());
        args.push("--tmpfs".to_string());
        args.push("/dev/shm".to_string());

        // GPU Direct Rendering for accelerated graphics across Mesa / Intel / AMD / NVIDIA
        args.push("--dev-bind-try".to_string());
        args.push("/dev/dri".to_string());
        args.push("/dev/dri".to_string());

        // 5. System configuration mounts in /etc and /var
        args.push("--dir".to_string());
        args.push("/etc".to_string());

        // Universal system configuration directories across all Linux distros
        let host_etc_mounts = [
            "/etc/fonts",
            "/etc/ssl",
            "/etc/ca-certificates",
            "/etc/pki",
            "/etc/resolv.conf",
            "/etc/localtime",
            "/etc/timezone",
            "/etc/mime.types",
            "/etc/xdg",
            "/etc/gtk-2.0",
            "/etc/gtk-3.0",
            "/etc/gtk-4.0",
            "/etc/glvnd",
            "/etc/vulkan",
            "/etc/alternatives",
            "/etc/nsswitch.conf",
            "/etc/protocols",
            "/etc/services",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/X11",
            "/etc/inputrc",
            "/etc/environment",
        ];
        for path in &host_etc_mounts {
            args.push("--ro-bind-try".to_string());
            args.push(path.to_string());
            args.push(path.to_string());
        }

        // Host Fontconfig cache
        args.push("--ro-bind-try".to_string());
        args.push("/var/cache/fontconfig".to_string());
        args.push("/var/cache/fontconfig".to_string());

        // D-Bus and systemd resolution sockets
        args.push("--ro-bind-try".to_string());
        args.push("/run/dbus".to_string());
        args.push("/run/dbus".to_string());

        args.push("--ro-bind-try".to_string());
        args.push("/run/systemd/resolve".to_string());
        args.push("/run/systemd/resolve".to_string());

        // 6. Identity spoofing layers (mounted over /etc, /proc, and /sys)
        let spoof = &mounts.spoof_dir;

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("etc/hostname").to_string_lossy().to_string());
        args.push("/etc/hostname".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("etc/hosts").to_string_lossy().to_string());
        args.push("/etc/hosts".to_string());

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

        // Also spoof /var/lib/dbus/machine-id if present on host
        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("etc/machine-id").to_string_lossy().to_string());
        args.push("/var/lib/dbus/machine-id".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("proc/cpuinfo").to_string_lossy().to_string());
        args.push("/proc/cpuinfo".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("proc/version").to_string_lossy().to_string());
        args.push("/proc/version".to_string());

        // Sysfs DMI spoofing - ensure parent directories exist
        args.push("--dir".to_string());
        args.push("/sys".to_string());
        args.push("--dir".to_string());
        args.push("/sys/class".to_string());
        args.push("--dir".to_string());
        args.push("/sys/class/dmi".to_string());
        args.push("--dir".to_string());
        args.push("/sys/class/dmi/id".to_string());

        args.push("--ro-bind-try".to_string());
        args.push(spoof.join("sys/class/dmi/id").to_string_lossy().to_string());
        args.push("/sys/class/dmi/id".to_string());

        // 7. Transparent application shims via /volt-shims
        args.push("--dir".to_string());
        args.push("/volt-shims".to_string());
        args.push("--ro-bind".to_string());
        args.push(mounts.shim_bin_dir.to_string_lossy().to_string());
        args.push("/volt-shims".to_string());

        // 8. Writable scratch spaces (tmpfs and case overlay)
        args.push("--tmpfs".to_string());
        args.push("/tmp".to_string());

        args.push("--dir".to_string());
        args.push("/var/tmp".to_string());
        args.push("--tmpfs".to_string());
        args.push("/var/tmp".to_string());

        args.push("--dir".to_string());
        args.push("/run/lock".to_string());
        args.push("--tmpfs".to_string());
        args.push("/run/lock".to_string());

        // Forward host X11 and ICE unix domain sockets into sandbox /tmp
        args.push("--ro-bind-try".to_string());
        args.push("/tmp/.X11-unix".to_string());
        args.push("/tmp/.X11-unix".to_string());

        args.push("--ro-bind-try".to_string());
        args.push("/tmp/.ICE-unix".to_string());
        args.push("/tmp/.ICE-unix".to_string());

        // Forward Wayland / PipeWire / PulseAudio runtime directory if present on host
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            if Path::new(&runtime_dir).exists() {
                args.push("--ro-bind-try".to_string());
                args.push(runtime_dir.clone());
                args.push(runtime_dir);
            }
        }

        let overlay_upper = self.case_dir.join("overlay/upper");
        args.push("--bind".to_string());
        args.push(overlay_upper.to_string_lossy().to_string());
        args.push("/root".to_string());

        // 9. Environment variables
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
        args.push("/volt-shims:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string());

        let host_term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
        args.push("--setenv".to_string());
        args.push("TERM".to_string());
        args.push(host_term);

        // Forward and auto-detect GUI display variables (X11 & Wayland)
        if let Ok(display) = std::env::var("DISPLAY") {
            args.push("--setenv".to_string());
            args.push("DISPLAY".to_string());
            args.push(display);
        } else if Path::new("/tmp/.X11-unix/X0").exists() {
            args.push("--setenv".to_string());
            args.push("DISPLAY".to_string());
            args.push(":0".to_string());
        }

        if let Ok(wayland_display) = std::env::var("WAYLAND_DISPLAY") {
            args.push("--setenv".to_string());
            args.push("WAYLAND_DISPLAY".to_string());
            args.push(wayland_display);
        } else if let Ok(ref runtime) = std::env::var("XDG_RUNTIME_DIR") {
            if Path::new(runtime).join("wayland-0").exists() {
                args.push("--setenv".to_string());
                args.push("WAYLAND_DISPLAY".to_string());
                args.push("wayland-0".to_string());
            }
        }

        if let Ok(ref runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            args.push("--setenv".to_string());
            args.push("XDG_RUNTIME_DIR".to_string());
            args.push(runtime_dir.clone());

            // Auto-configure PulseAudio / PipeWire audio server
            let pulse_socket = Path::new(runtime_dir).join("pulse/native");
            if pulse_socket.exists() {
                args.push("--setenv".to_string());
                args.push("PULSE_SERVER".to_string());
                args.push(format!("unix:{}", pulse_socket.display()));
            }
        }

        // Forward Desktop Environment integration variables (GNOME, KDE Plasma, DDE / Deepin, XFCE, Cinnamon, MATE)
        for var in &[
            "XDG_CURRENT_DESKTOP",
            "XDG_SESSION_TYPE",
            "DESKTOP_SESSION",
            "QT_QPA_PLATFORMTHEME",
            "QT_QPA_PLATFORM",
            "GDK_BACKEND",
        ] {
            if let Ok(val) = std::env::var(var) {
                args.push("--setenv".to_string());
                args.push(var.to_string());
                args.push(val);
            }
        }

        let xauth_path = self.case_dir.join("overlay/upper/.Xauthority");
        if xauth_path.exists() {
            args.push("--setenv".to_string());
            args.push("XAUTHORITY".to_string());
            args.push("/root/.Xauthority".to_string());
        }

        // Disable internal nested namespace sandboxing (VOLT outer sandbox provides isolation)
        args.push("--setenv".to_string());
        args.push("MOZ_DISABLE_CONTENT_SANDBOX".to_string());
        args.push("1".to_string());

        args.push("--setenv".to_string());
        args.push("MOZ_DISABLE_SANDBOX".to_string());
        args.push("1".to_string());

        args.push("--setenv".to_string());
        args.push("NO_SANDBOX".to_string());
        args.push("1".to_string());

        args.push("--setenv".to_string());
        args.push("ELECTRON_DISABLE_SANDBOX".to_string());
        args.push("1".to_string());

        args.push("--setenv".to_string());
        args.push("NO_AT_SPI_BUS".to_string());
        args.push("1".to_string());

        // Signal raw socket availability to sandboxed application shims
        args.push("--setenv".to_string());
        args.push("VOLT_RAW_SOCKETS".to_string());
        args.push(if is_root { "1" } else { "0" }.to_string());

        // Unset desktop session manager to prevent ICE non-local connection rejections
        args.push("--unsetenv".to_string());
        args.push("SESSION_MANAGER".to_string());

        args.push("--chdir".to_string());
        args.push("/root".to_string());

        // 10. Command to execute inside sandbox
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
