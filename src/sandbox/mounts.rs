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

        // 1. Transparent privilege escalation shims (sudo, su, doas, pkexec)
        let sudo_shim = r#"#!/bin/bash
# VOLT Smart sudo shim — user is already UID 0 inside sandbox
LOGIN_SHELL=0
while [ $# -gt 0 ]; do
    case "$1" in
        -i|--login)
            LOGIN_SHELL=1
            shift
            ;;
        -s|--shell)
            shift
            ;;
        -u|--user|-g|--group|-p|--prompt)
            shift 2
            ;;
        -E|--preserve-env|-H|--set-home|-S|--stdin|-b|--background|-n|--non-interactive|-v|--validate|-k|--reset-timestamp)
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            shift
            ;;
        *)
            break
            ;;
    esac
done

if [ $# -eq 0 ]; then
    if [ $LOGIN_SHELL -eq 1 ]; then
        exec /bin/bash -l
    else
        exec /bin/bash
    fi
else
    exec "$@"
fi
"#;
        Self::write_executable_shim(&shim_bin_dir.join("sudo"), sudo_shim)?;

        let su_shim = r#"#!/bin/bash
# VOLT su shim — user is already UID 0 inside sandbox
LOGIN=0
for arg in "$@"; do
    case "$arg" in
        -|--login|-l)
            LOGIN=1
            ;;
    esac
done

if [ $LOGIN -eq 1 ]; then
    exec /bin/bash -l
else
    exec /bin/bash
fi
"#;
        Self::write_executable_shim(&shim_bin_dir.join("su"), su_shim)?;

        let doas_shim = r#"#!/bin/bash
# VOLT doas shim
while [ $# -gt 0 ]; do
    case "$1" in
        -u) shift 2 ;;
        -s) exec /bin/bash ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
if [ $# -eq 0 ]; then
    exec /bin/bash
else
    exec "$@"
fi
"#;
        Self::write_executable_shim(&shim_bin_dir.join("doas"), doas_shim)?;

        let pkexec_shim = r#"#!/bin/bash
# VOLT pkexec shim
while [ $# -gt 0 ]; do
    case "$1" in
        --user) shift 2 ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
if [ $# -eq 0 ]; then
    exec /bin/bash
else
    exec "$@"
fi
"#;
        Self::write_executable_shim(&shim_bin_dir.join("pkexec"), pkexec_shim)?;

        // Package manager guidance shims
        let pkg_shim = r#"#!/bin/bash
PKG=$(basename "$0")
REAL_BIN=""
for bin in "/usr/bin/$PKG" "/bin/$PKG"; do
    if [ -x "$bin" ] && [ "$bin" != "$0" ]; then
        REAL_BIN="$bin"
        break
    fi
done
if [ -z "$REAL_BIN" ]; then
    NEW_PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "/volt-shims" | paste -sd:)
    REAL_BIN=$(PATH="$NEW_PATH" which "$PKG" 2>/dev/null)
fi

for arg in "$@"; do
    case "$arg" in
        install|update|upgrade|dist-upgrade|remove|purge|-S|-Syu|-R)
            echo "⚡ [VOLT] Notice: VOLT forensic sandbox guarantees zero host mutation." >&2
            echo "⚡ [VOLT] Host filesystem (/usr, /lib) is strictly read-only inside this session." >&2
            echo "⚡ [VOLT] To install permanent host tools, run on your host: sudo $PKG $@" >&2
            echo "⚡ [VOLT] For session-only tools, download portable binaries or run standalone scripts in /root or /tmp." >&2
            echo "" >&2
            ;;
    esac
done

if [ -n "$REAL_BIN" ]; then
    exec "$REAL_BIN" "$@"
else
    echo "$PKG: command not found" >&2
    exit 127
fi
"#;
        for pkg in &["apt", "apt-get", "pacman", "dnf", "yum", "apk"] {
            Self::write_executable_shim(&shim_bin_dir.join(pkg), pkg_shim)?;
        }

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
        Self::write_browser_shim(
            &shim_bin_dir,
            "librewolf",
            &["/usr/bin/librewolf", "/usr/lib/librewolf/librewolf"],
            true,
        )?;

        // 3. Chromium family shims across all distros and packages
        let chrome_binaries = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/opt/google/chrome/chrome",
            "/opt/google/chrome/google-chrome",
        ];
        Self::write_browser_shim(&shim_bin_dir, "google-chrome", &chrome_binaries, false)?;
        Self::write_browser_shim(
            &shim_bin_dir,
            "google-chrome-stable",
            &chrome_binaries,
            false,
        )?;

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
        Self::write_browser_shim(
            &shim_bin_dir,
            "microsoft-edge-stable",
            &edge_binaries,
            false,
        )?;

        Self::write_browser_shim(
            &shim_bin_dir,
            "vivaldi",
            &["/usr/bin/vivaldi", "/opt/vivaldi/vivaldi"],
            false,
        )?;
        Self::write_browser_shim(
            &shim_bin_dir,
            "opera",
            &["/usr/bin/opera", "/usr/lib/x86_64-linux-gnu/opera/opera"],
            false,
        )?;

        // 4. Electron application shim (VS Code, etc.)
        let code_binaries = [
            "/usr/bin/code",
            "/usr/share/code/code",
            "/opt/visual-studio-code/code",
        ];
        Self::write_browser_shim(&shim_bin_dir, "code", &code_binaries, false)?;

        // 5. Intelligent network tool shims (nmap, ping, masscan)
        Self::write_network_shims(&shim_bin_dir)?;

        // 6. Cross-terminal shared environment manager (volt-env, env-share)
        Self::write_env_shim(&shim_bin_dir)?;

        // Prepare clean interactive root environment (.bashrc)
        let root_dir = case_dir.join("overlay/upper");
        fs::create_dir_all(&root_dir)?;

        // Ensure shared environment file exists
        let env_file = root_dir.join(".volt_env");
        if !env_file.exists() {
            fs::write(
                &env_file,
                "# VOLT Shared Environment Variables\n# Automatically synchronized across all active shells and saved for future sessions.\n",
            )?;
        }

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
        let mut bashrc_content = format!(
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
             alias nmap='nmap'\n\
             alias ping='ping'\n\
             alias env-share='volt-env'\n\
             alias volt-env='volt-env'\n\
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

        let env_engine = r#"
# ==============================================================================
# ⚡ VOLT Real-Time Cross-Terminal Environment Sharing Engine
# Automatically synchronizes all exported variables across all active terminals
# and persists them permanently across session restarts.
# ==============================================================================
_VOLT_ENV_FILE="/root/.volt_env"
_VOLT_SYNC_MARKER="/tmp/.volt_sync_$$"
_VOLT_MANAGED_VARS=""

touch "$_VOLT_SYNC_MARKER" 2>/dev/null

__volt_sync_env() {
    [ -f "$_VOLT_ENV_FILE" ] || return 0
    if [ "$_VOLT_ENV_FILE" -nt "$_VOLT_SYNC_MARKER" ] || [ -z "$_VOLT_MANAGED_VARS" ]; then
        touch "$_VOLT_SYNC_MARKER" 2>/dev/null
        local current_keys
        current_keys=$(grep -E "^export [a-zA-Z_][a-zA-Z0-9_]*=" "$_VOLT_ENV_FILE" 2>/dev/null | sed -E 's/^export ([a-zA-Z_][a-zA-Z0-9_]*)=.*/\1/')

        local added_vars=()
        for k in $current_keys; do
            if ! echo "$_VOLT_MANAGED_VARS" | grep -qw "$k"; then
                added_vars+=("$k")
            fi
        done

        if [ -n "$_VOLT_MANAGED_VARS" ]; then
            local old_var
            for old_var in $_VOLT_MANAGED_VARS; do
                if ! echo "$current_keys" | grep -qw "$old_var"; then
                    builtin unset "$old_var"
                fi
            done
        fi

        local prev_trap
        prev_trap=$(trap -p DEBUG)
        trap '' DEBUG
        . "$_VOLT_ENV_FILE" 2>/dev/null
        if [ -n "$prev_trap" ]; then
            eval "$prev_trap"
        else
            trap - DEBUG
        fi

        # Notify if new variables were synced from another terminal (interactive only)
        if [ -z "$VOLT_ENV_QUIET" ] && [ -t 1 ] && [ -n "$_VOLT_MANAGED_VARS" ] && [ ${#added_vars[@]} -gt 0 ]; then
            for k in "${added_vars[@]}"; do
                echo -e "\033[0;36m⚡ [VOLT]\033[0m Synced from other shell: \033[1m$k\033[0m=\"${!k}\"" >&2
            done
        fi

        _VOLT_MANAGED_VARS="$current_keys"
    fi
}

export() {
    if [ $# -eq 0 ]; then
        builtin export
        return $?
    fi
    builtin export "$@"
    local ret=$?
    [ $ret -ne 0 ] && return $ret

    local arg key val updated=0 synced_keys=()
    for arg in "$@"; do
        case "$arg" in
            -p|-f|-n|-*) continue ;;
            *=*) key="${arg%%=*}" ;;
            *) key="$arg" ;;
        esac
        if [[ "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
            case "$key" in
                PATH|HOME|USER|SHELL|TERM|PS1|SHLVL|PWD|OLDPWD|_|IFS|PROMPT_COMMAND|HISTFILE|HISTSIZE|HISTFILESIZE|UID|EUID|PPID|BASH*|VOLT_*|_VOLT_*) continue ;;
            esac
            val="${!key}"
            mkdir -p /root 2>/dev/null
            touch "$_VOLT_ENV_FILE" 2>/dev/null
            (
                if command -v flock >/dev/null 2>&1; then
                    flock -x 200
                fi
                sed -i "/^export ${key}=/d" "$_VOLT_ENV_FILE" 2>/dev/null || true
                printf "export %s=%q\n" "$key" "$val" >> "$_VOLT_ENV_FILE"
            ) 200>"/tmp/.volt_env.lock"
            updated=1
            synced_keys+=("$key")
        fi
    done

    if [ $updated -eq 1 ]; then
        touch "$_VOLT_ENV_FILE" 2>/dev/null
        touch "$_VOLT_SYNC_MARKER" 2>/dev/null
        _VOLT_MANAGED_VARS=$(grep -E "^export [a-zA-Z_][a-zA-Z0-9_]*=" "$_VOLT_ENV_FILE" 2>/dev/null | sed -E 's/^export ([a-zA-Z_][a-zA-Z0-9_]*)=.*/\1/')
        if [ -z "$VOLT_ENV_QUIET" ] && [ -t 1 ]; then
            for k in "${synced_keys[@]}"; do
                echo -e "\033[0;36m⚡ [VOLT]\033[0m Shared across shells: \033[1m$k\033[0m=\"${!k}\"" >&2
            done
        fi
    fi
    return $ret
}

unset() {
    builtin unset "$@"
    local ret=$?
    local arg updated=0 unset_keys=()
    for arg in "$@"; do
        case "$arg" in
            -*) continue ;;
            *)
                if [ -f "$_VOLT_ENV_FILE" ]; then
                    (
                        if command -v flock >/dev/null 2>&1; then
                            flock -x 200
                        fi
                        sed -i "/^export ${arg}=/d" "$_VOLT_ENV_FILE" 2>/dev/null || true
                    ) 200>"/tmp/.volt_env.lock"
                    updated=1
                    unset_keys+=("$arg")
                fi
                ;;
        esac
    done
    if [ $updated -eq 1 ]; then
        touch "$_VOLT_ENV_FILE" 2>/dev/null
        touch "$_VOLT_SYNC_MARKER" 2>/dev/null
        _VOLT_MANAGED_VARS=$(grep -E "^export [a-zA-Z_][a-zA-Z0-9_]*=" "$_VOLT_ENV_FILE" 2>/dev/null | sed -E 's/^export ([a-zA-Z_][a-zA-Z0-9_]*)=.*/\1/')
        if [ -z "$VOLT_ENV_QUIET" ] && [ -t 1 ]; then
            for k in "${unset_keys[@]}"; do
                echo -e "\033[0;36m⚡ [VOLT]\033[0m Unset across shells: \033[1m$k\033[0m" >&2
            done
        fi
    fi
    return $ret
}

__volt_sync_env
PROMPT_COMMAND="__volt_sync_env${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
trap '__volt_sync_env' DEBUG
"#;
        bashrc_content.push_str(env_engine);
        fs::write(&bashrc, bashrc_content)?;

        Ok(Self {
            spoof_dir,
            shim_bin_dir,
        })
    }

    fn write_browser_shim(
        dir: &Path,
        name: &str,
        binaries: &[&str],
        is_firefox: bool,
    ) -> Result<()> {
        let bin_list = binaries
            .iter()
            .map(|b| format!("\"{}\"", b))
            .collect::<Vec<_>>()
            .join(" ");
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

    fn write_network_shims(dir: &Path) -> Result<()> {
        // 1. Intelligent nmap shim
        // In unprivileged user namespaces, raw sockets (SOCK_RAW / AF_PACKET) are denied by kernel.
        // Automatically injects --unprivileged (TCP Connect scan), preventing crashes on tun0/eth.
        // If user explicitly asks for -sS (SYN scan), converts to -sT with informative notice.
        let nmap_shim = r#"#!/bin/bash
# VOLT Application Shim: Intelligent unprivileged execution for nmap
REAL_NMAP=""
for bin in /usr/bin/nmap /usr/local/bin/nmap /bin/nmap; do
    if [ -x "$bin" ] && [ "$bin" != "$0" ]; then
        REAL_NMAP="$bin"
        break
    fi
done

if [ -z "$REAL_NMAP" ]; then
    NEW_PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "/volt-shims" | paste -sd:)
    REAL_NMAP=$(PATH="$NEW_PATH" which nmap 2>/dev/null)
fi

if [ -z "$REAL_NMAP" ]; then
    echo "nmap: command not found" >&2
    exit 127
fi

# Check if raw sockets are functional in this session
CAN_RAW=0
if [ "$VOLT_RAW_SOCKETS" = "1" ]; then
    # Test if raw sockets can genuinely be opened in the current environment
    if python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW); s.close()" 2>/dev/null; then
        CAN_RAW=1
    elif perl -e 'use Socket; socket(my $s, PF_INET, SOCK_RAW, 255) or exit(1);' 2>/dev/null; then
        CAN_RAW=1
    elif [ "$(id -u)" -eq 0 ]; then
        CAN_RAW=1
    fi
fi

if [ "$CAN_RAW" -eq 1 ]; then
    exec "$REAL_NMAP" "$@"
fi

# Check arguments
HAS_PRIV_FLAG=0
HAS_SYN_FLAG=0
RAW_SCAN_NAME=""

for arg in "$@"; do
    case "$arg" in
        --unprivileged)
            HAS_PRIV_FLAG=1
            ;;
        --privileged)
            exec "$REAL_NMAP" "$@"
            ;;
        -sS)
            HAS_SYN_FLAG=1
            ;;
        -sU)
            RAW_SCAN_NAME="UDP scan (-sU)"
            ;;
        -sO)
            RAW_SCAN_NAME="IP protocol scan (-sO)"
            ;;
        -sA|-sW|-sM)
            RAW_SCAN_NAME="Raw TCP probe scan ($arg)"
            ;;
        -sN|-sF|-sX)
            RAW_SCAN_NAME="TCP Stealth scan ($arg)"
            ;;
        -O)
            RAW_SCAN_NAME="TCP/IP OS fingerprinting (-O)"
            ;;
    esac
done

if [ "$HAS_PRIV_FLAG" -eq 1 ]; then
    exec "$REAL_NMAP" "$@"
fi

# If a scan fundamentally requiring raw sockets was requested in an unprivileged session
if [ -n "$RAW_SCAN_NAME" ]; then
    echo "❌ [VOLT] Error: $RAW_SCAN_NAME requires raw packet sockets (CAP_NET_RAW)." >&2
    echo "⚡ [VOLT] Raw packet crafting is restricted in this unprivileged sandbox session." >&2
    echo "⚡ [VOLT] To enable raw packet scanning (-sS SYN, -sU UDP, -O OS detection):" >&2
    echo "⚡ [VOLT]     1. Exit current session: exit" >&2
    echo "⚡ [VOLT]     2. Launch VOLT with root privileges: sudo volt start --case <CASE>" >&2
    echo "⚡ [VOLT]" >&2
    echo "⚡ [VOLT] Tip: For unprivileged TCP scanning in this session, use:" >&2
    echo "⚡ [VOLT]     nmap -sT [options] <target>" >&2
    exit 1
fi

if [ "$HAS_SYN_FLAG" -eq 1 ]; then
    echo "⚡ [VOLT] Notice: Raw sockets unavailable in unprivileged sandbox." >&2
    echo "⚡ [VOLT] Converting SYN scan (-sS) to TCP Connect scan (-sT --unprivileged)." >&2
    echo "⚡ [VOLT] (Tip: For raw packet SYN scanning, launch VOLT with: sudo volt start --case <CASE>)" >&2
    NEW_ARGS=()
    for arg in "$@"; do
        if [ "$arg" = "-sS" ]; then
            NEW_ARGS+=("-sT")
        else
            NEW_ARGS+=("$arg")
        fi
    done
    exec "$REAL_NMAP" --unprivileged "${NEW_ARGS[@]}"
fi

exec "$REAL_NMAP" --unprivileged "$@"
"#;
        Self::write_executable_shim(&dir.join("nmap"), nmap_shim)?;

        // 2. Intelligent ping shim
        let ping_shim = r#"#!/bin/bash
# VOLT Application Shim: ping
REAL_PING=""
for bin in /bin/ping /usr/bin/ping; do
    if [ -x "$bin" ] && [ "$bin" != "$0" ]; then
        REAL_PING="$bin"
        break
    fi
done

if [ -z "$REAL_PING" ]; then
    echo "ping: command not found" >&2
    exit 127
fi

if [ "$VOLT_RAW_SOCKETS" = "1" ]; then
    exec "$REAL_PING" "$@"
fi

# Test if native ping works (e.g. ping_group_range allowed)
OUTPUT=$("$REAL_PING" -c 1 -W 1 127.0.0.1 2>&1)
if [ $? -eq 0 ]; then
    exec "$REAL_PING" "$@"
fi

# In unprivileged containers, raw ICMP socket is denied by kernel without CAP_NET_RAW.
# Extract target and use unprivileged nmap ping scan
TARGET=""
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        *) TARGET="$arg";;
    esac
done

if [ -n "$TARGET" ]; then
    echo "⚡ [VOLT] Notice: ICMP raw sockets require CAP_NET_RAW. Using unprivileged TCP/ICMP probe via nmap:" >&2
    exec nmap -sn --unprivileged "$TARGET"
else
    exec "$REAL_PING" "$@"
fi
"#;
        Self::write_executable_shim(&dir.join("ping"), ping_shim)?;

        // 3. Informative masscan shim
        let masscan_shim = r#"#!/bin/bash
# VOLT Application Shim: masscan
REAL_MASSCAN=""
for bin in /usr/bin/masscan /usr/local/bin/masscan; do
    if [ -x "$bin" ] && [ "$bin" != "$0" ]; then
        REAL_MASSCAN="$bin"
        break
    fi
done

if [ -z "$REAL_MASSCAN" ]; then
    NEW_PATH=$(echo "$PATH" | tr ':' '\n' | grep -v "/volt-shims" | paste -sd:)
    REAL_MASSCAN=$(PATH="$NEW_PATH" which masscan 2>/dev/null)
fi

if [ -z "$REAL_MASSCAN" ]; then
    echo "masscan: command not found" >&2
    exit 127
fi

if [ "$VOLT_RAW_SOCKETS" = "1" ]; then
    exec "$REAL_MASSCAN" "$@"
fi

echo "❌ [VOLT] Error: masscan requires raw packet sockets (CAP_NET_RAW) to craft custom IP packets." >&2
echo "⚡ [VOLT] To use masscan, launch VOLT with: sudo volt start --case <CASE>" >&2
echo "⚡ [VOLT] Or use nmap: nmap -p- --unprivileged <target>" >&2
exit 1
"#;
        Self::write_executable_shim(&dir.join("masscan"), masscan_shim)?;

        Ok(())
    }

    fn write_env_shim(dir: &Path) -> Result<()> {
        let content = r#"#!/bin/bash
# VOLT Shared Environment Manager (In-Sandbox Utility)
ENV_FILE="/root/.volt_env"
SYNC_FILE="/root/.volt_env_sync"

mkdir -p /root 2>/dev/null
touch "$ENV_FILE" 2>/dev/null

show_help() {
    echo "⚡ VOLT Shared Environment Manager"
    echo "Variables set or exported here are automatically synchronized across all"
    echo "active terminals in this session and permanently saved for next open."
    echo ""
    echo "Usage:"
    echo "  volt-env                         List all shared environment variables"
    echo "  volt-env list                    List all shared environment variables"
    echo "  volt-env get <KEY>               Print the value of a shared variable"
    echo "  volt-env set <KEY> <VALUE>       Set and broadcast a variable to all shells"
    echo "  volt-env unset <KEY>             Unset a variable across all shells"
    echo "  volt-env clear                   Clear all shared environment variables"
    echo "  volt-env export                  Print variables in export syntax (for eval)"
    echo "  volt-env sync                    Force immediate re-synchronization from disk"
    echo ""
    echo "Tip: Standard 'export KEY=val' in any terminal automatically shares and saves too."
}

case "${1:-list}" in
    list|"")
        if [ ! -s "$ENV_FILE" ]; then
            echo "⚡ No shared environment variables currently defined."
            echo "  Export any variable in any shell: export TARGET_IP=192.168.1.1"
            echo "  Or use: volt-env set TARGET_IP 192.168.1.1"
            exit 0
        fi
        echo "⚡ VOLT Shared Environment Variables (/root/.volt_env):"
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
                export\ *=*|*=* )
                    clean="${line#export }"
                    k="${clean%%=*}"
                    v="${clean#*=}"
                    printf "  \033[1;36m%-20s\033[0m = %s\n" "$k" "$v"
                    ;;
            esac
        done < "$ENV_FILE"
        count=$(grep -c -E "^(export )?[a-zA-Z_][a-zA-Z0-9_]*=" "$ENV_FILE" 2>/dev/null || echo 0)
        echo ""
        echo "✓ $count variable(s) synchronized across all terminals."
        ;;
    get)
        if [ -z "$2" ]; then
            echo "Usage: volt-env get <KEY>" >&2
            exit 1
        fi
        key="$2"
        val=$(grep -E "^(export )?${key}=" "$ENV_FILE" 2>/dev/null | tail -n1 | sed -E "s/^(export )?${key}=//")
        if [ -n "$val" ]; then
            eval "echo $val"
        fi
        ;;
    set)
        if [ -z "$2" ]; then
            echo "Usage: volt-env set <KEY> <VALUE>" >&2
            exit 1
        fi
        key="$2"
        shift 2
        val="$*"
        if [[ ! "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
            echo "Error: Invalid variable name '$key'" >&2
            exit 1
        fi
        sed -i "/^[[:space:]]*\(export \)\?${key}=/d" "$ENV_FILE" 2>/dev/null || true
        printf "export %s=%q\n" "$key" "$val" >> "$ENV_FILE"
        touch "$ENV_FILE" 2>/dev/null
        touch "$SYNC_FILE" 2>/dev/null
        echo "✓ Shared: $key=$val (broadcast to all terminals)"
        ;;
    unset)
        if [ -z "$2" ]; then
            echo "Usage: volt-env unset <KEY>" >&2
            exit 1
        fi
        key="$2"
        sed -i "/^[[:space:]]*\(export \)\?${key}=/d" "$ENV_FILE" 2>/dev/null || true
        touch "$ENV_FILE" 2>/dev/null
        touch "$SYNC_FILE" 2>/dev/null
        echo "✓ Unset: $key (removed from all terminals)"
        ;;
    clear)
        > "$ENV_FILE"
        touch "$ENV_FILE" 2>/dev/null
        touch "$SYNC_FILE" 2>/dev/null
        echo "✓ Cleared all shared environment variables."
        ;;
    export)
        cat "$ENV_FILE" 2>/dev/null
        ;;
    sync)
        if [ -f "$ENV_FILE" ]; then
            . "$ENV_FILE"
            echo "✓ Environment synchronized with $ENV_FILE"
        fi
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac
"#;
        Self::write_executable_shim(&dir.join("volt-env"), content)?;
        Self::write_executable_shim(&dir.join("env-share"), content)?;
        Ok(())
    }

    fn write_executable_shim(path: &Path, content: &str) -> Result<()> {
        fs::write(path, content)?;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
        Ok(())
    }
}
