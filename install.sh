#!/usr/bin/env bash
# ==============================================================================
# ⚡ VOLT System Installer
# Installs binary to /usr/local/bin and hardware profiles to /usr/local/share/volt
# sudo is strictly restricted to copying files to system directories.
# All compilation is performed under the current (or invoking) user.
# ==============================================================================

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
SHARE_DIR="${PREFIX}/share/volt"
PROFILE_DIR="${SHARE_DIR}/profiles"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "⚡ VOLT System Installer"

# 1. Locate or build binary
VOLT_BIN=""
if [ -f "${SCRIPT_DIR}/volt" ]; then
    VOLT_BIN="${SCRIPT_DIR}/volt"
elif [ -f "${SCRIPT_DIR}/target/release/volt" ]; then
    VOLT_BIN="${SCRIPT_DIR}/target/release/volt"
elif [ -f "${SCRIPT_DIR}/target/debug/volt" ]; then
    VOLT_BIN="${SCRIPT_DIR}/target/debug/volt"
elif [ -f "${SCRIPT_DIR}/Cargo.toml" ]; then
    echo "🔨 'volt' binary not found. Compiling from source..."
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        echo "   (Building as user '${SUDO_USER}' to preserve file ownership)"
        sudo -u "$SUDO_USER" env "PATH=$PATH" cargo build --release --manifest-path "${SCRIPT_DIR}/Cargo.toml"
    else
        cargo build --release --manifest-path "${SCRIPT_DIR}/Cargo.toml"
    fi
    VOLT_BIN="${SCRIPT_DIR}/target/release/volt"
else
    echo "❌ Error: Could not locate 'volt' binary or 'Cargo.toml' in ${SCRIPT_DIR}."
    echo "   If building from source, please run 'cargo build --release' first."
    exit 1
fi

if [ ! -f "${VOLT_BIN}" ]; then
    echo "❌ Error: Could not locate executable at ${VOLT_BIN}"
    exit 1
fi

# 2. Determine if sudo is needed for system directories
SUDO_CMD=""
check_dir_writable() {
    local target="$1"
    while [ ! -d "$target" ] && [ "$target" != "/" ] && [ "$target" != "." ]; do
        target="$(dirname "$target")"
    done
    [ -w "$target" ]
}

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    if ! check_dir_writable "${BIN_DIR}" || ! check_dir_writable "${SHARE_DIR}"; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO_CMD="sudo"
            echo "🔒 Elevated privileges required to copy files to ${PREFIX}."
        else
            echo "❌ Error: Destination ${PREFIX} is not writable and 'sudo' is not available."
            echo "   Please run as root or install to a user directory (e.g. PREFIX=\$HOME/.local ./install.sh)"
            exit 1
        fi
    fi
fi

# 3. Install binary
echo "  [1/4] Installing binary to ${BIN_DIR}/volt..."
$SUDO_CMD install -d "${BIN_DIR}"
$SUDO_CMD install -m 755 "${VOLT_BIN}" "${BIN_DIR}/volt"

# 4. Install standard hardware profiles
echo "  [2/4] Installing hardware profiles to ${PROFILE_DIR}..."
$SUDO_CMD install -d "${PROFILE_DIR}"

if [ -d "${SCRIPT_DIR}/profiles" ]; then
    $SUDO_CMD cp -r "${SCRIPT_DIR}/profiles/"*.json "${PROFILE_DIR}/" 2>/dev/null || true
fi

# Set read permissions for profiles
$SUDO_CMD chmod -R 644 "${PROFILE_DIR}"/*.json 2>/dev/null || true
$SUDO_CMD chmod 755 "${PROFILE_DIR}"

# 5. Set network capabilities for raw scanning (nmap -sS)
echo "  [3/4] Granting CAP_NET_RAW network capability for stealth scans..."
if command -v setcap >/dev/null 2>&1; then
    $SUDO_CMD setcap cap_net_raw,cap_net_admin+eip "${BIN_DIR}/volt" 2>/dev/null && \
        echo "        ✓ CAP_NET_RAW granted successfully." || \
        echo "        ℹ Notice: setcap failed (kernel may restrict capabilities in container)."
else
    echo "        ℹ Notice: 'setcap' not found. Raw scans may require running via sudo."
fi

# 6. Verify installation
echo "  [4/4] Verifying installation..."
if [ -x "${BIN_DIR}/volt" ]; then
    VERSION="$("${BIN_DIR}/volt" --version 2>/dev/null || echo "volt 0.1.0")"
    echo ""
    echo "=========================================================================="
    echo "✅ VOLT Installed Successfully!"
    echo "   Binary:   ${BIN_DIR}/volt"
    echo "   Profiles: ${PROFILE_DIR}/"
    echo "   Version:  ${VERSION}"
    echo "=========================================================================="
    echo "You can now run 'volt --help' from any terminal."
else
    echo "❌ Verification failed. Could not execute ${BIN_DIR}/volt"
    exit 1
fi
