#!/usr/bin/env bash
# ==============================================================================
# ⚡ VOLT System Installer
# Installs binary to /usr/local/bin and hardware profiles to /usr/local/share/volt
# ==============================================================================

set -euo pipefail

# Ensure running with root / sudo
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "❌ Error: This installation script must be run as root or with sudo:"
    echo "   sudo ./install.sh"
    exit 1
fi

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
SHARE_DIR="${PREFIX}/share/volt"
PROFILE_DIR="${SHARE_DIR}/profiles"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "⚡ Installing VOLT (Volatile Observation & Logging Terminal)..."

# 1. Locate binary
VOLT_BIN=""
if [ -f "${SCRIPT_DIR}/volt" ]; then
    VOLT_BIN="${SCRIPT_DIR}/volt"
elif [ -f "${SCRIPT_DIR}/target/release/volt" ]; then
    VOLT_BIN="${SCRIPT_DIR}/target/release/volt"
elif [ -f "${SCRIPT_DIR}/target/debug/volt" ]; then
    VOLT_BIN="${SCRIPT_DIR}/target/debug/volt"
else
    echo "❌ Error: Could not locate 'volt' binary in ${SCRIPT_DIR}."
    echo "   If building from source, please run 'cargo build --release' first."
    exit 1
fi

# 2. Install binary
echo "  [1/4] Installing binary to ${BIN_DIR}/volt..."
install -d "${BIN_DIR}"
install -m 755 "${VOLT_BIN}" "${BIN_DIR}/volt"

# 3. Install standard hardware profiles to /usr/local/share/volt/profiles
echo "  [2/4] Installing hardware profiles to ${PROFILE_DIR}..."
install -d "${PROFILE_DIR}"

if [ -d "${SCRIPT_DIR}/profiles" ]; then
    cp -r "${SCRIPT_DIR}/profiles/"*.json "${PROFILE_DIR}/" 2>/dev/null || true
fi

# Set read permissions for profiles
chmod -R 644 "${PROFILE_DIR}"/*.json 2>/dev/null || true
chmod 755 "${PROFILE_DIR}"

# 4. Set network capabilities for raw scanning (nmap -sS)
echo "  [3/4] Granting CAP_NET_RAW network capability for stealth scans..."
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin+eip "${BIN_DIR}/volt" 2>/dev/null && \
        echo "        ✓ CAP_NET_RAW granted successfully." || \
        echo "        ℹ Notice: setcap failed (kernel may restrict capabilities in container)."
else
    echo "        ℹ Notice: 'setcap' not found. Raw scans may require running via sudo."
fi

# 5. Verify installation
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
