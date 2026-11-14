#!/usr/bin/env bash
# ==============================================================================
# ⚡ VOLT System Uninstaller
# Removes binary from /usr/local/bin and hardware profiles from /usr/local/share/volt
# sudo is strictly restricted to deleting files from system directories.
# ==============================================================================

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
SHARE_DIR="${PREFIX}/share/volt"

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
            echo "🔒 Elevated privileges required to remove files from ${PREFIX}."
        else
            echo "❌ Error: Destination ${PREFIX} is not writable and 'sudo' is not available."
            echo "   Please run as root: sudo ./uninstall.sh"
            exit 1
        fi
    fi
fi

echo "🗑️ Uninstalling VOLT..."

if [ -f "${BIN_DIR}/volt" ]; then
    $SUDO_CMD rm -f "${BIN_DIR}/volt"
    echo "  ✓ Removed ${BIN_DIR}/volt"
fi

if [ -d "${SHARE_DIR}" ]; then
    $SUDO_CMD rm -rf "${SHARE_DIR}"
    echo "  ✓ Removed ${SHARE_DIR}"
fi

echo "✅ VOLT uninstalled successfully."
