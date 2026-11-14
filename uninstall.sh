#!/usr/bin/env bash
# ==============================================================================
# ⚡ VOLT System Uninstaller
# ==============================================================================

set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "❌ Error: Please run as root: sudo ./uninstall.sh"
    exit 1
fi

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
SHARE_DIR="${PREFIX}/share/volt"

echo "🗑️ Uninstalling VOLT..."

if [ -f "${BIN_DIR}/volt" ]; then
    rm -f "${BIN_DIR}/volt"
    echo "  ✓ Removed ${BIN_DIR}/volt"
fi

if [ -d "${SHARE_DIR}" ]; then
    rm -rf "${SHARE_DIR}"
    echo "  ✓ Removed ${SHARE_DIR}"
fi

echo "✅ VOLT uninstalled successfully."
