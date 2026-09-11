#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GN-Shield: System Uninstall Script (Linux)
# Adheres to PRD.md Section 7.5 (Full Reversibility & Cleanup)
# ==============================================================================

BIN_DEST="/usr/local/bin"
CONF_DEST="/etc/gn-shield"
VAR_DEST="/var/lib/gn-shield"
RUN_DEST="/run/gn-shield"
SERVICE_DEST="/etc/systemd/system/gn-shield.service"

PURGE_DATA=false

print_usage() {
    cat <<EOF
Usage: sudo ./uninstall.sh [OPTIONS]

Options:
  --purge         Remove all configuration, audit logs, and data directories without confirmation
  --help, -h      Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge)
            PURGE_DATA=true
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

echo "============================================================"
echo "🛡️  GN-Shield System Uninstaller"
echo "============================================================"

# 1. Privilege Check
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: Root privileges are required to uninstall GN-Shield."
    echo "Please re-run with: sudo ./uninstall.sh"
    exit 1
fi

# 2. Stop and Disable Systemd Service (PRD Section 7.5 Point 5)
echo "==> [1/5] Stopping and removing systemd service..."
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet gn-shield.service 2>/dev/null; then
        echo "  • Stopping gn-shield.service..."
        systemctl stop gn-shield.service
    fi
    if systemctl is-enabled --quiet gn-shield.service 2>/dev/null; then
        echo "  • Disabling gn-shield.service..."
        systemctl disable gn-shield.service
    fi
    if [ -f "$SERVICE_DEST" ]; then
        rm -f "$SERVICE_DEST"
        systemctl daemon-reload
        echo "  • Removed $SERVICE_DEST"
    fi
fi

# 3. Remove Native Messaging Manifests (PRD Section 7.5 Point 2)
echo "==> [2/5] Removing browser native messaging companion manifests..."
MANIFEST_LOCATIONS=(
    "/etc/opt/chrome/native-messaging-hosts/com.gnshield.host.json"
    "/etc/chromium/native-messaging-hosts/com.gnshield.host.json"
    "/usr/lib/mozilla/native-messaging-hosts/com.gnshield.host.json"
    "/etc/brave/native-messaging-hosts/com.gnshield.host.json"
    "/etc/opt/edge/native-messaging-hosts/com.gnshield.host.json"
)

for mf in "${MANIFEST_LOCATIONS[@]}"; do
    if [ -f "$mf" ]; then
        rm -f "$mf"
        echo "  • Removed manifest: $mf"
    fi
done

# 4. Remove Binaries
echo "==> [3/5] Removing installed binaries from $BIN_DEST..."
rm -f "$BIN_DEST/gn-shield-core"
rm -f "$BIN_DEST/gn-shield-cli"
rm -f "$BIN_DEST/gn-shield-native-host"
echo "  • Removed gn-shield-core, gn-shield-cli, gn-shield-native-host"

# 5. Clean Runtime Socket Directory
echo "==> [4/5] Cleaning runtime socket..."
rm -rf "$RUN_DEST"

# 6. Quarantine and Data Retention (PRD Section 7.5 Point 4)
echo "==> [5/5] Reviewing quarantined files and storage..."
QUARANTINE_DIR="$VAR_DEST/quarantine"
if [ -d "$QUARANTINE_DIR" ] && [ "$(ls -A "$QUARANTINE_DIR" 2>/dev/null)" ]; then
    echo "  ⚠️ Warning: Quarantined files detected in $QUARANTINE_DIR:"
    ls -l "$QUARANTINE_DIR"
    echo ""
    echo "  In accordance with PRD.md Section 7.5, quarantined files are preserved"
    echo "  to prevent accidental data loss in case of unresolved false positives."
    if [ "$PURGE_DATA" = false ]; then
        echo "  Preserving $VAR_DEST and $CONF_DEST."
        echo "  To completely remove all data and quarantine files, pass --purge."
    fi
fi

if [ "$PURGE_DATA" = true ]; then
    echo "  • Purging data and configuration directories (--purge specified)..."
    rm -rf "$VAR_DEST"
    rm -rf "$CONF_DEST"
    echo "  • Removed $VAR_DEST and $CONF_DEST"
    if getent group gn-shield >/dev/null 2>&1; then
        groupdel gn-shield 2>/dev/null || true
        echo "  • Removed system group 'gn-shield'"
    fi
else
    echo "  • Configuration preserved at $CONF_DEST (remove manually or re-run with --purge)"
fi

echo ""
echo "============================================================"
echo "✅ GN-Shield has been uninstalled successfully."
echo "============================================================"
echo ""
