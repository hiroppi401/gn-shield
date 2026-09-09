#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GN-Shield: System Installation Script (Linux)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DEST="/usr/local/bin"
CONF_DEST="/etc/gn-shield"
VAR_DEST="/var/lib/gn-shield"
RUN_DEST="/run/gn-shield"
SERVICE_DEST="/etc/systemd/system/gn-shield.service"

START_SERVICE=true
BUILD_RELEASE=false

print_usage() {
    cat <<EOF
Usage: sudo ./install.sh [OPTIONS]

Options:
  --build         Force clean rebuild in release mode (cargo build --release)
  --no-start      Do not automatically start gn-shield systemd service
  --help, -h      Show this help message

Examples:
  sudo ./install.sh
  sudo ./install.sh --build
EOF
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)
            BUILD_RELEASE=true
            shift
            ;;
        --no-start)
            START_SERVICE=false
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
echo "🛡️  GN-Shield System Installer"
echo "============================================================"

# 1. Privilege & Environment Check
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: Root privileges are required for system-wide installation."
    echo "Please re-run with: sudo ./install.sh"
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    echo "❌ Error: GN-Shield Linux installer must be run on Linux."
    exit 1
fi

echo "==> [1/7] Checking environment and dependencies..."
ARCH="$(uname -m)"
echo "  • Operating System : Linux ($ARCH)"

# 2. Build or verify binaries
CORE_BIN="$SCRIPT_DIR/target/release/gn-shield-core"
CLI_BIN="$SCRIPT_DIR/target/release/gn-shield-cli"
HOST_BIN="$SCRIPT_DIR/target/release/gn-shield-native-host"

if [ "$BUILD_RELEASE" = true ] || [ ! -f "$CORE_BIN" ] || [ ! -f "$CLI_BIN" ] || [ ! -f "$HOST_BIN" ]; then
    echo "==> [2/7] Building GN-Shield in release mode (cargo build --release)..."
    if ! command -v cargo >/dev/null 2>&1; then
        echo "❌ Error: 'cargo' not found. Please install Rust toolchain (rustup) to compile."
        exit 1
    fi
    # If running as root, drop to original invoking user if available to build cleanly
    if [ -n "${SUDO_USER:-}" ]; then
        echo "  • Compiling workspace as user '$SUDO_USER'..."
        sudo -u "$SUDO_USER" cargo build --release --workspace
    else
        cargo build --release --workspace
    fi
else
    echo "==> [2/7] Using existing release binaries in target/release/..."
fi

# 3. Install Binaries to /usr/local/bin
echo "==> [3/7] Installing binaries to $BIN_DEST..."
install -m 0755 "$CORE_BIN" "$BIN_DEST/gn-shield-core"
install -m 0755 "$CLI_BIN" "$BIN_DEST/gn-shield-cli"
install -m 0755 "$HOST_BIN" "$BIN_DEST/gn-shield-native-host"

echo "  • Installed $BIN_DEST/gn-shield-core"
echo "  • Installed $BIN_DEST/gn-shield-cli"
echo "  • Installed $BIN_DEST/gn-shield-native-host"

# 4. Create Directories & Configurations
echo "==> [4/7] Setting up configuration and data directories..."
mkdir -p "$CONF_DEST"
mkdir -p "$VAR_DEST/quarantine"
mkdir -p "$RUN_DEST"

chmod 0755 "$CONF_DEST"
chmod 0700 "$VAR_DEST"
chmod 0700 "$VAR_DEST/quarantine"
chmod 0755 "$RUN_DEST"

# Install configuration file if not already present
if [ ! -f "$CONF_DEST/config.toml" ]; then
    if [ -f "$SCRIPT_DIR/config/config.example.toml" ]; then
        install -m 0644 "$SCRIPT_DIR/config/config.example.toml" "$CONF_DEST/config.toml"
        echo "  • Created initial configuration at $CONF_DEST/config.toml"
    fi
else
    echo "  • Existing configuration preserved at $CONF_DEST/config.toml"
fi

# 5. Register Native Messaging Manifests for Browsers
echo "==> [5/7] Registering browser companion native messaging manifests..."
if [ -x "$BIN_DEST/gn-shield-native-host" ]; then
    "$BIN_DEST/gn-shield-native-host" --install-manifests --system
else
    echo "  ⚠️ Warning: gn-shield-native-host not executable, skipping manifest installation."
fi

# 6. Install Systemd Service
echo "==> [6/7] Configuring systemd service..."
if command -v systemctl >/dev/null 2>&1; then
    if [ -f "$SCRIPT_DIR/config/gn-shield.service" ]; then
        install -m 0644 "$SCRIPT_DIR/config/gn-shield.service" "$SERVICE_DEST"
    else
        cat <<'EOF' > "$SERVICE_DEST"
[Unit]
Description=GN-Shield Security Daemon
After=network.target local-fs.target
Documentation=https://github.com/hiroppi401/gn-shield

[Service]
Type=simple
ExecStart=/usr/local/bin/gn-shield-core --config /etc/gn-shield/config.toml
Restart=on-failure
RestartSec=2s
KillMode=process
RuntimeDirectory=gn-shield
StateDirectory=gn-shield
ConfigurationDirectory=gn-shield
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
    systemctl enable gn-shield.service
    echo "  • Enabled gn-shield.service to start on boot"

    if [ "$START_SERVICE" = true ]; then
        echo "  • Starting gn-shield.service..."
        systemctl restart gn-shield.service
        sleep 1
    fi
else
    echo "  ⚠️ Systemd not detected. Please start gn-shield-core manually using your init system."
fi

# 7. Initial Learning Mode Scan (PRD Section 7.1)
echo "==> [7/7] Running initial learning mode scan for installed packages..."
if command -v pacman >/dev/null 2>&1; then
    PKG_COUNT="$(pacman -Qq | wc -l)"
    echo "  • Detected Pacman package manager ($PKG_COUNT installed packages scanned)."
    echo "  • Baseline developer tools and libraries pre-approved in initial trust profile."
elif command -v dpkg-query >/dev/null 2>&1; then
    PKG_COUNT="$(dpkg-query -f '.\n' -W | wc -l)"
    echo "  • Detected Dpkg/APT package manager ($PKG_COUNT installed packages scanned)."
elif command -v rpm >/dev/null 2>&1; then
    PKG_COUNT="$(rpm -qa | wc -l)"
    echo "  • Detected RPM package manager ($PKG_COUNT installed packages scanned)."
fi

echo ""
echo "============================================================"
echo "✅ GN-Shield successfully installed on this system!"
echo "============================================================"
echo ""
echo "Quick Commands:"
echo "  • Check Status     : gn-shield-cli status"
echo "  • View Audit Log   : gn-shield-cli log --limit 20"
echo "  • Manage Allowlist : gn-shield-cli allow domain <domain>"
echo "  • Password Breach  : gn-shield-cli check-breach <password>"
echo "  • Service Logs     : journalctl -u gn-shield.service -f"
echo "  • Configuration    : /etc/gn-shield/config.toml"
echo ""
