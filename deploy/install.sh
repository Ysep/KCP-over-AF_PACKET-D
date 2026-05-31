#!/bin/bash
#
# install.sh - KCP-over-AF_PACKET Deployment Installer
#
# This script:
#   1. Checks for root privileges
#   2. Detects the OS (Debian/Ubuntu, CentOS/RHEL/Fedora)
#   3. Installs build and runtime dependencies
#   4. Creates the kcp system user/group if they don't exist
#   5. Compiles the project (make clean && make all)
#   6. Installs the binary to /usr/local/bin/kcp-afpacket
#   7. Creates the /etc/kcp/ configuration directory
#   8. Copies sample configs to /etc/kcp/
#   9. Generates an SM4 encryption key if not already provided
#  10. Installs the systemd service file
#  11. Sets up logrotate
#  12. Applies proper file permissions
#  13. Prints an installation summary
#
# Usage:  sudo ./install.sh [--sm4-key <hex-key>]

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="kcp-afpacket"
INSTALL_BIN="/usr/local/bin/${BINARY_NAME}"
CONFIG_DIR="/etc/kcp"
LOG_FILE="/var/log/kcp-afpacket.log"
SERVICE_FILE="/etc/systemd/system/kcp-afpacket.service"
LOGROTATE_FILE="/etc/logrotate.d/kcp-afpacket"
KCP_USER="kcp"
KCP_GROUP="kcp"
SAMPLE_DIR="${PROJECT_DIR}/sample"
DEPLOY_DIR="${PROJECT_DIR}/deploy"

# ---------------------------------------------------------------------------
# Colour helpers (optional — colour when stdout is a tty)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# 1. Root check
# ---------------------------------------------------------------------------
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root (or with sudo)."
        exit 1
    fi
    log_info "Running with root privileges."
}

# ---------------------------------------------------------------------------
# 2. OS detection
# ---------------------------------------------------------------------------
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID:-unknown}"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_VERSION="unknown"
    else
        log_error "Unable to detect OS.  Only Debian/Ubuntu and CentOS/RHEL/Fedora are supported."
        exit 1
    fi

    case "${OS_ID}" in
        debian|ubuntu)
            OS_FAMILY="debian"
            PKG_INSTALL="apt-get install -y"
            PKG_UPDATE="apt-get update"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            OS_FAMILY="rhel"
            if command -v dnf >/dev/null 2>&1; then
                PKG_INSTALL="dnf install -y"
            else
                PKG_INSTALL="yum install -y"
            fi
            PKG_UPDATE="true"   # dnf/yum refresh metadata automatically
            ;;
        *)
            log_error "Unsupported OS: ${OS_ID}. Supported: Debian, Ubuntu, CentOS, RHEL, Fedora."
            exit 1
            ;;
    esac

    log_info "Detected OS: ${OS_ID} (${OS_FAMILY} family)"
}

# ---------------------------------------------------------------------------
# 3. Dependencies
# ---------------------------------------------------------------------------
install_dependencies() {
    log_info "Installing build and runtime dependencies..."

    if [ "${OS_FAMILY}" = "debian" ]; then
        ${PKG_UPDATE}
        ${PKG_INSTALL} gcc make libjson-c-dev nettle-dev build-essential
    else
        ${PKG_INSTALL} gcc make json-c-devel nettle-devel
        # Ensure "development tools" group or build-essential equivalent
        if command -v dnf >/dev/null 2>&1; then
            dnf groupinstall -y "Development Tools" 2>/dev/null || true
        else
            yum groupinstall -y "Development Tools" 2>/dev/null || true
        fi
    fi

    log_info "Dependencies installed successfully."
}

# ---------------------------------------------------------------------------
# 4. kcp user / group
# ---------------------------------------------------------------------------
create_kcp_user() {
    if ! getent group "${KCP_GROUP}" >/dev/null 2>&1; then
        groupadd --system "${KCP_GROUP}"
        log_info "Group '${KCP_GROUP}' created."
    else
        log_info "Group '${KCP_GROUP}' already exists."
    fi

    if ! id -u "${KCP_USER}" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --gid "${KCP_GROUP}" "${KCP_USER}"
        log_info "User '${KCP_USER}' created."
    else
        log_info "User '${KCP_USER}' already exists."
    fi
}

# ---------------------------------------------------------------------------
# 5. Compile
# ---------------------------------------------------------------------------
compile_project() {
    log_info "Building the project..."
    cd "${PROJECT_DIR}"

    make clean
    make all

    if [ ! -f "${PROJECT_DIR}/${BINARY_NAME}" ]; then
        log_error "Build failed: '${BINARY_NAME}' binary not found after compilation."
        exit 1
    fi

    log_info "Build succeeded."
}

# ---------------------------------------------------------------------------
# 6. Install binary
# ---------------------------------------------------------------------------
install_binary() {
    log_info "Installing binary to ${INSTALL_BIN}..."
    cp "${PROJECT_DIR}/${BINARY_NAME}" "${INSTALL_BIN}"
    chmod 755 "${INSTALL_BIN}"
    log_info "Binary installed."
}

# ---------------------------------------------------------------------------
# 7. Create /etc/kcp
# ---------------------------------------------------------------------------
create_config_dir() {
    if [ ! -d "${CONFIG_DIR}" ]; then
        mkdir -p "${CONFIG_DIR}"
        log_info "Created ${CONFIG_DIR}"
    else
        log_info "${CONFIG_DIR} already exists."
    fi
}

# ---------------------------------------------------------------------------
# 8. Copy sample configs
# ---------------------------------------------------------------------------
copy_sample_configs() {
    log_info "Copying sample configuration files..."

    if [ -d "${SAMPLE_DIR}" ]; then
        for f in "${SAMPLE_DIR}"/*.json; do
            if [ -f "$f" ]; then
                local dest="${CONFIG_DIR}/$(basename "$f")"
                if [ ! -f "${dest}" ]; then
                    cp "$f" "${dest}"
                    log_info "  Copied $(basename "$f") → ${dest}"
                else
                    log_info "  Skipped $(basename "$f") — already exists at ${dest}"
                fi
            fi
        done
    else
        log_warn "Sample config directory not found: ${SAMPLE_DIR}"
    fi

    # If no config.json exists, create a symlink or copy from example
    if [ ! -f "${CONFIG_DIR}/config.json" ]; then
        if [ -f "${CONFIG_DIR}/config.example.json" ]; then
            cp "${CONFIG_DIR}/config.example.json" "${CONFIG_DIR}/config.json"
            log_info "  Created ${CONFIG_DIR}/config.json from config.example.json"
        fi
    fi
}

# ---------------------------------------------------------------------------
# 9. Generate / verify SM4 key
# ---------------------------------------------------------------------------
generate_sm4_key() {
    local provided_key=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --sm4-key)
                provided_key="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    local config_json="${CONFIG_DIR}/config.json"

    if [ -n "${provided_key}" ]; then
        log_info "Using provided SM4 key."
        # Inject key into config.json if it exists
        if [ -f "${config_json}" ]; then
            # Simple sed replacement — assumes encryption.enabled and sm4_key placeholders
            sed -i "s/\"sm4_key\": *\"[^\"]*\"/\"sm4_key\": \"${provided_key}\"/" "${config_json}" || true
        fi
        return
    fi

    # Generate a random 128-bit (16-byte) key in hex
    local generated_key
    if command -v openssl >/dev/null 2>&1; then
        generated_key=$(openssl rand -hex 16)
    elif [ -r /dev/urandom ]; then
        generated_key=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
    else
        log_warn "Cannot generate SM4 key: no openssl and /dev/urandom unavailable."
        return
    fi

    log_info "Generated random SM4 key: ${generated_key}"
    log_warn "Save this key securely — it is required on the peer node."

    # Write key to a standalone file
    echo "${generated_key}" > "${CONFIG_DIR}/sm4_key.hex"
    chmod 600 "${CONFIG_DIR}/sm4_key.hex"
    chown root:root "${CONFIG_DIR}/sm4_key.hex"
    log_info "SM4 key saved to ${CONFIG_DIR}/sm4_key.hex (0600)"

    # Optionally inject into config.json
    if [ -f "${config_json}" ]; then
        sed -i "s/\"sm4_key\": *\"[^\"]*\"/\"sm4_key\": \"${generated_key}\"/" "${config_json}" || true
        sed -i 's/"enabled": *false/"enabled": true/' "${config_json}" || true
        log_info "Updated ${config_json} with the generated SM4 key."
    fi
}

# ---------------------------------------------------------------------------
# 10. Install systemd service
# ---------------------------------------------------------------------------
install_service() {
    log_info "Installing systemd service..."

    cp "${DEPLOY_DIR}/kcp-afpacket.service" "${SERVICE_FILE}"
    chmod 644 "${SERVICE_FILE}"

    systemctl daemon-reload
    log_info "Service file installed at ${SERVICE_FILE}"
    log_info "Enable with: systemctl enable kcp-afpacket && systemctl start kcp-afpacket"
}

# ---------------------------------------------------------------------------
# 11. Set up logrotate
# ---------------------------------------------------------------------------
setup_logrotate() {
    log_info "Installing logrotate configuration..."

    cp "${DEPLOY_DIR}/logrotate.conf" "${LOGROTATE_FILE}"
    chmod 644 "${LOGROTATE_FILE}"

    # Create the log file with correct ownership if it doesn't exist
    if [ ! -f "${LOG_FILE}" ]; then
        touch "${LOG_FILE}"
        chown "${KCP_USER}:${KCP_GROUP}" "${LOG_FILE}"
        chmod 640 "${LOG_FILE}"
        log_info "Created ${LOG_FILE}"
    fi

    log_info "Logrotate configuration installed at ${LOGROTATE_FILE}"
}

# ---------------------------------------------------------------------------
# 12. Permissions
# ---------------------------------------------------------------------------
set_permissions() {
    log_info "Setting file permissions..."

    chown -R root:root "${CONFIG_DIR}"
    chmod 750 "${CONFIG_DIR}"

    # Config files should be readable by the kcp group
    if [ -d "${CONFIG_DIR}" ]; then
        find "${CONFIG_DIR}" -type f -name '*.json' -exec chmod 640 {} \;
        find "${CONFIG_DIR}" -type f -name '*.hex'  -exec chmod 600 {} \;
    fi

    log_info "Permissions applied."
}

# ---------------------------------------------------------------------------
# 13. Summary
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo "============================================================"
    echo "  KCP-over-AF_PACKET Installation Complete"
    echo "============================================================"
    echo ""
    echo "  Binary        : ${INSTALL_BIN}"
    echo "  Config dir    : ${CONFIG_DIR}"
    echo "  Service       : ${SERVICE_FILE}"
    echo "  Logrotate     : ${LOGROTATE_FILE}"
    echo "  Log file      : ${LOG_FILE}"
    echo "  System user   : ${KCP_USER}"
    echo ""
    echo "  Next steps:"
    echo "    1. Edit ${CONFIG_DIR}/config.json to match your setup"
    echo "    2. Set the correct SM4 key (if using encryption)"
    echo "    3. Enable & start the service:"
    echo "         systemctl enable kcp-afpacket"
    echo "         systemctl start  kcp-afpacket"
    echo "    4. Check status:"
    echo "         systemctl status kcp-afpacket"
    echo "         journalctl -u kcp-afpacket -f"
    echo ""
    echo "  Runtime control signals:"
    echo "    SIGHUP  (kill -HUP)  — Hot-reload config.json"
    echo "    SIGUSR1 (kill -USR1) — Channel control via config-ctl.json"
    echo ""
    echo "============================================================"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo ""
    echo "=== KCP-over-AF_PACKET Deployment Installer ==="
    echo ""

    check_root
    detect_os

    install_dependencies
    create_kcp_user
    compile_project
    install_binary
    create_config_dir
    copy_sample_configs
    generate_sm4_key "$@"
    install_service
    setup_logrotate
    set_permissions
    print_summary
}

main "$@"
