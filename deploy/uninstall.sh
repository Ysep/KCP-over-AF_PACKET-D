#!/bin/bash
#
# uninstall.sh - KCP-over-AF_PACKET Clean Uninstaller
#
# This script:
#   1. Stops and disables the systemd service
#   2. Removes the binary
#   3. Removes configuration files (optional)
#   4. Removes the kcp user/group
#   5. Cleans up logrotate
#   6. Removes the PID file
#
# Usage:  sudo ./uninstall.sh [--purge]

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BINARY_NAME="kcp-afpacket"
INSTALL_BIN="/usr/local/bin/${BINARY_NAME}"
CONFIG_DIR="/etc/kcp"
LOG_FILE="/var/log/kcp-afpacket.log"
SERVICE_NAME="kcp-afpacket"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOGROTATE_FILE="/etc/logrotate.d/${SERVICE_NAME}"
PID_FILE="/var/run/kcp-afpacket.pid"
KCP_USER="kcp"
KCP_GROUP="kcp"

PURGE=false
if [ "${1:-}" = "--purge" ]; then
    PURGE=true
fi

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root (or with sudo)."
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Stop and disable the service
# ---------------------------------------------------------------------------
stop_service() {
    log_info "Stopping and disabling systemd service '${SERVICE_NAME}'..."

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl stop "${SERVICE_NAME}"
        log_info "  Service stopped."
    else
        log_info "  Service is not running."
    fi

    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl disable "${SERVICE_NAME}"
        log_info "  Service disabled."
    else
        log_info "  Service was not enabled."
    fi

    if [ -f "${SERVICE_FILE}" ]; then
        rm -f "${SERVICE_FILE}"
        log_info "  Removed ${SERVICE_FILE}"
    fi

    systemctl daemon-reload 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 2. Remove binary
# ---------------------------------------------------------------------------
remove_binary() {
    if [ -f "${INSTALL_BIN}" ]; then
        rm -f "${INSTALL_BIN}"
        log_info "Removed ${INSTALL_BIN}"
    else
        log_info "Binary not found at ${INSTALL_BIN}, skipping."
    fi
}

# ---------------------------------------------------------------------------
# 3. Remove configuration files
# ---------------------------------------------------------------------------
remove_configs() {
    if [ "${PURGE}" = true ]; then
        if [ -d "${CONFIG_DIR}" ]; then
            rm -rf "${CONFIG_DIR}"
            log_info "Purged configuration directory: ${CONFIG_DIR}"
        fi
    else
        if [ -d "${CONFIG_DIR}" ]; then
            log_warn "Configuration directory preserved: ${CONFIG_DIR}"
            log_warn "  To remove, re-run with --purge"
        fi
    fi
}

# ---------------------------------------------------------------------------
# 4. Remove user/group
# ---------------------------------------------------------------------------
remove_user_group() {
    if id -u "${KCP_USER}" >/dev/null 2>&1; then
        userdel "${KCP_USER}"
        log_info "Removed user '${KCP_USER}'."
    else
        log_info "User '${KCP_USER}' does not exist."
    fi

    if getent group "${KCP_GROUP}" >/dev/null 2>&1; then
        groupdel "${KCP_GROUP}"
        log_info "Removed group '${KCP_GROUP}'."
    else
        log_info "Group '${KCP_GROUP}' does not exist."
    fi
}

# ---------------------------------------------------------------------------
# 5. Clean up logrotate
# ---------------------------------------------------------------------------
remove_logrotate() {
    if [ -f "${LOGROTATE_FILE}" ]; then
        rm -f "${LOGROTATE_FILE}"
        log_info "Removed logrotate configuration: ${LOGROTATE_FILE}"
    else
        log_info "Logrotate file not found, skipping."
    fi

    if [ "${PURGE}" = true ] && [ -f "${LOG_FILE}" ]; then
        rm -f "${LOG_FILE}"
        log_info "Removed log file: ${LOG_FILE}"
    else
        log_info "Log file preserved: ${LOG_FILE} (use --purge to remove)"
    fi
}

# ---------------------------------------------------------------------------
# 6. Remove PID file
# ---------------------------------------------------------------------------
remove_pid() {
    if [ -f "${PID_FILE}" ]; then
        rm -f "${PID_FILE}"
        log_info "Removed PID file: ${PID_FILE}"
    fi
    # Also check config dir for any generated PID files
    if [ -d "${CONFIG_DIR}" ] || [ "${PURGE}" = true ]; then
        rm -f /var/run/kcp-afpacket*.pid 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo ""
echo "=== KCP-over-AF_PACKET Uninstaller ==="
echo ""

stop_service
remove_binary
remove_configs
remove_user_group
remove_logrotate
remove_pid

echo ""
echo "============================================================"
echo "  Uninstall complete."
echo "============================================================"
echo ""

if [ "${PURGE}" != true ]; then
    echo "  Run with --purge to also remove:"
    echo "    - ${CONFIG_DIR} (all configurations)"
    echo "    - ${LOG_FILE}"
    echo ""
fi
