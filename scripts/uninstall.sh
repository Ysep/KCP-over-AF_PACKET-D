#!/bin/bash
#
# uninstall.sh — KCP-over-AF_PACKET 卸载脚本
# 停止服务、移除二进制文件和配置、清理系统残留
#

set -euo pipefail

# -------------------- 颜色输出 --------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# -------------------- 检查 root 权限 --------------------
if [[ $EUID -ne 0 ]]; then
    error "请使用 root 权限运行此脚本 (sudo ./uninstall.sh)"
    exit 1
fi

# -------------------- 确认卸载 --------------------
echo "=============================================="
echo "  KCP-over-AF_PACKET 卸载脚本"
echo "=============================================="
echo ""
echo "此操作将执行以下步骤:"
echo "  1. 停止 kcp-afpacket 服务"
echo "  2. 禁用 kcp-afpacket 服务（取消开机自启）"
echo "  3. 删除二进制文件: /usr/local/bin/kcp-afpacket"
echo "  4. 删除配置文件:   /etc/kcp-afpacket/config.json"
echo "  5. 删除 systemd 单元文件"
echo "  6. 重载 systemd 配置"
echo ""
read -r -p "确认卸载? 输入 yes 继续: " REPLY
if [[ "$REPLY" != "yes" ]]; then
    info "已取消卸载"
    exit 0
fi

echo ""

# -------------------- 停止服务 --------------------
SERVICE_NAME="kcp-afpacket.service"

info "停止服务..."

if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"
    info "服务已停止"
else
    warn "服务未运行"
fi

# -------------------- 禁用服务 --------------------
info "禁用服务..."

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME"
    info "服务已禁用"
else
    warn "服务未启用"
fi

# -------------------- 删除二进制文件 --------------------
BINARY_PATH="/usr/local/bin/kcp-afpacket"
if [[ -f "$BINARY_PATH" ]]; then
    info "删除二进制文件: $BINARY_PATH"
    rm -f "$BINARY_PATH"
    info "二进制文件已删除"
else
    warn "二进制文件不存在: $BINARY_PATH"
fi

# -------------------- 删除配置文件 --------------------
CONFIG_DIR="/etc/kcp-afpacket"
if [[ -d "$CONFIG_DIR" ]]; then
    info "删除配置目录: $CONFIG_DIR"
    rm -rf "$CONFIG_DIR"
    info "配置目录已删除"
else
    warn "配置目录不存在: $CONFIG_DIR"
fi

# -------------------- 删除 systemd 单元文件 --------------------
SERVICE_DEST="/etc/systemd/system/kcp-afpacket.service"
if [[ -f "$SERVICE_DEST" ]]; then
    info "删除 systemd 单元文件: $SERVICE_DEST"
    rm -f "$SERVICE_DEST"
    info "单元文件已删除"
else
    warn "单元文件不存在: $SERVICE_DEST"
fi

# -------------------- 重载 systemd --------------------
info "重载 systemd 配置..."
systemctl daemon-reload

# -------------------- 清理 PID 文件 --------------------
PID_FILE="/var/run/kcp-afpacket.pid"
if [[ -f "$PID_FILE" ]]; then
    info "清理 PID 文件: $PID_FILE"
    rm -f "$PID_FILE"
fi

# -------------------- 完成 --------------------
echo ""
echo "=============================================="
info "KCP-over-AF_PACKET 卸载完成!"
echo "=============================================="
echo ""
echo "  已删除:"
echo "    - 二进制文件: $BINARY_PATH"
echo "    - 配置目录:   $CONFIG_DIR"
echo "    - 服务单元:   $SERVICE_DEST"
echo "    - PID 文件:   $PID_FILE (如果存在)"
echo ""
