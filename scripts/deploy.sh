#!/bin/bash
#
# deploy.sh — KCP-over-AF_PACKET 部署辅助脚本
# 将配置文件与 systemd 单元文件部署到系统并启动服务
#
# 用法: sudo ./deploy.sh <config.json>
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

# -------------------- 使用说明 --------------------
usage() {
    echo "用法: sudo $0 <config.json>"
    echo ""
    echo "描述:"
    echo "  将配置文件部署到 /etc/kcp-afpacket/ 并安装 systemd 服务"
    echo ""
    echo "参数:"
    echo "  config.json    JSON 配置文件路径"
    echo ""
    echo "示例:"
    echo "  sudo $0 config-node-c.json"
    exit 1
}

# -------------------- 检查参数 --------------------
if [[ $# -ne 1 ]]; then
    error "缺少参数"
    usage
fi

CONFIG_FILE="$1"

# -------------------- 检查 root 权限 --------------------
if [[ $EUID -ne 0 ]]; then
    error "请使用 root 权限运行此脚本 (sudo $0 <config.json>)"
    exit 1
fi

# -------------------- 验证配置文件 --------------------
if [[ ! -f "$CONFIG_FILE" ]]; then
    error "配置文件不存在: $CONFIG_FILE"
    exit 1
fi

info "验证配置文件格式..."

# 使用 Python 或 json_pp 验证 JSON 格式
if command -v python3 &> /dev/null; then
    if ! python3 -m json.tool "$CONFIG_FILE" > /dev/null 2>&1; then
        error "JSON 格式无效: $CONFIG_FILE"
        exit 1
    fi
elif command -v json_pp &> /dev/null; then
    if ! json_pp < "$CONFIG_FILE" > /dev/null 2>&1; then
        error "JSON 格式无效: $CONFIG_FILE"
        exit 1
    fi
else
    warn "未找到 JSON 验证工具 (python3/json_pp)，跳过格式验证"
fi

info "配置文件验证通过: $CONFIG_FILE"

# -------------------- 切换到项目根目录 --------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# -------------------- 检查二进制文件 --------------------
BINARY_PATH="/usr/local/bin/kcp-afpacket"
if [[ ! -f "$BINARY_PATH" ]]; then
    warn "二进制文件未安装: $BINARY_PATH"
    read -r -p "是否运行 install.sh 进行编译安装? [y/N] " REPLY
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        bash "$SCRIPT_DIR/install.sh"
        if [[ ! -f "$BINARY_PATH" ]]; then
            error "install.sh 执行后仍未找到 $BINARY_PATH，请手动检查"
            exit 1
        fi
    else
        error "请先运行 install.sh 编译并安装二进制文件"
        exit 1
    fi
else
    info "二进制文件已安装: $BINARY_PATH"
fi

# -------------------- 部署配置文件 --------------------
CONFIG_DIR="/etc/kcp-afpacket"
CONFIG_DEST="${CONFIG_DIR}/config.json"

info "部署配置文件..."
mkdir -p "$CONFIG_DIR"
cp -f "$CONFIG_FILE" "$CONFIG_DEST"
chmod 640 "$CONFIG_DEST"
info "配置文件已复制到: $CONFIG_DEST"

# -------------------- 部署 systemd 单元文件 --------------------
SERVICE_FILE="$SCRIPT_DIR/kcp-afpacket.service"
SERVICE_DEST="/etc/systemd/system/kcp-afpacket.service"

if [[ ! -f "$SERVICE_FILE" ]]; then
    error "找不到 systemd 单元文件: $SERVICE_FILE"
    exit 1
fi

info "部署 systemd 服务..."
cp -f "$SERVICE_FILE" "$SERVICE_DEST"
chmod 644 "$SERVICE_DEST"
info "单元文件已复制到: $SERVICE_DEST"

# -------------------- 重载 systemd --------------------
info "重载 systemd 配置..."
systemctl daemon-reload

# -------------------- 启用并启动服务 --------------------
info "启用服务（开机自启）..."
systemctl enable kcp-afpacket.service

echo ""
read -r -p "是否立即启动服务? [Y/n] " REPLY
if [[ -z "$REPLY" ]] || [[ "$REPLY" =~ ^[Yy]$ ]]; then
    info "启动服务..."
    systemctl start kcp-afpacket.service

    # 等待服务启动
    sleep 2

    # -------------------- 显示服务状态 --------------------
    echo ""
    info "服务状态:"
    echo "=============================================="
    systemctl status kcp-afpacket.service --no-pager || true
    echo "=============================================="
else
    info "服务已部署但未启动。可稍后手动启动:"
    info "  sudo systemctl start kcp-afpacket"
fi

# -------------------- 完成 --------------------
echo ""
echo "=============================================="
info "部署完成!"
echo "=============================================="
echo ""
echo "  配置文件:    $CONFIG_DEST"
echo "  服务单元:    $SERVICE_DEST"
echo "  二进制文件:  $BINARY_PATH"
echo ""
echo "  常用命令:"
echo "    sudo systemctl status kcp-afpacket   # 查看状态"
echo "    sudo systemctl start kcp-afpacket    # 启动服务"
echo "    sudo systemctl stop kcp-afpacket     # 停止服务"
echo "    sudo systemctl restart kcp-afpacket  # 重启服务"
echo "    sudo journalctl -u kcp-afpacket -f   # 实时日志"
echo ""
