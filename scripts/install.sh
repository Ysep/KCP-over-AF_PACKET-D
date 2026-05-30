#!/bin/bash
#
# install.sh — KCP-over-AF_PACKET 安装脚本
# 检查依赖、编译、安装二进制文件并设置 capabilities
#

set -euo pipefail

# -------------------- 颜色输出 --------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# -------------------- 检查是否为 root --------------------
if [[ $EUID -ne 0 ]]; then
    error "请使用 root 权限运行此脚本 (sudo ./install.sh)"
    exit 1
fi

# -------------------- 切换到项目根目录 --------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

info "项目目录: $PROJECT_DIR"

# -------------------- 依赖包列表 --------------------
DEPENDENCIES=(
    "gcc:gcc"
    "make:make"
    "libjson-c-dev:json-c-dev"
    "libnettle-dev:nettle-dev"
)

MISSING_PKGS=()

info "检查编译依赖..."

# 检查 gcc
if ! command -v gcc &> /dev/null; then
    MISSING_PKGS+=("gcc")
    warn "未找到: gcc"
else
    info "已找到: gcc ($(gcc --version | head -1))"
fi

# 检查 make
if ! command -v make &> /dev/null; then
    MISSING_PKGS+=("make")
    warn "未找到: make"
else
    info "已找到: make ($(make --version | head -1))"
fi

# 检查 json-c 开发头文件
if ! ldconfig -p 2>/dev/null | grep -q libjson-c || ! find /usr/include -name 'json.h' -path '*/json-c/*' 2>/dev/null | grep -q .; then
    MISSING_PKGS+=("libjson-c-dev")
    warn "未找到: libjson-c-dev"
else
    info "已找到: libjson-c-dev"
fi

# 检查 nettle 开发头文件
if ! ldconfig -p 2>/dev/null | grep -q libnettle || ! find /usr/include -name 'nettle' -type d 2>/dev/null | grep -q .; then
    MISSING_PKGS+=("nettle-dev")
    warn "未找到: nettle-dev"
else
    info "已找到: nettle-dev"
fi

# -------------------- 安装缺失的依赖 --------------------
if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    echo ""
    warn "以下依赖缺失: ${MISSING_PKGS[*]}"
    echo ""
    read -r -p "是否通过 apt-get 安装缺失的依赖? [y/N] " REPLY
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        info "更新软件包列表..."
        apt-get update
        info "安装: ${MISSING_PKGS[*]}"
        apt-get install -y "${MISSING_PKGS[@]}"
        info "依赖安装完成"
    else
        error "用户取消安装。请手动安装缺失的依赖后重试。"
        exit 1
    fi
else
    info "所有依赖均已满足"
fi

# -------------------- 编译项目 --------------------
echo ""
info "开始编译项目..."

if make clean; then
    info "清理完成"
fi

if make all; then
    info "编译成功: $(readlink -f kcp-afpacket)"
else
    error "编译失败，请检查错误信息"
    exit 1
fi

# -------------------- 安装二进制文件 --------------------
echo ""
BINARY_NAME="kcp-afpacket"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"

info "安装二进制文件到 ${INSTALL_PATH}..."
cp -f "$PROJECT_DIR/${BINARY_NAME}" "$INSTALL_PATH"
chmod 755 "$INSTALL_PATH"
info "二进制文件已安装"

# -------------------- 设置 capabilities --------------------
echo ""
info "设置 capabilities (cap_net_raw+ep)..."

if command -v setcap &> /dev/null; then
    setcap cap_net_raw+ep "$INSTALL_PATH"
    info "capabilities 已设置: $(getcap "$INSTALL_PATH")"
else
    warn "setcap 未安装，请手动执行:"
    warn "  sudo setcap cap_net_raw+ep ${INSTALL_PATH}"
    warn "  或: sudo apt-get install libcap2-bin"
fi

# -------------------- 完成 --------------------
echo ""
echo "=============================================="
info "KCP-over-AF_PACKET 安装完成!"
echo "=============================================="
echo ""
echo "  二进制文件: ${INSTALL_PATH}"
echo "  配置文件:   /etc/kcp-afpacket/config.json"
echo ""
echo "  下一步:"
echo "    1. 生成 SM4 密钥:  ./scripts/gen-key.sh"
echo "    2. 编辑配置文件:   sudo mkdir -p /etc/kcp-afpacket"
echo "                       sudo cp config.example.json /etc/kcp-afpacket/config.json"
echo "                       sudo vim /etc/kcp-afpacket/config.json"
echo "    3. 部署服务:        sudo ./scripts/deploy.sh /etc/kcp-afpacket/config.json"
echo ""
