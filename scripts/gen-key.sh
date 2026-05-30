#!/bin/bash
#
# gen-key.sh — SM4 加密密钥生成器
# 使用 /dev/urandom 生成 32 位随机十六进制字符串，用于 SM4-CBC 加密
#
# 用法: ./gen-key.sh
#

set -euo pipefail

# -------------------- 颜色输出 --------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC}  $*"; }

# -------------------- 密钥参数 --------------------
# SM4 要求 128 位密钥 = 16 字节 = 32 个十六进制字符
KEY_LENGTH_BYTES=16
KEY_LENGTH_HEX=$((KEY_LENGTH_BYTES * 2))  # 32

# -------------------- 生成密钥 --------------------
info "正在从 /dev/urandom 生成 ${KEY_LENGTH_BYTES} 字节 ($KEY_LENGTH_HEX 个十六进制字符) SM4 密钥..."

SM4_KEY=$(xxd -l "$KEY_LENGTH_BYTES" -p /dev/urandom | tr -d '\n')

if [[ ${#SM4_KEY} -ne $KEY_LENGTH_HEX ]]; then
    echo "错误: 密钥长度不正确 (${#SM4_KEY} != $KEY_LENGTH_HEX)" >&2
    exit 1
fi

# -------------------- 输出 --------------------
echo ""
echo "=============================================="
echo "  SM4 加密密钥已生成"
echo "=============================================="
echo ""
echo -e "${YELLOW}密钥:${NC}  ${SM4_KEY}"
echo ""
echo "----------------------------------------------"
echo "  config.json 配置片段 (复制到 encryption 字段):"
echo "----------------------------------------------"
echo ""
cat <<EOF
    "encryption": {
        "enabled": true,
        "sm4_key": "${SM4_KEY}"
    }
EOF
echo ""
echo "----------------------------------------------"
echo ""
info "请确保前后端节点使用相同的密钥"
info "请妥善保管此密钥，避免泄露"
echo ""
