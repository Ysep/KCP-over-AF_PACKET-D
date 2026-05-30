# 依赖说明

KCP-over-AF_PACKET-D 的第三方依赖分为两大类：

## 1. 已附带（源码内置）

| 组件 | 文件 | 许可证 | 说明 |
|------|------|--------|------|
| **KCP (ikcp)** | `vendor/kcp/ikcp.c`, `vendor/kcp/ikcp.h` | MIT | KCP 可靠传输协议，由 skywind3000 开发 |

KCP 协议是此项目的核心传输层，提供基于 UDP 模型的 ARQ 可靠传输。

## 2. 系统库（编译时安装）

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y build-essential libjson-c-dev nettle-dev
```

### RHEL / CentOS / Fedora

```bash
sudo yum install -y gcc make json-c-devel nettle-devel
# 或
sudo dnf install -y gcc make json-c-devel nettle-devel
```

| 组件 | 包名 (Debian) | 包名 (RHEL) | 最低版本 | 用途 |
|------|--------------|-------------|---------|------|
| **json-c** | `libjson-c-dev` | `json-c-devel` | ≥ 0.13 | 配置文件 JSON 解析 |
| **Nettle** | `nettle-dev` | `nettle-devel` | ≥ 3.4 | 国密 SM4-CBC + SM3-HMAC 加密 |
| **GCC** | `build-essential` | `gcc` | ≥ 7.0 | C11 编译 (GNU extensions) |
| **glibc** | 系统自带 | 系统自带 | ≥ 2.28 | clock_gettime(CLOCK_MONOTONIC) |
| **Linux** | 系统自带 | 系统自带 | ≥ 2.6.31 | AF_PACKET, epoll, BPF |

### 一键安装

```bash
# Debian/Ubuntu
./scripts/install.sh

# 或手动
sudo ./scripts/vendor-install.sh
```

## 3. 运行时依赖

| 组件 | 说明 |
|------|------|
| Linux Kernel ≥ 2.6.31 | AF_PACKET 原始套接字支持 |
| CAP_NET_RAW 或 root | 创建原始套接字权限 |
| libjson-c.so | JSON 配置解析（动态链接） |
| libnettle.so | 加密库（动态链接，仅加密模式下需要） |

## 4. 静态链接（可选）

若要生成无运行时依赖的可执行文件：

```bash
sudo apt-get install -y libjson-c-static libnettle-dev
# Nettle static: 需源码编译
make clean
make LDFLAGS="-static -ljson-c -lnettle -lhogweed -lgmp" all
```

## 5. 版本兼容性矩阵

| 组件 | 最低版本 | 推荐版本 | 备注 |
|------|---------|---------|------|
| Linux Kernel | 2.6.31 | 5.10+ | 5.x 对 AF_PACKET 支持更完善 |
| json-c | 0.13 | 0.18 | 0.13 无 json_object_object_get_ex |
| Nettle | 3.4 | 3.10 | SM4 在 3.4 引入，SM3 在 2.7 引入 |
| GCC | 7.0 | 12+ | 需 -std=gnu11 |
