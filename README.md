# KCP-over-AF_PACKET

## 项目简介

KCP-over-AF_PACKET 是一个 Linux 用户空间代理隧道系统，通过 **AF_PACKET 原始套接字**直接在数据链路层（OSI 第 2 层）进行通信，完全绕过 Linux 内核 TCP/IP 协议栈。系统集成 **KCP 协议**（一种基于 UDP 的可靠传输协议）提供 ARQ 可靠传输能力，支持**透明 TCP/UDP 代理**和**多流复用**（多通道），适用于需要低延迟、高吞吐、完全旁路内核网络的特殊场景。

**版本：** 1.0.0 | **许可证：** 参见源码头部声明

---

## 核心特性

- 🔌 **纯链路层通信**：基于 AF_PACKET + 自定义 EtherType，无需 IP 地址配置，无需路由表，两台主机通过以太网帧直接通信。
- 🔄 **透明 TCP/UDP 代理**：正向代理（本地监听 → 远端转发）和反向代理（远端请求 → 本地服务）两种模式，对应用层完全透明。
- 📦 **KCP 可靠 ARQ 传输**：集成 KCP (ikcp) 协议，提供可配置的自动重传、流量控制和拥塞控制。
- 🔀 **多流复用**：最多支持 256 个并发通道，每个通道独立维护 KCP 实例和状态机，通过 channel_id 实现帧级多路复用。
- 🔐 **可选加密与校验**：支持 SM4-CTR 加密 + HMAC-SM3 完整性校验，以及可选的 CRC32 帧校验。
- 🚀 **高性能设计**：epoll 边缘触发 I/O、TPACKET_V2 高性能数据路径、非阻塞套接字、零拷贝友好架构。
- 📡 **多实例部署**：通过 PID 文件管理，支持同一网卡上部署多个实例（需配置不同 EtherType）。
- 🔍 **BPF 内核过滤**：使用 Berkeley Packet Filter 在内核层面过滤帧，仅接收目标 EtherType 的帧。
- 🛡️ **自动 MAC 发现**：支持手动配置对端 MAC 地址或自动获取本机 MAC，预留广播自动发现能力。

---

## 架构概览

```
┌──────────┐     TCP/UDP     ┌──────────────┐    AF_PACKET     ┌────────────────┐    以太网链路    ┌────────────────┐    AF_PACKET    ┌──────────────┐     TCP/UDP     ┌──────────┐
│  主机 A   │ ──────────────→ │  本地代理      │ ──────────────→ │                │ ──────────────→ │                │ ──────────────→ │  远端代理      │ ──────────────→ │  主机 B   │
│  (应用)   │ ←────────────── │ (kcp-afpacket) │ ←────────────── │  eth0 (raw)    │ ←────────────── │  eth0 (raw)    │ ←────────────── │ (kcp-afpacket) │ ←────────────── │  (服务)   │
└──────────┘                 └──────────────┘                  └────────────────┘                 └────────────────┘                 └──────────────┘                  └──────────┘
```

### 数据流路径

```
应用层:    TCP/UDP Socket       ←→       本地代理监听端口 (127.0.0.1:8080)
              │                                      │
代理层:        └──── proxy.c (数据桥接) ──── kcp_wrap.c (KCP 可靠传输) ────┘
                                                        │
协议层:                                       myproto.c (MyProto 帧封装/加密/CRC)
                                                        │
链路层:                                       af_packet.c (AF_PACKET 原始套接字)
                                                        │
硬件层:                                           以太网帧发送/接收
```

### 模块结构

| 模块 | 文件 | 职责 |
|------|------|------|
| **af_packet** | `src/af_packet.c/h` | AF_PACKET 原始套接字创建、BPF 过滤、MAC 地址发现、NIC MTU 管理、帧收发 |
| **myproto** | `src/myproto.c/h` | MyProto 私有链路层协议：帧封装/解析、控制帧/数据帧构造、SM4-CTR 加解密存根、CRC32 校验 |
| **kcp_wrap** | `src/kcp_wrap.c/h` | KCP (ikcp) 库封装：实例创建/销毁、参数配置、输入/输出接口、定时更新 |
| **channel** | `src/channel.c/h` | 通道生命周期管理、状态机、哈希表查找、帧路由分发、心跳检测、超时处理 |
| **proxy** | `src/proxy.c/h` | TCP/UDP 代理：本地监听、连接管理、epoll 事件循环、数据桥接（local_fd ↔ KCP） |
| **main** | `src/main.c` | 入口点：配置加载/验证、信号处理、主事件循环、启动/清理编排 |
| **ikcp** | `src/ikcp.c/h` | KCP 协议核心库（第三方，轻量级可靠传输协议实现） |

### 通道状态机

```
                    ┌──────────┐
                    │  CLOSED  │
                    └────┬─────┘
                         │ SYN 发送
                    ┌────▼─────┐
                    │ SYN_SENT ├──────────────┐
                    └────┬─────┘              │
                         │ 收到 ACK            │ 收到 SYN
                    ┌────▼─────┐         ┌────▼─────┐
                    │ESTABLISHED│         │ SYN_RCVD │
                    └──┬───┬───┘         └────┬─────┘
                       │   │                  │ 发送 ACK
         发送 FIN      │   │ 收到 FIN    ┌────▼─────┐
       ┌───────────────┘   └───────────→ │ESTABLISHED│
       │                                 └──┬───┬───┘
  ┌────▼─────┐                              │   │
  │ FIN_SENT │←── 收到 FIN ─────────────────┘   │
  └────┬─────┘                                  │
       │ 收到 FIN                                │ 发送 FIN
  ┌────▼─────┐                             ┌────▼─────┐
  │TIME_WAIT │                             │ FIN_RCVD │
  └────┬─────┘                             └────┬─────┘
       │ 超时                                    │ 收到 FIN
       ▼                                         ▼
  ┌──────────┐                            ┌──────────┐
  │  CLOSED  │                            │TIME_WAIT │
  └──────────┘                            └────┬─────┘
                                               │ 超时
                                               ▼
                                          ┌──────────┐
                                          │  CLOSED  │
                                          └──────────┘
                          RST 可从任意状态直接回到 CLOSED
```

---

## 编译要求

### 系统要求

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| Linux Kernel | ≥ 2.6.31 | 需要 AF_PACKET 和 TPACKET_V2 支持 |
| GCC | ≥ 7.0 | C11/GNU11 标准，`_Static_assert` 支持 |
| libjson-c | ≥ 0.13 | JSON 配置文件解析 |
| glibc | ≥ 2.17 | `epoll_create1`, `clock_gettime` |

### 运行时权限

- **CAP_NET_RAW**：创建 AF_PACKET 原始套接字
- **CAP_NET_ADMIN**：设置 NIC MTU（可选，仅在启用 `auto_set_nic_mtu` 时需要）

---

## 快速开始

### 编译

```bash
# Release 构建（-O2 优化）
make

# Debug 构建（-g -O0 -DDEBUG，包含调试日志）
make debug

# 查看所有构建目标
make help
```

### 测试

```bash
# 运行所有测试（单元测试 34 项 + 集成测试 26 项）
make test

# 仅运行单元测试（MyProto 协议模块）
make test-unit

# 仅运行集成测试（配置加载、KCP 生命周期、通道管理等）
make test-integ

# 清理测试产物
make test-clean
```

### 安装

```bash
sudo make install          # 安装到 /usr/local/bin/
sudo make install PREFIX=/opt/kcp  # 自定义安装路径
```

---

## 配置文件示例

```json
{
    "interface": "eth0",
    "ethertype": 35013,
    "peer_mac": "aa:bb:cc:dd:ee:ff",
    "local_mac": "",
    "kcp": {
        "mtu": 1400,
        "sndwnd": 1024,
        "rcvwnd": 1024,
        "nodelay": 1,
        "interval": 10,
        "resend": 2,
        "nc": 1
    },
    "proxy_mode": "forward",
    "max_channels": 256,
    "heartbeat_interval": 10,
    "heartbeat_timeout": 60,
    "crypto": {
        "enabled": false,
        "key": ""
    },
    "crc_enabled": true,
    "auto_set_nic_mtu": false,
    "nic_mtu": 1500,
    "pid_file": "/var/run/kcp-afpacket.pid",
    "channels": [
        {
            "channel_id": 1,
            "listen_port": 8080,
            "remote_port": 80,
            "listen_addr": "127.0.0.1",
            "remote_addr": "192.168.1.100",
            "is_tcp": true
        },
        {
            "channel_id": 2,
            "listen_port": 5353,
            "remote_port": 53,
            "listen_addr": "127.0.0.1",
            "remote_addr": "192.168.1.1",
            "is_tcp": false
        }
    ]
}
```

完整配置项说明请参阅 [docs/CONFIG.md](docs/CONFIG.md)。

---

## 运行

```bash
# 赋予二进制文件必要的 Linux capabilities
sudo setcap cap_net_raw,cap_net_admin+ep ./kcp-afpacket

# 以配置文件启动
./kcp-afpacket config.json

# 支持 --version 和 --help
./kcp-afpacket --version
./kcp-afpacket --help
```

### 两节点部署示例

**节点 A（正向代理，本地监听）：**

```json
{
    "interface": "eth1",
    "ethertype": 35013,
    "peer_mac": "00:11:22:33:44:55",
    "proxy_mode": "forward",
    "channels": [
        { "channel_id": 1, "listen_port": 8080, "remote_port": 80,
          "listen_addr": "127.0.0.1", "remote_addr": "10.0.0.2", "is_tcp": true }
    ]
}
```

**节点 B（正向代理，响应方）：** 使用相同配置，`peer_mac` 指向节点 A 的 MAC 地址。

---

## 信号处理

| 信号 | 行为 |
|------|------|
| **SIGINT** (Ctrl+C) | 优雅关闭：关闭所有通道，刷新 KCP 缓冲区，释放资源 |
| **SIGTERM** | 同上，用于 systemd 等服务管理器停止服务 |
| **SIGHUP** | 请求配置重载（当前为预留接口，需重启生效） |
| **SIGPIPE** | 忽略，防止对已关闭套接字写入导致进程退出 |

---

## 安全建议

1. **Capabilities 而非 root**：强烈推荐使用 `setcap` 或 systemd ambient capabilities 赋予最小权限，避免以 root 运行。
2. **生产环境加密**：当前 SM4-CTR + HMAC-SM3 为存根实现（使用 XOR + FNV-1a 模拟），**不具备实际安全性**。生产环境请替换为真实的 SM4/SM3 密码库（如 OpenSSL、GmSSL）。
3. **物理链路隔离**：建议在直接物理链路（网线直连、物理隔离的 VLAN）上部署，因为链路层通信不经过防火墙和 IP 层访问控制。
4. **EtherType 冲突避免**：确保自定义 EtherType（默认 `0x88B5`）不与同一链路上其他协议冲突。
5. **密钥管理**：16 字节 SM4 密钥以十六进制字符串（32 字符）存储在 JSON 配置中，注意配置文件访问权限控制（推荐 `chmod 600`）。
6. **CRC32 校验**：虽然链路层自带 FCS 校验，但启用 CRC32 可检测软件层面的数据损坏。在已经启用加密（包含 HMAC）的场景下，CRC32 为冗余校验。

---

## 性能调优

| 参数 | 说明 | 建议值 |
|------|------|--------|
| `kcp.mtu` | KCP 最大传输单元 | 1400（保守）或 1478（高性能） |
| `kcp.sndwnd` / `kcp.rcvwnd` | 发送/接收窗口 | 1024（默认），高速链路可增大至 2048 |
| `kcp.nodelay` | 启用 nodelay 模式 | 1（低延迟场景必开） |
| `kcp.nc` | 禁用拥塞控制 | 1（直连链路推荐） |
| `nic_mtu` | 网卡 MTU | 与 KCP MTU 配合，确保帧不超出 NIC MTU |
| 套接字缓冲区 | `SO_SNDBUF`/`SO_RCVBUF` | 已硬编码为 256KB/512KB，可在源码中调整 |

---

## 文档索引

- [配置参考文档](docs/CONFIG.md) — 所有配置项的详细说明
- [架构设计文档](docs/ARCHITECTURE.md) — 数据流、帧格式、模块交互、MTU 预算
- 示例配置文件：`config.example.json`

---

## 限制与已知问题

1. **对端 MAC 自动发现未实现**：若不配置 `peer_mac`，当前回退为广播地址（`ff:ff:ff:ff:ff:ff`），可能导致通信失败。
2. **配置热重载未完全实现**：`SIGHUP` 已捕获，但重载逻辑为预留接口。
3. **仅支持 IPv4 映射**：本地监听地址和远端地址仅支持 IPv4。
4. **最大通道数 256**：由 `MAX_CHANNELS` 常量定义，哈希表大小 512 槽位。
