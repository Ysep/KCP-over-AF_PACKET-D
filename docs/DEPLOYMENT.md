# 部署指南 — KCP-over-AF_PACKET

本文档提供 KCP-over-AF_PACKET 的完整部署指南，涵盖系统要求、编译构建、配置文件、拓扑示例、systemd 服务、日志监控、故障排查和性能调优。

---

## 目录

1. [系统要求](#1-系统要求)
2. [编译构建](#2-编译构建)
3. [配置文件详解](#3-配置文件详解)
4. [示例拓扑部署](#4-示例拓扑部署)
5. [作为 systemd 服务运行](#5-作为-systemd-服务运行)
6. [日志与监控](#6-日志与监控)
7. [故障排查](#7-故障排查)
8. [性能调优](#8-性能调优)

---

## 1. 系统要求

### 操作系统

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| Linux Kernel | ≥ 2.6.31 | 需要 `AF_PACKET` 和 `TPACKET_V2` 支持 |
| glibc | ≥ 2.17 | `epoll_create1`、`clock_gettime`、`_GNU_SOURCE` |

### 编译工具链

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| GCC | ≥ 7.0 | C11/GNU11 标准，`_Static_assert` 支持 |
| GNU Make | ≥ 3.82 | 构建系统 |
| libjson-c | ≥ 0.13 | JSON 配置文件解析（`libjson-c-dev`） |
| libnettle | ≥ 3.4 | 国密加密库（`nettle-dev`，SM4 + SM3） |

### 安装依赖（Debian/Ubuntu）

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc make libjson-c-dev nettle-dev
```

### 安装依赖（RHEL/CentOS/Fedora）

```bash
sudo dnf install -y gcc make json-c-devel nettle-devel
```

### 运行时权限

| 能力 | 用途 |
|------|------|
| `CAP_NET_RAW` | 创建 AF_PACKET 原始套接字（始终需要） |
| `CAP_NET_ADMIN` | 设置 NIC MTU（仅 `auto_set_nic_mtu: true` 时需要） |
| root / sudo | 以上能力通常需要 root 权限 |

### 硬件要求

- 至少一块以太网网卡（支持 AF_PACKET 原始套接字）
- 两台主机之间需要二层可达（同一广播域或通过交换机）
- 可选：支持巨型帧（MTU > 1500）的网卡可进一步提升吞吐量

---

## 2. 编译构建

### 快速编译

```bash
cd /sandbox/workspace/kcp-afpacket-C

# Release 构建（-O2 优化，生产环境推荐）
make

# Debug 构建（-g -O0 -DDEBUG，包含调试日志）
make debug

# 查看所有构建目标
make help
```

### 编译产物

```
kcp-afpacket          # 可执行文件 (~95KB)
obj/
  ├── main.o
  ├── af_packet.o
  ├── myproto.o
  ├── crypto.o
  ├── kcp_wrap.o
  ├── channel.o
  ├── proxy.o
  └── ikcp.o
```

### 安装到系统

```bash
# 安装到 /usr/local/bin（默认）
make install

# 自定义安装路径
make install PREFIX=/opt/kcp-afpacket

# 手动安装
sudo cp kcp-afpacket /usr/local/bin/
sudo chmod 755 /usr/local/bin/kcp-afpacket
```

### 交叉编译

```bash
# ARM64
make CC=aarch64-linux-gnu-gcc

# ARM32
make CC=arm-linux-gnueabihf-gcc
```

### 清理

```bash
make clean          # 清理构建产物
make test-clean     # 清理测试二进制
```

---

## 3. 配置文件详解

配置文件为 JSON 格式，通过命令行参数指定：

```bash
kcp-afpacket /etc/kcp-afpacket/config.json
```

### 完整配置结构

```json
{
    "interface":          "<string>",
    "ethertype":          <uint16>,
    "peer_mac":           "<string | \"\">",
    "local_mac":          "<string | \"\">",
    "instance_name":      "<string>",
    "node_type":          "frontend" | "backend",
    "max_channels":       <int>,
    "heartbeat_interval": <int>,
    "heartbeat_timeout":  <int>,
    "kcp": {
        "mtu":      <int>,
        "sndwnd":   <int>,
        "rcvwnd":   <int>,
        "nodelay":  <int>,
        "interval": <int>,
        "resend":   <int>,
        "nc":       <int>
    },
    "encryption": {
        "enabled": <bool>,
        "sm4_key": "<string>"
    },
    "crc_enabled":     <bool>,
    "auto_set_nic_mtu": <bool>,
    "nic_mtu":         <int>,
    "pid_file":        "<string>",
    "channels": [
        {
            "channel_id":  <int>,
            "listen_port": <int>,
            "remote_port": <int>,
            "listen_addr": "<string>",
            "remote_addr": "<string>",
            "is_tcp":      <bool>
        }
    ]
}
```

### 字段详细说明

#### `interface`（必填）

| 属性 | 说明 |
|------|------|
| 类型 | `string` |
| 必填 | 是 |
| 示例 | `"eth0"`、`"ens19"`、`"enp3s0"` |

AF_PACKET 套接字绑定的网卡名称。不能超过 32 字符（`IFNAMSIZ` 限制）。可通过 `ip link show` 查看可用网卡。

---

#### `ethertype`（必填）

| 属性 | 说明 |
|------|------|
| 类型 | `integer` (uint16) |
| 默认值 | `35013` (`0x88B5`) |
| 范围 | `0x0600` ~ `0xFFFF` |

自定义以太网帧类型。用于区分本系统与其他协议的数据帧。

- ⚠️ 同一链路上的两个对端**必须使用相同的 EtherType**
- 同一网卡上部署多个实例时需使用**不同的 EtherType**
- 禁止使用 `0x0000`-`0x05FF`（IEEE 802.3 长度字段范围）及已广泛使用的标准协议类型（如 `0x0800` IPv4、`0x0806` ARP、`0x86DD` IPv6）

---

#### `peer_mac`（强烈推荐）

| 属性 | 说明 |
|------|------|
| 类型 | `string` |
| 默认值 | `""`（回退为广播 `ff:ff:ff:ff:ff:ff`） |
| 格式 | 冒号分隔十六进制，如 `"aa:bb:cc:dd:ee:ff"` |

对端网卡的 MAC 地址。

- **强烈建议显式配置**：自动 MAC 发现功能尚未完整实现，留空可能导致通信失败
- 可通过对端运行 `ip link show eth0` 获取 MAC 地址

---

#### `local_mac`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `string` |
| 默认值 | `""`（通过 `ioctl(SIOCGIFHWADDR)` 自动获取） |

本地网卡的 MAC 地址。建议留空让系统自动获取。

---

#### `instance_name`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `string` |
| 默认值 | `"default"` |
| 示例 | `"node-w"`、`"tunnel-1"` |

实例名称。用于日志标识和 PID 文件命名。同一主机运行多个实例时建议设置不同名称。

---

#### `node_type`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `string` |
| 默认值 | `"frontend"` |
| 可选值 | `"frontend"`、`"backend"` |

| 值 | 说明 | 通道角色 |
|----|------|---------|
| `"frontend"` | 前端节点：面向客户端，监听本地端口，将数据通过 AF_PACKET 隧道转发到远端 | Initiator |
| `"backend"` | 后端节点：从 AF_PACKET 接收对端请求，转发到本地运行的服务 | Responder |

---

#### `max_channels`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `integer` |
| 默认值 | `256` |
| 范围 | `1` ~ `256` |

最大通道数上限。如果运行时动态创建的通道数超过此值，新连接将被拒绝。

---

#### `heartbeat_interval`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `integer` |
| 默认值 | `10` |
| 单位 | 秒 |

心跳探测间隔。通道空闲时每此间隔发送 PING 帧检测对端存活状态。

---

#### `heartbeat_timeout`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `integer` |
| 默认值 | `60` |
| 单位 | 秒 |

心跳超时时间。在此时间内未收到对端任何帧（包括 PONG 响应），通道将被判定为已断开并进入清理流程。

---

#### `kcp`（KCP 配置，全部可选）

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `mtu` | int | `1400` | KCP 最大传输单元。MSS = MTU - 24 |
| `sndwnd` | int | `1024` | 发送窗口大小（段数） |
| `rcvwnd` | int | `1024` | 接收窗口大小（段数） |
| `nodelay` | int | `1` | 启用 nodelay 模式（0/1） |
| `interval` | int | `10` | KCP 内部定时器间隔（毫秒） |
| `resend` | int | `2` | 快速重传阈值 |
| `nc` | int | `1` | 禁用拥塞控制（0=保留，1=禁用） |

---

#### `encryption`（加密配置，可选）

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 是否启用加密 |
| `sm4_key` | string | `""` | SM4 密钥，32 字符十六进制字符串（对应 16 字节密钥） |

**生成 SM4 密钥：**

```bash
# 使用 openssl 生成随机 16 字节密钥并转为 hex
openssl rand -hex 16
# 输出示例: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

---

#### `crc_enabled`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `boolean` |
| 默认值 | `false` |

是否启用 CRC32 帧校验。启用后每帧尾部附加 4 字节 CRC32 校验值，可检测传输过程中的比特错误。建议在不可靠链路上启用。

---

#### `auto_set_nic_mtu`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `boolean` |
| 默认值 | `false` |

是否自动设置网卡 MTU。启用后程序启动时会通过 `ioctl(SIOCSIFMTU)` 将网卡 MTU 设置为 `nic_mtu` 指定的值。**需要 `CAP_NET_ADMIN` 权限。**

---

#### `nic_mtu`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `integer` |
| 默认值 | `1500` |

目标 NIC MTU 值。仅在 `auto_set_nic_mtu: true` 时生效。

---

#### `pid_file`（可选）

| 属性 | 说明 |
|------|------|
| 类型 | `string` |
| 默认值 | `"/var/run/kcp-afpacket.pid"` |

PID 文件路径。用于防止同一配置文件的多实例运行。

---

#### `channels`（必填，至少一个）

通道列表，每个通道定义一个端口映射：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `channel_id` | int | 是 | 通道 ID（1-65535），两端必须对应相同 |
| `listen_port` | int | 是 | 本地监听端口 |
| `remote_port` | int | 是 | 远端目标端口 |
| `listen_addr` | string | 是 | 本地监听地址（如 `"127.0.0.1"` 或 `"0.0.0.0"`） |
| `remote_addr` | string | 是 | 远端目标地址 |
| `is_tcp` | bool | 是 | `true`=TCP，`false`=UDP |

---

## 4. 示例拓扑部署

### 场景：SSH 代理隧道

两台 Linux 主机通过以太网直连（或经交换机），通过 KCP-over-AF_PACKET 隧道代理 SSH 连接。

```
┌────────────────────────────┐          ┌────────────────────────────┐
│  Host W (客户端)             │          │  Host N (服务端)             │
│                            │          │                            │
│  ssh -p 55222 127.0.0.1   │          │  SSH Server on port 22     │
│        │                   │          │        ▲                   │
│        ▼                   │          │        │                   │
│  kcp-afpacket (frontend)   │  ether   │  kcp-afpacket (frontend)   │
│  127.0.0.1:55222 → 远端:22 │ ◄══════► │  远端:55222 → 127.0.0.1:22│
│  eth: ens19                │          │  eth: ens19                │
│  MAC: 16:95:e8:30:eb:91    │          │  MAC: 1a:af:4e:ed:9d:91    │
└────────────────────────────┘          └────────────────────────────┘
```

### Host W 配置（客户端侧，`config-node-w.json`）

```json
{
    "instance_name": "node-w",
    "interface": "ens19",
    "local_mac": "16:95:e8:30:eb:91",
    "peer_mac": "1a:af:4e:ed:9d:91",
    "nic_mtu": 1500,
    "ethertype": 35013,
    "node_type": "frontend",
    "encryption": {
        "enabled": false,
        "sm4_key": ""
    },
    "crc_enabled": false,
    "channels": [
        {
            "channel_id": 1,
            "listen_addr": "0.0.0.0",
            "listen_port": 55222,
            "remote_addr": "192.168.1.67",
            "remote_port": 22,
            "is_tcp": true
        }
    ]
}
```

### Host N 配置（服务端侧，`config-node-n.json`）

```json
{
    "instance_name": "node-n",
    "interface": "ens19",
    "local_mac": "1a:af:4e:ed:9d:91",
    "peer_mac": "16:95:e8:30:eb:91",
    "nic_mtu": 1500,
    "ethertype": 35013,
    "node_type": "frontend",
    "encryption": {
        "enabled": false,
        "sm4_key": ""
    },
    "crc_enabled": false,
    "channels": [
        {
            "channel_id": 1,
            "listen_addr": "0.0.0.0",
            "listen_port": 55222,
            "remote_addr": "192.168.1.67",
            "remote_port": 22,
            "is_tcp": true
        }
    ]
}
```

### 启动

```bash
# Host W
sudo ./kcp-afpacket config-node-w.json &

# Host N
sudo ./kcp-afpacket config-node-n.json &

# 客户端使用
ssh -p 55222 user@127.0.0.1
```

### 场景：多通道代理（Web + DNS）

```json
{
    "interface": "eth0",
    "ethertype": 35013,
    "peer_mac": "aa:bb:cc:dd:ee:ff",
    "local_mac": "",
    "instance_name": "multi-proxy",
    "node_type": "frontend",
    "kcp": {
        "mtu": 1400,
        "sndwnd": 1024,
        "rcvwnd": 1024,
        "nodelay": 1,
        "interval": 10,
        "resend": 2,
        "nc": 1
    },
    "encryption": {
        "enabled": true,
        "sm4_key": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    },
    "crc_enabled": true,
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
            "listen_port": 8443,
            "remote_port": 443,
            "listen_addr": "127.0.0.1",
            "remote_addr": "192.168.1.100",
            "is_tcp": true
        },
        {
            "channel_id": 3,
            "listen_port": 5353,
            "remote_port": 53,
            "listen_addr": "127.0.0.1",
            "remote_addr": "192.168.1.1",
            "is_tcp": false
        }
    ]
}
```

### 场景：反向代理模式

```json
{
    "interface": "eth0",
    "ethertype": 35013,
    "peer_mac": "11:22:33:44:55:66",
    "local_mac": "aa:bb:cc:dd:ee:ff",
    "node_type": "backend",
    "channels": [
        {
            "channel_id": 10,
            "listen_port": 0,
            "remote_port": 8080,
            "listen_addr": "0.0.0.0",
            "remote_addr": "127.0.0.1",
            "is_tcp": true
        }
    ]
}
```

反向代理模式下，Backend 节点不监听本地端口，而是从 AF_PACKET 接收数据后主动 `connect()` 到本地服务。

---

## 5. 作为 systemd 服务运行

### 创建 systemd unit 文件

`/etc/systemd/system/kcp-afpacket.service`

```ini
[Unit]
Description=KCP-over-AF_PACKET Tunnel Service
Documentation=https://github.com/example/kcp-afpacket
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kcp-afpacket /etc/kcp-afpacket/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/run
PrivateTmp=yes

# 安全加固
User=kcp-afpacket
Group=kcp-afpacket

[Install]
WantedBy=multi-user.target
```

### 创建专用用户

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/kcp-afpacket kcp-afpacket
sudo mkdir -p /etc/kcp-afpacket /var/lib/kcp-afpacket
sudo chown -R kcp-afpacket:kcp-afpacket /var/lib/kcp-afpacket
```

### 启用并启动服务

```bash
sudo systemctl daemon-reload
sudo systemctl enable kcp-afpacket
sudo systemctl start kcp-afpacket
sudo systemctl status kcp-afpacket
```

### 常用管理命令

```bash
# 启动 / 停止 / 重启
sudo systemctl start kcp-afpacket
sudo systemctl stop kcp-afpacket
sudo systemctl restart kcp-afpacket

# 配置热重载（不中断现有连接）
sudo systemctl reload kcp-afpacket

# 查看日志
sudo journalctl -u kcp-afpacket -f
sudo journalctl -u kcp-afpacket -n 100

# 查看状态
sudo systemctl status kcp-afpacket
```

---

## 6. 日志与监控

### 日志输出

程序日志输出到 **stderr**，格式如下：

```
[INFO] KCP-over-AF_PACKET v1.0.0 starting...
[INFO] interface: eth0, ethertype: 0x88B5
[INFO] AF_PACKET socket created, fd=3
[INFO] channel 1 created, listening on 127.0.0.1:8080
[INFO] entering main event loop
[WARN] channel 1 heartbeat timeout, closing...
[ERROR] failed to send frame: No buffer space available
```

### 调试日志

编译 Debug 版本可启用 `LOG_DEBUG` 宏输出：

```bash
make debug
./kcp-afpacket config.json 2>debug.log
```

### 统计输出

每 60 秒输出一次统计摘要（需启用 `stats_enabled`）：

```
[STATS] uptime=3600 tx_frames=12345 tx_bytes=12345678 rx_frames=12340 rx_bytes=12340000
        retrans=12 tx_err=0 rx_err=0 crc_err=0 crypto_err=0
```

### 使用 systemd journal

```bash
# 实时跟踪日志
sudo journalctl -u kcp-afpacket -f -o cat

# 过去一小时的日志
sudo journalctl -u kcp-afpacket --since "1 hour ago"

# 仅显示错误
sudo journalctl -u kcp-afpacket -p err
```

### 监控指标

| 指标 | 来源 | 说明 |
|------|------|------|
| 进程存活 | `systemctl status` / PID 文件 | 检查进程是否运行 |
| 帧收发速率 | 统计日志 | `tx_frames` / `rx_frames` 增量 |
| 重传率 | 统计日志 | `retrans / tx_frames`，应 < 5% |
| 错误率 | 统计日志 | `tx_err`、`rx_err`、`crc_err`、`crypto_err` |
| 通道数 | 统计日志 | 活跃通道数量 |
| 文件描述符 | `/proc/<pid>/fd` | socket 和 epoll fd 数量 |
| 内存占用 | `/proc/<pid>/status` | VmRSS 驻留内存 |

### 简单监控脚本

```bash
#!/bin/bash
# check_kcp_afpacket.sh
if ! pgrep -f kcp-afpacket > /dev/null; then
    echo "ERROR: kcp-afpacket not running!"
    sudo systemctl restart kcp-afpacket
fi
```

配合 cron 每分钟检查：

```
* * * * * /usr/local/bin/check_kcp_afpacket.sh
```

---

## 7. 故障排查

### 常见问题

#### Q1: `Permission denied` 或 `Operation not permitted`

**原因**：缺少 `CAP_NET_RAW` 权限。

**解决**：
```bash
# 以 root 运行
sudo ./kcp-afpacket config.json

# 或授予 capabilities
sudo setcap cap_net_raw,cap_net_admin+ep ./kcp-afpacket
```

---

#### Q2: 无法创建 AF_PACKET 套接字

**原因**：网卡名称错误或网卡不存在。

**排查**：
```bash
ip link show                          # 列出所有网卡
./kcp-afpacket test.json 2>&1 | head  # 查看错误信息
```

**解决**：确认配置文件中的 `interface` 与 `ip link show` 输出一致。

---

#### Q3: 对端无法通信（帧发送但收不到）

**排查步骤**：
1. 确认两端 `ethertype` 一致
2. 确认两端 `peer_mac` 配置正确
3. 确认两端二层可达（同一广播域/交换机）
4. 使用 `tcpdump` 抓包验证：

```bash
# 在两端分别抓包
sudo tcpdump -i eth0 ether proto 0x88b5 -vvv -X
```

5. 检查 BPF 过滤器是否正确设置：

```bash
# 查看 AF_PACKET 套接字状态
cat /proc/net/packet
```

---

#### Q4: 高重传率

**原因**：链路质量差、MTU 不匹配、KCP 参数不适合当前链路。

**排查**：
1. 检查链路 MTU：`ip link show eth0`
2. 确认 KCP MTU 不超过链路 MTU - 22（14 以太网头 + 8 MyProto 头）
3. 检查是否有 CRC 错误（说明物理链路或 MTU 问题）

---

#### Q5: 通道频繁超时断开

**原因**：心跳间隔过短、心跳超时过短、链路延迟过高。

**解决**：
```json
{
    "heartbeat_interval": 30,
    "heartbeat_timeout": 120
}
```

---

#### Q6: 加密通信失败（`crypto_errors` 递增）

**原因**：密钥不一致、HMAC 验证失败。

**排查**：
- 确认两端 `encryption.enabled` 和 `sm4_key` 完全一致
- 密钥必须为 32 字符十六进制字符串（对应 16 字节）
- 检查日志中的 `crypto_errors` 计数

---

#### Q7: 内存持续增长

**原因**：TIME_WAIT 状态通道未及时回收。

**排查**：
```bash
# 检查进程文件描述符数
ls /proc/$(pgrep kcp-afpacket)/fd | wc -l
```

**解决**：确认 `CHANNEL_GRACEFUL_TIMEOUT`（30s）超时后通道被回收。

---

#### Q8: `No buffer space available`

**原因**：发送缓冲区满。

**解决**：
```bash
# 增大套接字发送缓冲区
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.wmem_default=262144
```

---

### 诊断命令速查

```bash
# 查看 AF_PACKET 套接字
cat /proc/net/packet

# 查看 BPF 过滤器
cat /proc/net/ptype

# 网卡信息
ip link show eth0
ethtool eth0

# 抓包
sudo tcpdump -i eth0 ether proto 0x88b5 -w capture.pcap

# 进程信息
ps aux | grep kcp-afpacket
lsof -p $(pgrep kcp-afpacket)
strace -p $(pgrep kcp-afpacket) -f -e trace=network
```

---

## 8. 性能调优

### KCP 参数调优

| 场景 | mtu | sndwnd | rcvwnd | nodelay | interval | resend | nc |
|------|-----|--------|--------|---------|----------|--------|----|
| 低延迟直连 | 1478 | 512 | 512 | 1 | 5 | 1 | 1 |
| 通用直连（推荐） | 1400 | 1024 | 1024 | 1 | 10 | 2 | 1 |
| 高吞吐直连 | 1478 | 2048 | 2048 | 1 | 10 | 2 | 1 |
| 经过交换机 | 1400 | 1024 | 1024 | 0 | 20 | 3 | 0 |
| 高丢包链路 | 1400 | 512 | 512 | 0 | 20 | 1 | 0 |

### 参数含义

- **mtu**: 越大单帧承载数据越多，但超出链路 MTU 会导致 IP 分片或丢包。MSS = mtu - 24
- **sndwnd/rcvwnd**: 窗口越大吞吐越高，但内存占用越大（每段约 mtu 字节）
- **nodelay=1**: 降低延迟，直连链路推荐开启
- **interval**: 越小 KCP 更新越频繁，CPU 开销越大
- **resend**: 越小快速重传越积极，适合高丢包链路
- **nc=1**: 禁用拥塞控制，直连链路推荐；经过交换机的共享链路建议设为 0

### 系统层面优化

```bash
# 增大套接字缓冲区
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.rmem_default=262144
sudo sysctl -w net.core.wmem_default=262144

# 增大 AF_PACKET 内存限制
sudo sysctl -w net.core.optmem_max=65536

# 提高文件描述符限制
ulimit -n 65536

# 如果使用巨型帧
sudo ip link set eth0 mtu 9000
# 并在配置中设置 "nic_mtu": 9000 和更高的 kcp.mtu
```

### 网卡 MTU 与 KCP MTU 的关系

```
网卡 MTU = 1500
  → 以太网头 14 + MyProto 头 8 = 22 字节开销
  → 最大可用负载 = 1500 - 22 = 1478 字节
  → 若加密: 1478 - 48 (IV+HMAC) = 1430 字节
  → 若 CRC:  1478 - 4  = 1474 字节 (或 1430 - 4 = 1426)

因此 KCP MTU 不应超过 1478（无加密无 CRC）或 1430（加密）或 1426（加密+CRC）。
推荐保守值 1400，确保在所有配置组合下安全。
```

### 多实例部署调优

同一网卡部署多个实例时：

1. 使用不同的 EtherType
2. 使用不同的 `instance_name`
3. 使用不同的 `pid_file`
4. 合理分配 KCP 发送/接收窗口，总窗口 × 实例数不超过系统内存限制

```bash
# 实例 1
./kcp-afpacket config-1.json &

# 实例 2（不同 EtherType）
./kcp-afpacket config-2.json &
```
