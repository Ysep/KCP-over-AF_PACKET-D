# 配置文件参考 — KCP-over-AF_PACKET

本文档是 JSON 配置文件的完整参考，涵盖所有配置项的类型、默认值、取值范围和详细说明。

---

## 顶层结构

```json
{
    "interface":          "<string>",
    "ethertype":          <uint16>,
    "peer_mac":           "<string | "">",
    "local_mac":          "<string | "">",
    "kcp":                { <KCP config> },
    "performance":        { <Performance config> },
    "node_type":          "frontend" | "backend",
    "max_channels":       <int>,
    "heartbeat_interval": <int>,
    "heartbeat_timeout":  <int>,
    "crypto":             { <Crypto config> },
    "crc_enabled":        <bool>,
    "auto_set_nic_mtu":   <bool>,
    "nic_mtu":            <int>,
    "pid_file":           "<string>",
    "channels":           [ <Channel config>, ... ]
}
```

---

## 性能调优配置

影响吞吐、重传和背压的参数集中在顶层 `performance` 对象中。完整说明见 [PERFORMANCE_CONFIG.md](PERFORMANCE_CONFIG.md)。

---

## 配置项详细说明

### 1. `interface`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **必填** | 是 |
| **默认值** | 无（空字符串会导致验证失败） |
| **示例** | `"eth0"`, `"enp3s0"`, `"eth1"` |

网卡接口名称。AF_PACKET 套接字将绑定到此网卡进行原始帧收发。接口名称不能超过 32 字符（`IFNAMSIZ`）。

---

### 2. `ethertype`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` (uint16) |
| **必填** | 是 |
| **默认值** | `35013` (`0x88B5`) |
| **示例** | `35013`, `0x88B5`, `34999` |

自定义以太网帧类型（EtherType），用于区分本系统与其他协议的数据帧。取值范围：`0x0600` ~ `0xFFFF`，不得使用保留范围 `0x0000`-`0x05FF`（IEEE 802.3 长度字段范围）以及已广泛使用的标准协议类型。**同一链路上的两个对端必须使用相同的 EtherType。** 同一网卡上部署多个实例时需使用不同的 EtherType。

#### 多实例 EtherType 分配

如果同一台机器、同一块网卡上启动多个 `kcp-afpacket` 实例，每一对 B/C 对端实例必须使用独立的 `ethertype`。否则多个进程会同时收到同一批 AF_PACKET 帧，动态通道 ID 又可能从相同范围开始分配，容易出现跨端口串包、错误连接后端端口或 `recv_buf overflow`。

分配规则：

```text
B 的实例 1 ethertype == C 的实例 1 ethertype
B 的实例 2 ethertype == C 的实例 2 ethertype
不同实例之间 ethertype 不能相同
```

示例：

```text
5201 实例:
B 5201.json ethertype = 35013
C 5201.json ethertype = 35013

5202 实例:
B 5202.json ethertype = 35014
C 5202.json ethertype = 35014

5203 实例:
B 5203.json ethertype = 35015
C 5203.json ethertype = 35015
```

常用连续值：

```text
35013 = 0x88C5
35014 = 0x88C6
35015 = 0x88C7
35016 = 0x88C8
```

多实例部署时，即使不同实例的 `channel_id` 都写 `100`，只要 `ethertype` 不同，也不会互相串包。反过来，如果 `ethertype` 相同，仅修改监听端口或配置文件名不能隔离不同实例。

---

### 3. `peer_mac`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **必填** | 否（但推荐填写） |
| **默认值** | `""`（空字符串，回退为广播地址 `ff:ff:ff:ff:ff:ff`） |
| **示例** | `"aa:bb:cc:dd:ee:ff"` |

对端网卡的 MAC 地址，格式为冒号分隔的十六进制字符串（6 字节）。发送的以太网帧将使用此地址作为目标 MAC。

- **已配置**：直接使用该 MAC 地址发送帧。
- **留空**：回退为广播地址。⚠️ **注意：** 自动发现功能尚未完整实现，当前可能无法正常通信。**强烈建议显式配置。**

---

### 4. `local_mac`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **必填** | 否 |
| **默认值** | `""`（空字符串，自动获取网卡 MAC） |
| **示例** | `"11:22:33:44:55:66"` |

本地网卡的 MAC 地址。

- **已配置**：使用该 MAC 地址作为以太网帧源地址。
- **留空**：通过 `ioctl(SIOCGIFHWADDR)` 自动从网卡获取 MAC 地址。

---

### 5. `kcp` (KCP 配置对象)

KCP 协议参数配置。所有子项均可选，未配置时使用默认值。

#### 5.1 `kcp.mtu`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `1400` |
| **范围** | `> 0` |
| **示例** | `1400`, `1478` |

KCP 最大传输单元（字节）。该值决定 KCP 内部数据分段大小（MSS = MTU - 24 字节 KCP 头）。

| 预设值 | 常量 | 值 | MSS | 适用场景 |
|--------|------|-----|------|----------|
| 保守 | `KCP_MTU_CONSERVATIVE` | 1400 | 1376 | 通用场景，确保不超出链路 MTU |
| 高性能 | `KCP_MTU_PERFORMANCE` | 1478 | 1454 | 已知链路 MTU 为 1500 的场景 |

#### 5.2 `kcp.sndwnd`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `1024` |
| **范围** | `> 0` |
| **示例** | `512`, `1024`, `2048` |

发送窗口大小（段数）。较大的窗口可提高吞吐量，但会增加内存占用。高速链路建议 1024-2048。

#### 5.3 `kcp.rcvwnd`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `1024` |
| **范围** | `> 0` |
| **示例** | `512`, `1024`, `2048` |

接收窗口大小（段数）。必须与对端的发送窗口配合设置。通常与 `sndwnd` 设为相同值。

#### 5.4 `kcp.nodelay`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `1` |
| **可选值** | `0`（关闭）, `1`（开启） |
| **示例** | `1` |

nodelay 模式开关。启用后 KCP 将更积极地发送数据（关闭 Nagle 类算法），降低延迟。建议保持为 `1`。

#### 5.5 `kcp.interval`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `10` |
| **单位** | 毫秒 |
| **示例** | `10`, `20` |

KCP 内部定时器更新间隔。较小的值可降低延迟但增加 CPU 开销。10ms 为推荐值。

#### 5.6 `kcp.resend`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `2` |
| **示例** | `2`, `3` |

快速重传阈值。当某个数据段被跳过的次数达到此值时触发快速重传（不等超时）。值越小重传越积极。

#### 5.7 `kcp.nc`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `1` |
| **可选值** | `0`（保留拥塞控制）, `1`（关闭拥塞控制） |
| **示例** | `1` |

是否禁用 KCP 拥塞控制。直连物理链路场景推荐设为 `1`（禁用），因为链路层不存在共享拥塞；经过交换机的场景可设为 `0` 保留基本的拥塞控制。

---

### 6. `node_type`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **默认值** | `"frontend"` |
| **可选值** | `"frontend"`, `"backend"` |
| **示例** | `"frontend"` |

节点角色：

| 模式 | 说明 | 通道角色 |
|------|------|----------|
| `"frontend"` | **前端节点**：在本地监听端口，将应用数据通过 AF_PACKET 隧道转发到后端，后端再转发到目标服务。 | Initiator |
| `"backend"` | **后端节点**：从 AF_PACKET 接收对端请求，转发到本地运行的服务。 | Responder |

---

### 7. `max_channels`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `256` |
| **范围** | `1` ~ `256` |
| **示例** | `128` |

最大通道数上限。如果运行时通过 SYN 动态创建的通道数超过此值，新连接将被拒绝。

---

### 8. `heartbeat_interval`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `10` |
| **单位** | 秒 |
| **示例** | `10`, `30` |

心跳探测间隔。通道在空闲时每此间隔发送 PING 帧检测对端是否存活。

---

### 9. `heartbeat_timeout`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `60` |
| **单位** | 秒 |
| **示例** | `60`, `120` |

心跳超时时间。如果在此时间内未收到对端的任何帧（包括 PONG 响应），通道将被判定已断开并进入清理流程。

---

### 10. `crypto` (加密配置对象)

#### 10.1 `crypto.enabled`

| 属性 | 值 |
|------|-----|
| **类型** | `boolean` |
| **默认值** | `false` |
| **示例** | `true` |

是否启用加密。启用后所有数据帧将使用 SM4-CTR 加密并附加 HMAC-SM3 完整性标签。

#### 10.2 `crypto.key`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **默认值** | `""`（空字符串） |
| **格式** | 32 字符十六进制字符串（16 字节） |
| **示例** | `"0123456789ABCDEFFEDCBA9876543210"` |

预共享密钥（PSK），16 字节。**两端必须使用相同的密钥。** `enabled=true` 时此字段必填，否则验证失败。

> ⚠️ **安全警告**：当前 SM4-CTR + HMAC-SM3 为**存根实现**（XOR + FNV-1a 模拟），不提供实际的安全性。生产环境请替换为 GmSSL 或 OpenSSL 的真实 SM4/SM3 实现。

---

### 11. `crc_enabled`

| 属性 | 值 |
|------|-----|
| **类型** | `boolean` |
| **默认值** | `false` |
| **示例** | `true` |

是否启用 CRC32 帧校验。启用后每帧末尾附加 4 字节 CRC32 校验值，接收端验证。注意：如果同时启用了加密（HMAC-SM3），CRC32 为冗余校验，可酌情关闭以减少 4 字节开销。

---

### 12. `auto_set_nic_mtu`

| 属性 | 值 |
|------|-----|
| **类型** | `boolean` |
| **默认值** | `false` |
| **示例** | `true` |

是否在启动时自动设置网卡 MTU。启用后使用 `nic_mtu` 指定的值通过 `ioctl(SIOCSIFMTU)` 修改网卡 MTU。**需要 CAP_NET_ADMIN 权限。**

---

### 13. `nic_mtu`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` |
| **默认值** | `1500` |
| **单位** | 字节 |
| **示例** | `1500`, `9000` |

目标网卡 MTU 值。仅在 `auto_set_nic_mtu=true` 时生效。如果物理链路支持巨帧（Jumbo Frame，如 9000），可配合调整 KCP MTU 以获得更好性能。

---

### 14. `pid_file`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **默认值** | `""`（不创建 PID 文件） |
| **示例** | `"/var/run/kcp-afpacket.pid"` |

PID 文件路径。用于多实例部署和进程管理（如 systemd 的 `PIDFile=` 指令）。

---

### 15. `channels` (通道配置数组)

类型为数组，每个元素定义一个通道。

#### 15.1 `channel_id`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` (uint32) |
| **必填** | 是 |
| **范围** | `1` ~ `65535`（静态）/ `65536` ~ `4294967295`（动态） |
| **示例** | `1`, `100` |

通道唯一标识符。在帧头部作为 `channel_id` 字段（4 字节），用于多流复用中的帧路由。**同一配置文件中的所有通道 `channel_id` 必须唯一。** 对端配置中相同 `channel_id` 的通道将配对通信。

#### 15.2 `listen_port` / `listen_port_range`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` (uint16) / `string` 或 `[start, end]` |
| **必填** | 是，二选一 |
| **范围** | `1` ~ `65535` |
| **示例** | `8080`, `"5201-5203"`, `[5201, 5203]` |

本地监听端口。正向代理模式下，代理程序在此端口上监听来自本地应用的 TCP/UDP 连接。连续端口可使用 `listen_port_range`，加载配置时会展开为多条内部通道。

#### 15.3 `remote_port` / `remote_port_range`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` (uint16) / `string` 或 `[start, end]` |
| **必填** | 是，二选一 |
| **范围** | `1` ~ `65535` |
| **示例** | `80`, `"5201-5203"`, `[5201, 5203]` |

远端目标端口。正向代理模式下，对端代理将数据转发到此端口上的目标服务。与 `listen_port_range` 搭配时，`remote_port` 可作为起始端口按偏移自动递增；也可显式写 `remote_port_range`，但长度必须与 `listen_port_range` 相同。

端口范围展开规则：

- `channel_id` 是起始 ID，展开后的内部通道按 `channel_id + offset` 递增。
- `listen_port_range: "5201-5203"` 会展开为监听 `5201`、`5202`、`5203`。
- 若配置 `remote_port: 6201`，远端端口展开为 `6201`、`6202`、`6203`。
- 若配置 `remote_port_range: "6201-6203"`，范围长度必须等于监听端口范围长度。
- 范围展开后的通道总数仍受 `MAX_CHANNELS` 和 `max_channels` 限制，展开后的 `channel_id` 仍必须唯一。

示例：

```json
{
    "channel_id": 100,
    "listen_addr": "0.0.0.0",
    "listen_port_range": "5201-5203",
    "remote_addr": "192.168.1.67",
    "remote_port": 5201,
    "is_tcp": true,
    "max_sessions": 256
}
```

等价于手写 `channel_id` 为 `100`、`101`、`102` 的三条通道。

#### 15.3.1 一个配置文件开启多个示例

推荐优先使用一个 `kcp-afpacket` 进程加载一个包含多个 `channels` 的配置文件，而不是为每个端口启动一个进程。单进程多通道可以避免同一网卡、同一 `ethertype` 下多个进程重复收帧。

每个示例写成 `channels` 数组中的一个对象：

```json
"channels": [
    {
        "channel_id": 100,
        "listen_addr": "0.0.0.0",
        "listen_port": 55222,
        "remote_addr": "192.168.1.149",
        "remote_port": 22,
        "is_tcp": true,
        "max_sessions": 256
    },
    {
        "channel_id": 101,
        "listen_addr": "0.0.0.0",
        "listen_port": 5201,
        "remote_addr": "192.168.1.149",
        "remote_port": 5201,
        "is_tcp": true,
        "max_sessions": 2000
    },
    {
        "channel_id": 102,
        "listen_addr": "0.0.0.0",
        "listen_port": 5202,
        "remote_addr": "127.0.0.1",
        "remote_port": 5202,
        "is_tcp": true,
        "max_sessions": 2000
    }
]
```

含义：

- `channel_id=100`: 客户端访问 frontend 的 `55222`，backend 转发到 `192.168.1.149:22`。
- `channel_id=101`: 客户端访问 frontend 的 `5201`，backend 转发到 `192.168.1.149:5201`。
- `channel_id=102`: 客户端访问 frontend 的 `5202`，backend 转发到 backend 本机 `127.0.0.1:5202`。

如果服务端在 backend 本机，backend 配置中的 `remote_addr` 写 `127.0.0.1`。如果服务端在另一台服务器，例如 D，则写 D 的 IP，如 `192.168.1.149`。

也可以用端口范围减少重复配置：

```json
{
    "channel_id": 200,
    "listen_addr": "0.0.0.0",
    "listen_port_range": "5203-5205",
    "remote_addr": "192.168.1.149",
    "remote_port": 5203,
    "is_tcp": true,
    "max_sessions": 2000
}
```

该配置会展开为：

```text
channel_id=200, listen 5203 -> remote 5203
channel_id=201, listen 5204 -> remote 5204
channel_id=202, listen 5205 -> remote 5205
```

注意事项：

- B/C 两端的静态 `channel_id` 必须一致。
- 同一个配置文件内 `channel_id` 不能重复。
- 同一个 frontend 进程内 `listen_port` 不能重复，否则绑定端口会失败。
- `listen_port_range` 展开后的 `channel_id` 也不能与其它通道冲突。
- 如果确实要启动多个进程实例，必须按前文为每个实例分配不同的 `ethertype`。

#### 15.4 `listen_addr`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **默认值** | `"127.0.0.1"` |
| **示例** | `"127.0.0.1"`, `"0.0.0.0"` |

本地监听地址（IPv4）。设为 `"0.0.0.0"` 监听所有网络接口，`"127.0.0.1"` 仅本地访问。

#### 15.5 `remote_addr`

| 属性 | 值 |
|------|-----|
| **类型** | `string` |
| **默认值** | `""`（空字符串） |
| **示例** | `"192.168.1.100"` |

远端目标地址（IPv4）。对端代理将数据连接到此地址。

#### 15.6 `is_tcp`

| 属性 | 值 |
|------|-----|
| **类型** | `boolean` |
| **默认值** | `false` |
| **示例** | `true`, `false` |

传输协议类型：`true` = TCP，`false` = UDP。

#### 15.7 `max_sessions`

| 属性 | 值 |
|------|-----|
| **类型** | `integer` (uint16) |
| **默认值** | `1` |
| **范围** | `1` ~ `65535` |
| **示例** | `1`, `5`, `32` |

此端口允许的最大并发会话数。0 或 1 使用单会话动态通道模式；>1 启用多会话模式，每个 accept 创建一个独立的动态 INITIATOR 通道，共享同一 listener 的网络层信息。

#### 15.8 `client_acl`（客户端访问控制）

| 属性 | 值 |
|------|-----|
| **类型** | `object`（可选） |
| **默认值** | 不配置 = 全部允许 |

仅 TCP 通道生效。在 `proxy_accept` 时通过 `getpeername()` 获取客户端 IP/端口进行匹配。

##### `ips` (string[], 最多 16 条)

IP 规则列表，匹配任一即通过。支持三种格式：

- `"10.0.0.5"` — 单个 IP
- `"10.0.1.0/24"` — CIDR 网段
- `"192.168.0.10-192.168.0.50"` — IP 范围（闭区间）

##### `ports` (string[], 最多 8 条)

端口规则列表，匹配任一即通过。支持两种格式：

- `"8080"` — 单个端口
- `"1024-65535"` — 端口范围（闭区间）

##### 组合逻辑

`ips` 和 `ports` 均为空 → 全部允许。均非空 → IP 和端口都需满足（AND）。仅一项非空 → 仅检查该项。

```json
"client_acl": {
    "ips": ["10.0.0.0/8", "172.16.0.0/12"],
    "ports": ["1024-65535"]
}
```

---

## 完整配置示例

```json
{
    "interface": "eth1",
    "ethertype": 35013,
    "peer_mac": "aa:bb:cc:dd:ee:ff",
    "local_mac": "11:22:33:44:55:66",
    "kcp": {
        "mtu": 1400,
        "sndwnd": 1024,
        "rcvwnd": 1024,
        "nodelay": 1,
        "interval": 10,
        "resend": 2,
        "nc": 1
    },
    "node_type": "frontend",
    "max_channels": 128,
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
            "remote_addr": "10.0.0.2",
            "is_tcp": true
        },
        {
            "channel_id": 2,
            "listen_port": 5353,
            "remote_port": 53,
            "listen_addr": "127.0.0.1",
            "remote_addr": "10.0.0.1",
            "is_tcp": false
        }
    ]
}
```

---

## 最简配置示例

仅需要三个必填项即可启动：

```json
{
    "interface": "eth0",
    "ethertype": 35013,
    "channels": [
        {
            "channel_id": 1,
            "listen_port": 8080,
            "remote_port": 80
        }
    ]
}
```

所有其他参数将使用默认值。

---

## 配置验证规则

配置文件加载后经过以下验证流程：

1. `interface` 不能为空
2. `ethertype` 必须 ≥ `0x0600`（排除 IEEE 802.3 保留范围）
3. 若指定 `peer_mac`，格式必须为 `xx:xx:xx:xx:xx:xx`
4. `kcp.mtu`, `kcp.sndwnd`, `kcp.rcvwnd` 均需 > 0
5. `node_type` 必须为 `"frontend"` 或 `"backend"`
6. `max_channels` 必须在 `[1, 256]` 范围内
7. 至少配置 1 个通道
8. 所有通道 `channel_id` 必须 > 0 且唯一
9. 所有通道 `listen_port` 和 `remote_port` 必须在 `[1, 65535]` 范围内
10. 若启用加密，必须提供 32 字符十六进制密钥
