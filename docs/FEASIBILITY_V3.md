# v3.0 需求可行性分析

## 需求 1：通道级客户端 IP 与源端口限制

### 目标
每个 listener 通道可限制允许连接的客户端 IP 地址（CIDR）和源端口范围。

### 技术方案

```
proxy_accept() 增加检查:
  accept4() → client_fd
  getpeername(client_fd, &client_addr, ...)  ← 新增
  check_against_allowlist(ch, &client_addr)  ← 新增
    ├── 匹配 → 继续创建动态通道
    └── 不匹配 → close(client_fd) → continue accept 循环
```

#### 配置扩展

```json
{
    "channels": [{
        "channel_id": 1,
        "listen_port": 55222,
        "remote_addr": "192.168.1.67",
        "remote_port": 22,
        "client_allow": {
            "address": "10.0.0.0/24",
            "port_min": 1024,
            "port_max": 65535
        }
    }]
}
```

不配置 `client_allow` 则行为不变（允许所有客户端）。

### 数据结构变更

```c
// channel_config_t 新增
typedef struct {
    uint8_t  enabled;              // 1=启用限制
    char     address[MAX_LISTEN_ADDR]; // "10.0.0.0/24" 或 "10.0.0.5"
    uint16_t port_min;
    uint16_t port_max;
} client_acl_t;
```

### 改动量

| 文件 | 改动 | 行数 |
|------|------|------|
| `types.h` | 新增 `client_acl_t`，嵌入 `channel_config_t` | +8 |
| `proxy.c` | `proxy_accept` 中加 `getpeername` + IP/CIDR 匹配 | +25 |
| `main.c` | JSON 解析 | +15 |
| `channel.c` | `channel_config_changed`/`update_config` 适配 | +5 |
| **合计** | | **~53 行** |

### 风险

| 风险 | 等级 | 缓解 |
|------|------|------|
| CIDR 匹配性能 | 低 | 32 位掩码操作，`accept` 时执行一次 |
| IPv6 支持 | 低 | 初版仅 IPv4，后续扩展 |

### 结论：✅ 可行，改动小，无架构变更。

---

## 需求 2：端口劫持 — 阻止 TCP RST

### 目标
指定端口范围的包不进内核 TCP 栈，未配置端口静默丢弃（无 RST）。

### 问题根源

```
客户端 ──TCP SYN──▶ 内核 TCP 栈
                       │
                       ├── 端口 55222 有进程监听 → accept ✅
                       └── 端口 55223 无进程监听 → 内核发 RST ❌
```

`listen()` 只能绑定已配置端口，其他端口由内核处理。

### 方案对比

| 方案 | 原理 | 复杂度 | 性能 |
|------|------|--------|------|
| **A: iptables DROP RST** | `iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport <range> -j DROP` | 极低 | 无影响 |
| B: NFQUEUE 劫持 | `iptables -j NFQUEUE` → 用户态处理 → 未配置丢弃 | 中 | 每次包上下文切换 |
| C: TPROXY 透明代理 | `iptables -j TPROXY` + `IP_TRANSPARENT` 监听 | 中 | 好 |
| D: AF_PACKET 层面拦截 | BPF 过滤所有端口范围 TCP 包 | 高 | 需用户态 TCP 栈 |

### 推荐方案 A：iptables DROP RST（零代码改动）

```bash
# 安装时自动配置
iptables -A OUTPUT -p tcp \
    --match multiport --dports 55222:55231 \
    --tcp-flags RST RST -j DROP
```

#### 工作原理

```
客户端 ──SYN──▶ 端口 55223（未配置）
                 │
                 内核 → 无监听者 → 发送 RST
                 │
                 iptables OUTPUT 链 → 匹配 RST + 端口范围 → DROP
                 │
                 客户端收不到 RST → 超时 → 连接失败（静默）
```

#### 部署脚本集成

```bash
# deploy/install.sh 新增
iptables -C OUTPUT -p tcp -m multiport --dports 55222:55231 \
    --tcp-flags RST RST -j DROP 2>/dev/null || \
iptables -A OUTPUT -p tcp -m multiport --dports 55222:55231 \
    --tcp-flags RST RST -j DROP

# uninstall.sh 清理
iptables -D OUTPUT -p tcp -m multiport --dports 55222:55231 \
    --tcp-flags RST RST -j DROP 2>/dev/null
```

### 限制

| 限制 | 说明 |
|------|------|
| 需 root | iptables 操作需要 root 权限 |
| 不影响 AF_PACKET | AF_PACKET 使用独立 EtherType（0x88B5），不经过 TCP 栈 |
| 端口范围需预知 | 配置变更后需刷新 iptables 规则 |

### 结论：✅ 可行，iptables 方案零代码改动，部署脚本自动配置。

---

## 需求 3：RSS 多队列

### 目标
AF_PACKET 接收路径使用 NIC 多队列 + RSS 哈希，将包分散到多个 CPU 核处理。

### 当前架构

```
NIC → 单 AF_PACKET socket (rx_ring) → epoll_wait → 单线程处理
                          队列 0  队列 1  队列 2  队列 3
                          └──────── 合并为一条 ───────┘
```

### 多队列架构

```
NIC 多队列
 ├── 队列 0 → AF_PACKET socket 0 (rx_ring) ┐
 ├── 队列 1 → AF_PACKET socket 1 (rx_ring) ├── epoll_wait → 单线程 event loop
 ├── 队列 2 → AF_PACKET socket 2 (rx_ring) │
 └── 队列 3 → AF_PACKET socket 3 (rx_ring) ┘
```

#### 单线程多 fd 方案

```c
// main.c init 阶段
#define RSS_QUEUES 4
int raw_socks[RSS_QUEUES];

for (int q = 0; q < RSS_QUEUES; q++) {
    raw_socks[q] = af_packet_create_mq(if_name, ethertype, ifindex, q);
    proxy_epoll_add(ctx, raw_socks[q], NULL);  // NULL = 不绑定 channel
}

// epoll 分发时
if (fd 是 AF_PACKET socket) {
    af_packet_recv(fd, ...) → 提取帧 → channel_process_frame → KCP
}
```

**关键**：所有 AF_PACKET socket 共享同一个 epoll 实例 + 同一个哈希表。单线程无需锁。

#### af_packet_create_mq 实现

```c
int af_packet_create_mq(const char *if_name, uint16_t ethertype,
                         int *ifindex, int queue_idx)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ethertype));
    // ... TPACKET_V2 ...

    // 绑定到指定队列
    setsockopt(fd, SOL_PACKET, PACKET_RX_RING, ...);
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, ...);

    // 通过 fanout 或直接绑定 queue
    struct tpacket_req3 req;
    // 设置 rx ring
    setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));

    // ETHTOOL 配置 queue mapping 在驱动层
    // 应用程序只需 bind 到接口，内核 RSS 自动分发
    bind(fd, ...);
    return fd;
}
```

**重要**：Linux 的 AF_PACKET + PACKET_RX_RING 在内核 3.x+ 已支持自动 RSS。创建多个 socket 绑定到同一接口时，内核自动 hash 分发到不同 socket。

### 改动量

| 文件 | 改动 | 行数 |
|------|------|------|
| `types.h` | `raw_sock` → `raw_socks[RSS_MAX]` + `rss_queues` | +3 |
| `af_packet.c` | `af_packet_create` → 支持多队列参数 | +15 |
| `main.c` | 初始化循环创建 N 个 socket + epoll 注册 | +15 |
| `proxy.c` | epoll 分发适配多 fd | +5 |
| **合计** | | **~38 行** |

### 多线程方案（可选升级）

```
主线程 epoll → AF_PACKET socket 0
线程 1  epoll → AF_PACKET socket 1
线程 2  epoll → AF_PACKET socket 2
线程 3  epoll → AF_PACKET socket 3
          ↓
共享 channel 哈希表（需读写锁）
```

| 复杂度 | 当前 | 多线程 |
|--------|------|--------|
| 锁 | 无 | 哈希表 rwlock |
| KCP 并发 | 无 | 需确认 ikcp 线程安全 |
| 改动量 | 38 行 | ~150 行 |

### 风险

| 风险 | 等级 | 说明 |
|------|------|------|
| 内核版本 | 低 | 需 3.x+（覆盖所有现代发行版） |
| NIC 驱动支持 | 中 | 需确认 NIC 支持 RSS（`ethtool -l`） |
| 队列数硬限制 | 低 | 受 NIC 硬件队列数限制（通常 4–16） |
| 单线程瓶颈 | 中 | 单线程处理 4 路队列，串行化收益有限 |

### 结论：✅ 可行。单线程多 fd 方案 38 行，零锁。多线程方案 ~150 行但需引入锁。

---

## 汇总

| 需求 | 方案 | 代码改动 | 风险 | 推荐 |
|------|------|---------|------|------|
| 1. 客户端限制 | `getpeername` + CIDR 匹配 | ~53 行 | 低 | ✅ |
| 2. 端口劫持 | iptables DROP RST（零代码） | 0 行 | 低 | ✅ |
| 3. RSS 多队列 | 单线程多 fd | ~38 行 | 中 | ✅ |

**总改动 ~90 行，零架构变更。**
