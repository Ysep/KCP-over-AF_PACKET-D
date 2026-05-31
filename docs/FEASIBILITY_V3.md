# v3.0 需求可行性分析（修订版）

## 需求 1：通道级客户端 IP 与源端口 ACL

### 目标
支持灵活组合：多 IP 网段 + 范围 + 单个 IP 的并集；多端口范围 + 单个端口的并集。

### 配置格式

```json
{
    "channels": [{
        "channel_id": 1,
        "listen_port": 55222,
        "client_allow": {
            "ips":  ["10.0.0.5", "10.0.1.0/24", "192.168.0.10-192.168.0.50"],
            "ports": ["1024-65535", "8080", "443"]
        }
    }]
}
```

### 数据结构

```c
#define MAX_ACL_IPS   16    // 每个通道最多 16 条 IP 规则
#define MAX_ACL_PORTS 8     // 每个通道最多 8 条端口规则

typedef enum { ACL_SINGLE=1, ACL_CIDR=2, ACL_RANGE=3 } acl_ip_type_t;
typedef enum { ACL_PORT_SINGLE=1, ACL_PORT_RANGE=2 } acl_port_type_t;

typedef struct {
    uint8_t  enabled;
    uint8_t  ip_count;
    struct {
        uint8_t  type;       // SINGLE / CIDR / RANGE
        uint32_t addr;       // 网络字节序
        uint32_t mask_or_end; // CIDR: 掩码; RANGE: 结束 IP
    } ips[MAX_ACL_IPS];

    uint8_t  port_count;
    struct {
        uint8_t  type;       // SINGLE / RANGE
        uint16_t port_start;
        uint16_t port_end;
    } ports[MAX_ACL_PORTS];
} channel_acl_t;
```

### 匹配逻辑

```
accept 后 getpeername 获取 (client_ip, client_port)
  ↓
ips 非空 → ip 匹配任一条 → 继续; 否则 → 拒绝
ports 非空 → port 匹配任一条 → 继续; 否则 → 拒绝
均空 → 全部允许
```

### 风险

| 风险 | 等级 | 说明 |
|------|------|------|
| ACL 条目上限 | 低 | IP×16 + Port×8 覆盖 99% 场景 |
| JSON 解析 | 低 | json-c 原生支持数组和字符串 |

### 结论：✅ 可行，~120 行。

---

## 需求 2：AF_PACKET 端口劫持 — 阻止内核 TCP RST（零 iptables）

### 问题

iptables 方案无法使用。AF_PACKET 默认是 **包嗅探器**——复制包到用户态，内核 TCP 栈仍处理原包。未监听端口内核必发 RST。

### 唯一可行方案：XDP + AF_XDP

```
                    ┌──────── NIC ────────┐
                    │                      │
  进来的包  ────▶ XDP 程序                    │
                    │   port ∈ 配置范围?     │
                    │   ├── YES → AF_XDP ──▶ 用户态代理
                    │   └── NO  → XDP_DROP (静默丢)
                    │                      │
                    │   port ∉ 劫持范围?     │
                    │   └── XDP_PASS ──────▶ 内核 TCP 栈（正常）
                    │                      │
                    └──────────────────────┘
```

#### 为什么只有 XDP 可行

| 方案 | 能抢包 | 内核看不见 | AF 原生 | 用户态 TCP 代价 |
|------|--------|-----------|---------|---------------|
| AF_PACKET raw | ✅ | ❌（副本） | ✅ | — |
| AF_PACKET + fanout | ✅ | ❌ | ✅ | — |
| BPF TC hook | ✅ | ✅（仅 tc） | ✅ | — |
| **XDP + AF_XDP** | ✅ | ✅ | ✅ AF_XDP | 需实现 |
| DPDK | ✅ | ✅ | ❌ 非 AF | 需实现 |
| TPROXY + iptables | ✅ | ✅ | ❌ | — |

**XDP 是唯一能**在不经过内核 TCP 栈的前提下、用 AF_* 族机制将包导入用户态的手段。

#### 架构

```
XDP 程序（C → BPF 字节码）
  ├── 解析 Eth + IP + TCP 头
  ├── TCP.dport ∈ [PORT_MIN, PORT_MAX]?
  │      └── YES → bpf_redirect_map(sock_map, ...) → AF_XDP socket
  │      └── NO  → XDP_DROP
  └── TCP.dport ∉ 劫持范围 → XDP_PASS

用户态代理（新模块: tcp_relay.c）
  ├── AF_XDP 收包
  ├── 解析完整 TCP 流
  ├── port 已配置 → 建立通道 → 数据 relay 到 KCP
  ├── port 未配置 → 不发 RST，不发任何响应
  └── TCP 三次握手、流控、RST/FIN 在用户态处理
```

#### 用户态 TCP 需求

| 功能 | 复杂度 | 说明 |
|------|--------|------|
| 三次握手（SYN → SYN-ACK → ACK） | 中 | 固定状态机 |
| 序列号管理 | 中 | 递增，窗口通告 |
| 数据收发 | 中 | buffer → XDP TX ring |
| 四次挥手 | 中 | FIN/FIN-ACK |
| 超时重传 | 高 | 可选初版不做 |
| 窗口缩放 / SACK | 高 | 可选初版不做 |

#### 改动量

| 组件 | 改动 | 行数 |
|------|------|------|
| `xdp_filter.c` | XDP 程序（BPF） | ~60 |
| `src/af_xdp.c` | AF_XDP 初始化 + UMEM | ~200 |
| `src/tcp_relay.c` | 用户态 TCP（握手 + 数据 relay） | ~600 |
| `src/main.c` | XDP 加载 + 事件循环集成 | ~50 |
| **合计** | | **~910 行** |

#### 风险

| 风险 | 等级 | 说明 |
|------|------|------|
| 内核版本 | 🔴 | XDP = 4.8+, AF_XDP = 4.18+。CentOS 7（3.10）不支持 |
| NIC 驱动 | 🔴 | 必须支持 XDP native 模式（`ethtool -i eth0` 查看） |
| 用户态 TCP | 🔴 | ~600 行，需充分测试（重传、乱序、窗口） |
| BPF 程序加载 | 中 | 需 libbpf 或 iproute2 `ip link set xdp` |

### 结论：⚠️ 技术可行，但需 ~910 行代码，且**强依赖内核 4.18+ 和 XDP 兼容 NIC**。

> 若部署环境不支持 XDP，则此需求不可行。

---

## 需求 3：RSS 多队列 + 多线程

### 架构

```
主线程
  └── 启动 N 个 worker 线程 (N = NIC RSS 队列数)
       ├── Thread 0: epoll → AF_PACKET socket 0 (RSS queue 0) + channel_hash
       ├── Thread 1: epoll → AF_PACKET socket 1 (RSS queue 1) + channel_hash
       └── Thread N: epoll → AF_PACKET socket N (RSS queue N) + channel_hash

  共享资源:
    channel_hash[]    ← pthread_rwlock
    config_t          ← mutex (仅 reload 时写)
    listener_base[]   ← atomic 分配

  不共享（每线程自有）:
    epoll_fd, epoll 事件循环
    KCP 实例（每通道独立，无并发访问）
```

### 锁策略

```c
// 每个 channel_t 的操作:
//   channel_find:            读锁 (fast path)
//   channel_create/destroy:  写锁 (infrequent)
//   config_reload:           全局写锁，暂停所有 worker

pthread_rwlock_t hash_lock;

channel_t *channel_find_safe(ctx, id) {
    pthread_rwlock_rdlock(&hash_lock);
    channel_t *ch = channel_find(ctx, id);  // O(1)
    pthread_rwlock_unlock(&hash_lock);
    return ch;
}
```

### 线程绑定

```c
// affinity: 每个 worker 绑定一个 CPU 核心
cpu_set_t cpuset;
CPU_ZERO(&cpuset);
CPU_SET(cpu_id, &cpuset);
pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
```

### 改动量

| 文件 | 改动 | 行数 |
|------|------|------|
| `types.h` | 新增 `rss_queues`, `hash_lock`, 线程相关字段 | +10 |
| `af_packet.c` | `af_packet_create_mq(index)` | +20 |
| `proxy.c` | epoll 分发适配（每线程独立 epoll） | +30 |
| `channel.c` | 哈希表操作加锁 | +40 |
| `main.c` | 线程创建 + affinity + 启动 | +60 |
| `tests/` | 无（需真实 NIC 测试多线程） | — |
| **合计** | | **~160 行** |

### 风险

| 风险 | 等级 | 说明 |
|------|------|------|
| 锁竞争 | 中 | `channel_find` 频繁读锁，92ns/次；写锁低频 |
| KCP 线程安全 | 低 | 每通道独占一线程，KCP 实例不共享 |
| deadlink 共享 | 🟡 | 主线程心跳可能需要自己的通道 |

### 结论：✅ 可行，~160 行。单通道 KCP 无锁。哈希表读锁性能足够。

---

## 汇总

| # | 需求 | 方案 | 代码 | 风险 | 可行 |
|---|------|------|------|------|------|
| 1 | IP/Port ACL | `getpeername` + 并集匹配 | ~120 行 | 低 | ✅ |
| 2 | AF 端口劫持 | XDP + AF_XDP + 用户态 TCP | ~910 行 | 🔴 高 | ⚠️ |
| 3 | RSS + 多线程 | pthread + rwlock | ~160 行 | 中 | ✅ |

### 需求 2 的决定性因素

```
必须满足 ALL:
  □ 内核 ≥ 4.18 (CentOS 7 ❌, CentOS 8+ ✅, Debian 10+ ✅, Ubuntu 18.04 ❌, 20.04+ ✅)
  □ NIC 支持 XDP native (ethtool -i eth0 | grep xdp)
  □ 开发周期可容纳 ~910 行用户态 TCP

任何一项不满足 → 需求 2 不可行，退化为 iptables 方案。
```
