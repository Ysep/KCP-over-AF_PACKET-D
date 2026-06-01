# 通道级客户端 IP/端口 ACL 设计

## 1. 概述

每个 listener 通道可配置客户端访问控制列表（ACL），在 `proxy_accept` 时通过 `getpeername` 获取客户端地址并匹配。ACL 不配置则行为不变——允许所有客户端。

## 2. 配置格式

```json
{
    "channels": [{
        "channel_id": 1,
        "listen_port": 55222,
        "client_acl": {
            "ips": [
                "10.0.0.5",
                "10.0.1.0/24",
                "192.168.0.10-192.168.0.50"
            ],
            "ports": [
                "1024-65535",
                "8080",
                "443"
            ]
        }
    }]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `ips` | string[] | IP 规则列表，匹配任一即通过。不配置 = 全部允许 |
| `ports` | string[] | 端口规则列表，匹配任一即通过。不配置 = 全部允许 |
| 组合逻辑 | — | `ips` 非空 **且** `ports` 非空 → 两者都需匹配。其一为空则仅检查另一项 |

IP 格式：
- `"10.0.0.5"` — 单个 IP
- `"10.0.1.0/24"` — CIDR 网段
- `"192.168.0.10-192.168.0.50"` — IP 范围（两端均包含）

端口格式：
- `"8080"` — 单个端口
- `"1024-65535"` — 端口范围（两端均包含）

数量上限：`ips` ≤ 16 条，`ports` ≤ 8 条（编译期常量）。

## 3. 数据结构

```c
#define MAX_ACL_IPS    16
#define MAX_ACL_PORTS  8

typedef enum {
    ACL_IP_SINGLE = 1,       /* 单个 IP  "10.0.0.5"          */
    ACL_IP_CIDR   = 2,       /* CIDR     "10.0.1.0/24"      */
    ACL_IP_RANGE  = 3        /* 范围     "192.168.0.10-50"   */
} acl_ip_type_t;

typedef enum {
    ACL_PORT_SINGLE = 1,     /* 单个端口 "8080"              */
    ACL_PORT_RANGE  = 2      /* 范围     "1024-65535"        */
} acl_port_type_t;

/* IP 访问控制条目 */
typedef struct {
    uint8_t  type;           /* acl_ip_type_t                */
    uint32_t addr;           /* 网络字节序: 起始 IP 或单 IP  */
    uint32_t mask_or_end;    /* CIDR: 子网掩码; RANGE: 结束 IP */
} acl_ip_entry_t;

/* 端口访问控制条目 */
typedef struct {
    uint8_t  type;           /* acl_port_type_t              */
    uint16_t port_start;     /* 起始端口                      */
    uint16_t port_end;       /* 结束端口（SINGLE 时 = port_start） */
} acl_port_entry_t;

/* 通道级客户端 ACL（嵌入 channel_config_t） */
typedef struct {
    uint8_t         enabled;    /* 0=不启用（全放行） */
    uint8_t         ip_count;   /* ips 数组有效条目数 */
    acl_ip_entry_t  ips[MAX_ACL_IPS];
    uint8_t         port_count; /* ports 数组有效条目数 */
    acl_port_entry_t ports[MAX_ACL_PORTS];
} channel_acl_t;
```

`channel_config_t` 新增字段：
```c
channel_acl_t client_acl;   /* +128 字节（16×8 + 8×4 + 3） */
```

`sizeof(channel_config_t)` 从 ~132 → ~260 字节，65536 条配置 ~17 MB (增加 ~8 MB)。

## 4. 匹配算法

### 4.1 IP 匹配

```c
static int acl_ip_match(uint32_t client_ip, const acl_ip_entry_t *entry)
{
    switch (entry->type) {
    case ACL_IP_SINGLE:
        return (client_ip == entry->addr);

    case ACL_IP_CIDR:
        return ((client_ip & entry->mask_or_end) ==
                (entry->addr & entry->mask_or_end));

    case ACL_IP_RANGE:
        return (ntohl(client_ip) >= ntohl(entry->addr) &&
                ntohl(client_ip) <= ntohl(entry->mask_or_end));

    default:
        return 0;
    }
}
```

### 4.2 端口匹配

```c
static int acl_port_match(uint16_t client_port, const acl_port_entry_t *entry)
{
    switch (entry->type) {
    case ACL_PORT_SINGLE:
        return (client_port == entry->port_start);

    case ACL_PORT_RANGE:
        return (client_port >= entry->port_start &&
                client_port <= entry->port_end);

    default:
        return 0;
    }
}
```

### 4.3 总匹配逻辑

```c
int acl_check(const channel_acl_t *acl, uint32_t client_ip, uint16_t client_port)
{
    /* 未启用 → 全部放行 */
    if (!acl->enabled) return 1;

    /* IP 检查（ip_count == 0 → 跳过） */
    if (acl->ip_count > 0) {
        int ip_ok = 0;
        for (int i = 0; i < acl->ip_count; i++) {
            if (acl_ip_match(client_ip, &acl->ips[i])) {
                ip_ok = 1;
                break;
            }
        }
        if (!ip_ok) return 0;
    }

    /* 端口检查（port_count == 0 → 跳过） */
    if (acl->port_count > 0) {
        int port_ok = 0;
        for (int i = 0; i < acl->port_count; i++) {
            if (acl_port_match(client_port, &acl->ports[i])) {
                port_ok = 1;
                break;
            }
        }
        if (!port_ok) return 0;
    }

    return 1; /* 通过 */
}
```

时间复杂度：O(ip_count + port_count) ≤ O(24)，每次 accept 执行一次。

## 5. 集成点

### 5.1 proxy_accept（proxy.c）

```c
// 现有代码:
client_fd = accept4(ch->listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

// 新增:
struct sockaddr_storage peer_addr;
socklen_t peer_len = sizeof(peer_addr);

if (ch->config && ch->config->client_acl.enabled) {
    if (getpeername(client_fd, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
        uint32_t ip;
        uint16_t port;
        if (extract_ip_port(&peer_addr, &ip, &port)) {
            if (!acl_check(&ch->config->client_acl, ip, port)) {
                LOG_DEBUG("proxy_accept: ACL rejected %s:%u on channel %u",
                          ip_to_str(ip), port, ch->channel_id);
                close(client_fd);
                continue;  // 继续 accept 循环，不等下一个 epoll 事件
            }
        }
    }
}
```

注意：静态 listener 通道的 `config` 指针指向 `channels[]` 中的配置项。动态通道继承 listener 的 `listener_idx`，但 ACL 检查只在 accept 阶段（listener 创建动态通道前）执行，动态通道自身不检查。

### 5.2 配置解析（main.c — config_load）

新增 JSON 解析函数 `parse_acl(json_object *obj, channel_acl_t *acl)`：
- 读取 `"client_acl"` 对象
- 若不存在 → `acl->enabled = 0`
- 若存在 → `acl->enabled = 1`
- 解析 `"ips"` 数组：逐个字符串 → 识别格式（`/` → CIDR，`-` → RANGE，否则 SINGLE）
- 解析 `"ports"` 数组：逐个字符串 → `-` → RANGE，否则 SINGLE
- 超限截断（ip_count > 16 时 `LOG_WARN` + 截断）

### 5.3 热重载（channel_config_changed / channel_update_config）

在 `channel_config_changed` 中新增字段比较：
```c
if (memcmp(&ch->config->client_acl, &cfg->client_acl, sizeof(channel_acl_t)) != 0)
    return 1;
```

`channel_update_config` 新增：
```c
memcpy(&ch->config->client_acl, &cfg->client_acl, sizeof(channel_acl_t));
```

### 5.4 SIGUSR1 通道控制（ctl_parse_channel）

新增可选 JSON 字段 `"client_acl"`，复用 `parse_acl`。

## 6. 内存与性能

| 项目 | 数值 |
|------|------|
| `channel_acl_t` 大小 | 128 字节 |
| `channel_config_t` 增量 | +128 字节（260 字节总计） |
| 65536 通道配置内存 | 17 MB（+8 MB） |
| ACL 匹配耗时（最坏） | 16 IP + 8 port 循环 ≈ 0.5μs |
| 匹配频率 | 每 accept 一次（低频） |

## 7. 改动量

| 文件 | 改动 | 行数 |
|------|------|------|
| `src/types.h` | 新增 `channel_acl_t` 及子结构，嵌入 `channel_config_t` | +30 |
| `src/proxy.c` | `proxy_accept` 中加 `getpeername` + `acl_check` | +25 |
| `src/acl.c`（新） | `acl_check`, `acl_ip_match`, `acl_port_match`, `parse_acl`, `extract_ip_port` | +90 |
| `src/acl.h`（新） | 函数声明 | +12 |
| `src/main.c` | JSON 解析 + ctl 适配 | +20 |
| `src/channel.c` | `config_changed` + `update_config` 适配 | +6 |
| `Makefile` | 新增 `obj/acl.o` | +2 |
| **合计** | | **~185 行** |

## 8. 测试设计

| # | 测试方法 | 覆盖 |
|---|---------|------|
| 1 | 单 IP 匹配 | `acl_check(10.0.0.5) == 1` |
| 2 | 单 IP 不匹配 | `acl_check(10.0.0.6) == 0` |
| 3 | CIDR 匹配 | `10.0.1.55` 在 `10.0.1.0/24` 内 |
| 4 | CIDR 不匹配 | `10.0.2.1` 不在 `10.0.1.0/24` 内 |
| 5 | 范围匹配 | `192.168.0.30` 在 `10~50` 内 |
| 6 | 范围边界 | `10` 和 `50` 均匹配（闭区间） |
| 7 | 范围不匹配 | `9` 和 `51` 均不匹配 |
| 8 | 端口范围匹配 | `8080` 在 `1024-65535` 内 |
| 9 | 端口单值匹配 | `443` 精确匹配 |
| 10 | 端口不匹配 | `80` 不在列表中 |
| 11 | IP + 端口组合 AND | 两条件都满足才通过 |
| 12 | 仅 IP 无端口 | 端口不检查，全部通过 |
| 13 | 仅端口无 IP | IP 不检查，全部通过 |
| 14 | ACL 未启用 | 全部放行 |
| 15 | 多 IP + 多端口 | 并集逻辑，命中任一即通过 |
| 16 | ACL 条目上限截断 | 第 17 条 IP 被截断 |

## 9. 配置示例

### 仅允许办公网段访问 SSH 隧道

```json
{
    "channel_id": 1,
    "listen_port": 55222,
    "remote_port": 22,
    "client_acl": {
        "ips": ["10.0.0.0/8", "172.16.0.0/12"],
        "ports": ["1024-65535"]
    }
}
```

### 允许特定 IP 访问任意端口

```json
{
    "channel_id": 2,
    "listen_port": 3306,
    "remote_port": 3306,
    "client_acl": {
        "ips": ["192.168.1.100", "192.168.1.101"]
    }
}
```

### 无 ACL（向后兼容）

```json
{
    "channel_id": 3,
    "listen_port": 8080,
    "remote_port": 80
}
```
