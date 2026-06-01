# 通道级客户端 IP/端口 ACL 设计

## 1. 概述

每个 listener 通道可配置客户端访问控制列表（ACL），在 `proxy_accept` 时通过 `getpeername` 获取客户端地址并匹配。ACL 不配置则行为不变——允许所有客户端。

**适用范围**：仅 TCP 通道。UDP 通道无 `accept` 阶段，ACL 不适用。仅 Frontend 节点执行 ACL 检查（Backend 不运行 `proxy_accept`）。

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
| `ips` | string[] | IP 规则列表，匹配任一即通过。不配置 = 全部允许（最多 16 条） |
| `ports` | string[] | 端口规则列表，匹配任一即通过。不配置 = 全部允许（最多 8 条） |
| 组合逻辑 | — | `ips` 非空 **且** `ports` 非空 → 两者都需匹配。其一为空则仅检查另一项 |

IP 格式：
- `"10.0.0.5"` — 单个 IP
- `"10.0.1.0/24"` — CIDR 网段
- `"192.168.0.10-192.168.0.50"` — IP 范围（两端均包含）

端口格式：
- `"8080"` — 单个端口
- `"1024-65535"` — 端口范围（两端均包含）

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
    uint32_t mask_or_end;    /* CIDR: 网络字节序掩码; RANGE: 结束 IP */
} acl_ip_entry_t;

/* 端口访问控制条目 */
typedef struct {
    uint8_t  type;           /* acl_port_type_t              */
    uint16_t port_start;     /* 起始端口                      */
    uint16_t port_end;       /* 结束端口（SINGLE 时 = port_start） */
} acl_port_entry_t;

/* 通道级客户端 ACL */
typedef struct {
    uint8_t          enabled;
    uint8_t          ip_count;
    acl_ip_entry_t   ips[MAX_ACL_IPS];
    uint8_t          port_count;
    acl_port_entry_t ports[MAX_ACL_PORTS];
} channel_acl_t;
```

`channel_config_t` 新增字段：
```c
channel_acl_t client_acl;   /* 嵌入，不额外分配 */
```

`sizeof(channel_config_t)` 增量约 136 字节。结构体内存按 `MAX_ACL_IPS` 和 `MAX_ACL_PORTS` 静态预留。

ACL 数据存储在 `channels[]` 配置数组中，通过 `ctx->config.channels[ch->listener_idx].client_acl` 访问。
`channel_t` 不增加 `config` 指针。

### CIDR 掩码转换

解析阶段将前缀长度转为网络字节序掩码：

```c
static uint32_t cidr_prefix_to_mask(int prefix_len)
{
    if (prefix_len <= 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFF;
    return htonl(0xFFFFFFFF << (32 - prefix_len));
}
/* 示例: /24 → htonl(0xFFFFFF00) → 0xFFFFFF00（网络字节序） */
```

## 4. 匹配算法

所有 IP 地址均以**网络字节序**（`sin_addr.s_addr` 原生格式）存储和比较，不使用 `ntohl()`。

### 4.1 IP 匹配

```c
static int acl_ip_match(uint32_t client_ip, /* 网络字节序 */
                         const acl_ip_entry_t *entry)
{
    switch (entry->type) {
    case ACL_IP_SINGLE:
        return (client_ip == entry->addr);

    case ACL_IP_CIDR:
        return ((client_ip & entry->mask_or_end) ==
                (entry->addr & entry->mask_or_end));

    case ACL_IP_RANGE:
        /* 直接比较网络字节序。大端特性保证 IP 顺序等同于 uint32 数值序。 */
        return (client_ip >= entry->addr &&
                client_ip <= entry->mask_or_end);

    default:
        return 0;
    }
}
```

### 4.2 端口匹配

```c
static int acl_port_match(uint16_t client_port,
                           const acl_port_entry_t *entry)
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
int acl_check(const channel_acl_t *acl,
              uint32_t client_ip,    /* 网络字节序 */
              uint16_t client_port)
{
    if (!acl->enabled) return 1;

    if (acl->ip_count > 0) {
        int ok = 0;
        for (int i = 0; i < acl->ip_count; i++)
            if (acl_ip_match(client_ip, &acl->ips[i])) { ok = 1; break; }
        if (!ok) return 0;
    }

    if (acl->port_count > 0) {
        int ok = 0;
        for (int i = 0; i < acl->port_count; i++)
            if (acl_port_match(client_port, &acl->ports[i])) { ok = 1; break; }
        if (!ok) return 0;
    }

    return 1;
}
```

复杂度：O(ip_count + port_count) ≤ O(24)，每次 accept 执行一次。

## 5. 集成点

### 5.1 proxy_accept（proxy.c）

```c
// 现有代码:
client_fd = accept4(ch->listen_fd, NULL, NULL,
                    SOCK_NONBLOCK | SOCK_CLOEXEC);

// 新增:
struct sockaddr_storage peer_addr;
socklen_t peer_len = sizeof(peer_addr);

if (getpeername(client_fd, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
    uint32_t ip;
    uint16_t port;
    if (extract_ip_port(&peer_addr, &ip, &port)) {
        channel_acl_t *acl =
            &ctx->config.channels[ch->listener_idx].client_acl;
        if (!acl_check(acl, ip, port)) {
            LOG_DEBUG("proxy_accept: ACL reject %s:%u ch=%u",
                      ip_to_str(ip), port, ch->channel_id);
            close(client_fd);
            continue;
        }
    }
}
```

**注意**：`proxy_accept` 已有 IPv6 双栈支持（`AF_INET6` + `IPV6_V6ONLY=0`）。`extract_ip_port` 需处理 IPv4-mapped IPv6（`::ffff:a.b.c.d`）。

#### extract_ip_port 实现

```c
static int extract_ip_port(const struct sockaddr_storage *ss,
                            uint32_t *ip_out, uint16_t *port_out)
{
    if (ss->ss_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)ss;
        *ip_out   = in->sin_addr.s_addr;        /* 网络字节序 */
        *port_out = ntohs(in->sin_port);
        return 1;
    }
    if (ss->ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
        /* IPv4-mapped: ::ffff:a.b.c.d → 提取嵌入 IPv4 */
        static const uint8_t v4mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
        if (memcmp(in6->sin6_addr.s6_addr, v4mapped, 12) == 0) {
            memcpy(ip_out, in6->sin6_addr.s6_addr + 12, 4);
        } else {
            /* 纯 IPv6: 不匹配 IPv4 ACL */
            return 0;
        }
        *port_out = ntohs(in6->sin6_port);
        return 1;
    }
    return 0;
}
```

### 5.2 配置解析（main.c — config_load）

新增函数 `parse_acl(json_object *obj, channel_acl_t *acl)`：

```
parse_acl(obj, acl):
  memset(acl, 0, sizeof(*acl))
  client_acl = json_object_object_get(obj, "client_acl")
  if (!client_acl) → return   (enabled 保持 0)
  acl->enabled = 1

  ips_array = json_object_object_get(client_acl, "ips")
  if (ips_array):
    遍历 ips_array → 识别格式:
      '/' 出现 → CIDR: 解析前缀 → cidr_prefix_to_mask → 填充 mask_or_end
      '-' 出现 → RANGE: 解析两端 IP
      其他     → SINGLE
    ip_count++；超 MAX_ACL_IPS 时 LOG_WARN + break

  ports_array = json_object_object_get(client_acl, "ports")
  if (ports_array):
    遍历 ports_array → 识别格式:
      '-' 出现 → RANGE
      其他     → SINGLE (port_end = port_start)
    port_count++；超 MAX_ACL_PORTS 时 LOG_WARN + break
```

### 5.3 热重载

`channel_config_changed()` 当前签名：
```c
int channel_config_changed(const channel_t *ch, const channel_config_t *new_cfg);
```
该函数直接比较 `ch->listen_port` 等字段，不接收 `ctx` 参数。

ACL 变更检测由调用者 `config_reload_channels()` 在执行 `channel_update_config()` 前自行完成：
```c
// 在 config_reload_channels 中新增（其他字段检测后）
channel_acl_t *old_acl =
    &ctx->config.channels[old_ch->listener_idx].client_acl;
if (memcmp(old_acl, &new_ch->client_acl, sizeof(channel_acl_t)) != 0)
    changed = 1;
```

`channel_update_config()` 不负责 ACL（ACL 仅存于配置数组，不需要复制到 channel_t）。

### 5.4 SIGUSR1 通道控制

`ctl_parse_channel()` 新增可选字段 `"client_acl"`，复用 `parse_acl()`。

## 6. 内存与性能

| 项目 | 数值 |
|------|------|
| `channel_acl_t` 大小 | ~136 字节 |
| `channel_config_t` 增量 | ~136 字节 |
| 65536 通道配置内存 | ~17 MB（+9 MB） |
| ACL 匹配耗时（最坏） | ~0.5μs |
| 匹配频率 | 每 accept 一次（低频） |

## 7. 改动量

| 文件 | 改动 | 行数 |
|------|------|------|
| `src/types.h` | 新增 `channel_acl_t` 及子结构，嵌入 `channel_config_t` | +30 |
| `src/acl.c`（新） | `acl_check`, `acl_ip_match`, `acl_port_match`, `parse_acl`, `extract_ip_port` | +110 |
| `src/acl.h`（新） | 函数声明 | +15 |
| `src/proxy.c` | `proxy_accept` 中加 `getpeername` + `acl_check` | +30 |
| `src/main.c` | JSON 解析 + `config_reload_channels` 适配 + ctl 适配 | +25 |
| `Makefile` | 新增 `obj/acl.o` | +2 |
| **合计** | | **~212 行** |

## 8. 测试设计

| # | 测试方法 | 覆盖 |
|---|---------|------|
| 1 | 单 IP 匹配 | `acl_check(10.0.0.5) == 1` |
| 2 | 单 IP 不匹配 | `acl_check(10.0.0.6) == 0` |
| 3 | CIDR 匹配 | `10.0.1.55` 在 `10.0.1.0/24` 内 → 1 |
| 4 | CIDR 不匹配 | `10.0.2.1` 不在 `10.0.1.0/24` 内 → 0 |
| 5 | CIDR 边界值 | `10.0.1.0` 和 `10.0.1.255` 均匹配 |
| 6 | 范围匹配 | `192.168.0.30` 在 `10~50` 内 → 1 |
| 7 | 范围边界 | `10` 和 `50` 均匹配（闭区间） |
| 8 | 范围不匹配 | `9` 和 `51` 均不匹配 |
| 9 | 端口范围匹配 | `8080` 在 `1024-65535` 内 → 1 |
| 10 | 端口单值匹配 | `443` 精确匹配 → 1 |
| 11 | 端口不匹配 | `80` 不在列表中 → 0 |
| 12 | IP + 端口组合 AND | 两条件都满足才通过 |
| 13 | 仅 IP 无端口 | 端口不检查，全放行 |
| 14 | 仅端口无 IP | IP 不检查，全放行 |
| 15 | ACL 未启用 | `enabled=0` → 全放行 |
| 16 | 多 IP + 多端口 | 并集逻辑，任一条命中即通过 |
| 17 | 条目超上限截断 | 第 17 条 IP 触发 `LOG_WARN`，不进入 ACL |
| 18 | CIDR /32 边界 | `10.0.0.5/32` 等价单 IP，仅自身匹配 |
| 19 | IPv4-mapped IPv6 | `::ffff:10.0.0.5` 通过 `10.0.0.5` 的 ACL |
| 20 | 纯 IPv6 客户端 | 对只含 IPv4 规则的 ACL 返回 0 |

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
