# 高并发多会话架构设计

## 现状问题

```
                              ┌─────────────────────┐
client1 ──TCP:55222──▶ listen_fd ──▶ accept
client2 ──TCP:55222──▶ listen_fd ──▶ accept → close ❌
client3 ──TCP:55222──▶ listen_fd ──▶ accept → close ❌
                              └─────────────────────┘
```

一个 channel 只有 1 个 local_fd + 1 个 KCP 实例，第 2+ 个连接直接被丢。

## 目标

```
client1 ──▶ accept ──▶ chan1 (KCP#1) ──▶ AF_PACKET
client2 ──▶ accept ──▶ chan2 (KCP#2) ──▶ AF_PACKET    ← 新的独立通道
client3 ──▶ accept ──▶ chan3 (KCP#3) ──▶ AF_PACKET    ← 新的独立通道
                          ↓
                   listen_fd （仅用于 accept 分发）
```

每个 TCP 连接 → 一个独立 channel + 一个独立 KCP 实例（"One L4 per KCP" 模型）。

## 设计要点

### 1. 角色分层

| 角色 | 现在（单会话） | 改造后（多会话） |
|------|--------------|-----------------|
| **listen_fd** | 属于静态通道，`local_fd` 唯一 | 属于 listener 通道，**仅用于 accept** |
| **静态通道** | 承载连接状态 | 变为 **listener**（不承载数据） |
| **动态通道** | 仅 peer SYN 触发创建（responder） | 也由本地 accept 触发创建（initiator） |
| **channel_id** | 固定 = 配置值 | 动态分配，需要 ID 池管理 |

### 2. 配置语义变化

```json
{
    "channels": [{
        "channel_id": 1,          // 不变，用作 listener 标识
        "listen_port": 55222,     // 监听端口（不变）
        "remote_addr": "192.168.1.67",
        "remote_port": 22,
        "is_tcp": true,
        "max_sessions": 256       // 新增：此端口最大并发数
    }]
}
```

`channel_id` 配置值仅用作 listener 标识。实际数据帧中传输的 `channel_id` 是动态分配的 ID。**配置 `channel_id` 不在数据帧中出现。**

**`max_sessions` 默认值**：
- `max_sessions` 未设置或为 0 → 默认 `1`（向后兼容单会话行为）
- `max_sessions >= 2` → 启用多会话，每个新 accept 创建动态通道
- `max_sessions <= 256`（每个 listener 的数据 ID 池为 256 个，不受 listener ID 占用）

```
现有配置（无 max_sessions）：等价于 max_sessions=1，行为不变
新配置（max_sessions=256）：支持 256 并发 + 1 个 listener
```

### 3. channel_id 管理

引入 **ID 池**，将 channel_id 划分为两个层级：

```c
/* 分配器用 array index（不是 channel_id），RESPONDER 反向映射一致 */
listener array index = 0 → 数据通道 ID 范围 [257, 512]
listener array index = 1 → 数据通道 ID 范围 [513, 768]
listener array index = N → 数据通道 ID 范围 [257+N*256, 512+N*256]
```

**为什么用 array index 而不是 channel_id**：配置中的 `channel_id` 可以是任意值（如 `1`），但 RESPONDER 收到 data ID 后需要通过 `/256` 反向找到对应的 listener。用 **连续、无间隙的 array index**确保映射正确。

管理算法：
```c
/* next_id: ctx->next_dynamic_channel_id（persistent per-ctx） */
uint16_t alloc_channel_id(global_ctx_t *ctx, int listener_idx)
{
    uint16_t base = (uint16_t)(257 + (uint32_t)listener_idx * 256);
    uint16_t max  = (uint16_t)(base + 255);

    if (ctx->next_dynamic_channel_id < base)
        ctx->next_dynamic_channel_id = base;
    if (ctx->next_dynamic_channel_id > max)
        ctx->next_dynamic_channel_id = base;

    for (int attempt = 0; attempt < 256; attempt++) {
        uint16_t id = ctx->next_dynamic_channel_id++;
        if (id > max) ctx->next_dynamic_channel_id = base;
        if (channel_find(ctx, id) == NULL) return id;
    }
    return 0;  /* 耗尽 */
}
```

RESPONDER 反向映射：
```c
/* 数据 ID → listener array index */
uint16_t listener_idx = (hdr->channel_id - 257) / 256;
if (listener_idx < g_ctx->config.channel_count) {
    cfg = &g_ctx->config.channels[listener_idx];
}
```

### 4. accept 流程改造

```c
/* proxy_accept() 改造 */
/* listener_idx: 此 listener 在 config.channels[] 中的 array index */
int proxy_accept(global_ctx_t *ctx, channel_t *listener)
{
    while (1) {
        client_fd = accept4(listener->listen_fd, NULL, NULL,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd < 0) break;  /* EAGAIN */

        uint16_t new_id = alloc_channel_id(ctx, listener->listener_idx);
        if (new_id == 0) {
            close(client_fd);
            LOG_WARN("proxy_accept: channel ID exhausted for listener %u",
                     listener->channel_id);
            continue;
        }

        /* channel_create 内部发送 SYN（INITIATOR 角色自动触发） */
        channel_t *ch = channel_create(ctx, new_id,
                            CHANNEL_ROLE_INITIATOR,
                            listener->listen_port,
                            listener->remote_port,
                            listener->listen_addr,
                            listener->remote_addr,
                            listener->is_tcp);
        if (!ch) {
            close(client_fd);
            continue;
        }

        ch->local_fd = client_fd;
        if (proxy_epoll_add(ctx, client_fd, ch) < 0) {
            /* epoll 注册失败 → 销毁通道，关闭 fd */
            close(client_fd);
            channel_destroy(ctx, ch);
            continue;
        }

        LOG_INFO("proxy_accept: new session chan=%u fd=%d",
                 new_id, client_fd);
    }
    return 0;
}
```

### 5. 数据流

```
                    frontend                           backend
                        │                                │
  client1 ────TCP──────▶│  chan_id=257 ──SYN──▶ AF_PACKET │
                        │                    ┌───────────▶│  chan_id=257
                        │                    │            │  connect──▶ 目标服务
                        │  local_fd=6         │            │
  client2 ────TCP──────▶│  chan_id=258 ──SYN─┘            │  chan_id=258
                        │                                 │  connect──▶ 目标服务
```

- 每个 channel **独立 KCP 实例**，KCP segment 中由 `channel_id` 区分
- frontend 的 `local_fd` → `proxy_handle_local_read` → `channel_send_data` → kcp_output → AF_PACKET
- backend 的 AF_PACKET → `channel_process_frame` → 按 `channel_id` 路由到对应 KCP → `proxy_write_to_local` → `local_fd`

### 6. 响应方通道创建（已有实现，需改造）

backend 收到 SYN 时，需要 `remote_addr:remote_port` 才能 `proxy_connect_remote`。

**当前代码的局限**（channel.c:688）：
```c
cfg = channel_lookup_config(hdr->channel_id);  // 256+ 查不到 → raddr = "0.0.0.0"
```

`channel_lookup_config` 按 `channel_id` 查静态配置。动态 ID（256+）不在配置中，返回 NULL。

**改造方案**：用 `(data_id - 257) / 256` 反向映射到 listener 的 array index：

```c
/* 动态 ID → listener array index（对应 alloc_channel_id 的 listener_idx）*/
uint16_t base_idx = (hdr->channel_id - 257) / 256;
if (base_idx < g_ctx->config.channel_count) {
    cfg = &g_ctx->config.channels[base_idx];
    lport = cfg->listen_port;
    rport = cfg->remote_port;
    laddr = cfg->listen_addr;
    raddr = cfg->remote_addr;
    tcp   = cfg->is_tcp;
}
```

### 7. Listener 通道初始化

新增 `CHANNEL_ROLE_LISTENER`（角色值 = 2），与现有 INITIATOR/RESPONDER 并列。

区别：

| 特性 | INITIATOR | RESPONDER | LISTENER |
|------|-----------|-----------|----------|
| 自动发 SYN | ✅ 创建后立即发（配置 INITIATOR）<br>❌ accept 创建的 INITIATOR（由 proxy_accept 触发） | ❌ | ❌ |
| 绑定 local_fd | ✅ | ❌（由 proxy_connect 分配） | ❌ |
| 绑定 listen_fd | ❌ | ✅（backend 模式） | ✅ |
| 自动销毁 | ❌（正常 FIN 后） | ❌（正常 FIN 后） | ❌（永不，仅 shutdown） |
| 创建者 | accept | backend SYN handler | main.c 静态初始化 |

启动流程（main.c）：
```c
for each cfg in config.channels:
    ch = channel_create(ctx, cfg.channel_id, CHANNEL_ROLE_LISTENER, ...)
    if (ch) {
        ch->flags |= CH_FLAG_STATIC_LISTENER;
        ch->listener_idx = i;  /* 存储 array index 用于 alloc_channel_id */
        proxy_start_listen(ctx, ch);  /* 创建 listen_fd，开始监听 */
    }
```

`CHANNEL_ROLE_LISTENER` 不发送 SYN，不绑定 `local_fd`。`listen_fd` 由 `proxy_start_listen` 设置。所有 accept 来的连接走 Section 4 的动态 INITIATOR 通道。

### 8. 资源上限

| 资源 | 单会话 | 多会话 | 限制因素 |
|------|--------|--------|---------|
| 最大通道数 | 256 | 每个 listener 256 | KCP 内存 + hash 表 |
| 最大并发连接 | 1 | 每个 listener 最大 255 | `max_sessions` 配置项 |
| 每个通道内存 | ~2KB | ~2KB | KCP 控制块 + 缓冲区 |
| 每个 KCP 内存 | ~8KB | ~8KB | KCP segment 池 + recv/send 窗口 |
| **256 并发约需** | — | ~2.5MB | 可接受 |
| **4096 并发约需** | — | ~40MB | 可接受（需多个 listener） |

### 9. 清理与生命周期

| 事件 | 动作 | 通道类型 |
|------|------|---------|
| 客户端 TCP 断开 | `proxy_handle_local_read` 读回 0 → `proxy_close_local(ch)` → 发 FIN → 等待 FIN_ACK → `channel_destroy` | 数据通道 |
| 对端 TCP 断开 | 收到 FIN → `proxy_close_local(ch)` → 回 FIN → TIME_WAIT → `channel_destroy` | 数据通道 |
| 心跳超时 | `channel_timeout_check` → `channel_destroy` | 数据通道 |
| SYN 重试超限 | `channel_timeout_check` → `channel_destroy` | 数据通道 |
| 通道 ID 耗尽 | accept 返回错误，日志告警 | — |
| **listen_fd 错误** | `LOG_ERROR` + `close(listen_fd)` → 重新 `socket/bind/listen` → 恢复监听 | listener 通道 |

**关键区别：listener 通道不会被 `channel_destroy` 销毁。** 其 `listen_fd` 仅由自身错误处理逻辑关闭和重建。`channel_destroy()` 添加 `!(ch->flags & CH_FLAG_STATIC_LISTENER)` 防护。`channel_timeout_check()` 同样跳过 listener 通道（检查 `CH_FLAG_STATIC_LISTENER` 标志），防止意外误杀。

### 10. UDP 设计

UDP（`is_tcp: false`）的 `listen_fd == local_fd`（共用同一个套接字），未做客户端级区分。

**本设计不支持 UDP 多会话。** UDP 场景保持单通道语义。

若未来需要 UDP 多人连接，可引入"UDP source mapping"机制：

```c
/* 多会话 UDP 扩展（未实现，预留设计） */
if (!ch->is_tcp) {
    /* recvfrom 获取客户端地址 */
    struct sockaddr_storage peer_addr;
    socklen_t addr_len = sizeof(peer_addr);
    n = recvfrom(ch->local_fd, buf, ..., &peer_addr, &addr_len);
    /* 用 src_addr hash 查找或创建动态通道 */
}
```

### 11. 兼容性性

- **无需改动 AF_PACKET 帧格式**（`channel_id` 字段已在 MyProto 协议中，16bit）
- **无需改动 KCP 集成**（读写接口不变，只有 channel 数量变化）
- **配置向后兼容**（旧配置只有一个 channel，外加 256 并发上限，行为与现在一致）
- **两端需同步升级**（动态通道 ID 在 257+ 范围，旧后端无法通过 channel_lookup_config 找到目标地址）

### 12. 需修复的代码缺陷（更新）

以下 5 个问题需在实现时同步修复（R3→N1，R6→N6）：

**R3: `channel_destroy` 误关 listener 的 `listen_fd`** (channel.c:584)

```diff
-    if (ch->listen_fd >= 0) {
+    if (ch->listen_fd >= 0 && !(ch->flags & CH_FLAG_STATIC_LISTENER)) {
         close(ch->listen_fd);
```

**R6: static listener EPOLLERR 不应 CLOSED** (proxy.c:1088-1089)

```diff
-    ch->state = CHANNEL_CLOSED;
+    /* 重建监听套接字 */
+    if (ch->listen_fd >= 0) {
+        proxy_epoll_del(ctx, ch->listen_fd);
+        close(ch->listen_fd);
+    }
+    proxy_start_listen(ctx, ch);
```

**N1: RESPONDER 通道无目标地址** (channel.c:688)

```diff
-    cfg = channel_lookup_config(hdr->channel_id);
+    /* 动态 ID: 用 (data_id - 257) / 256 映射到 listener 的 array index */
+    uint16_t base_idx = (hdr->channel_id - 257) / 256;
+    if (base_idx < g_ctx->config.channel_count)
+        cfg = &g_ctx->config.channels[base_idx];
```

**N3: accept 失败路径泄漏** (proxy.c take-``diff
+    if (proxy_epoll_add(ctx, client_fd, ch) < 0) {
+        close(client_fd);
+        channel_destroy(ctx, ch);
+        continue;
+    }
```

**N6: ACK 在 connect 之前发送** (channel.c:751→before connect)

```diff
-    channel_send_ctrl(ch, MPF_ACK);  // 移到 proxy_connect_remote 之后
+    /* ACK sent after proxy_connect_remote succeeds */
```

### 13. 工作分解（终版）

| # | 步骤 | 文件 | 改动 | 风险 | 依赖 |
|---|------|------|------|------|------|
| 1 | `CH_FLAG_STATIC_LISTENER` + `listener_idx` 字段 + destroy 防护 | `types.h` / `channel.c` | 8 行 | 低 | — |
| 2 | 新增 `CHANNEL_ROLE_LISTENER`（不发 SYN） | `types.h` / `channel.c` | 5 行 | 低 | — |
| 3 | listen_fd 错误恢复（epoll_del + 重建） | `proxy.c` | 8 行 | 低 | #1 |
| 4 | `alloc_channel_id` ID 池（array index 分区） | `channel.c` | 35 行 | **中** | — |
| 5 | SYN handler：RESPONDER 目标地址继承（array index 反向映射） | `channel.c` | 5 行 | **中** | #4 |
| 6 | `proxy_accept` 多会话 + 泄漏修复 | `proxy.c` | 30 行 | 中 | #4, #5 |
| 7 | listener 通道 init（`CH_FLAG_STATIC_LISTENER` + `CHANNEL_ROLE_LISTENER`） | `main.c` | 5 行 | 低 | #1, #2 |
| 8 | ACK 移到 connect 成功后 | `channel.c` | 5 行 | 低 | #5 |
| 9 | UDP 跳过 accept 多会话 | `proxy.c` | 3 行 | 低 | #6 |
| 10 | `next_dynamic_channel_id` 字段 + 初始化 | `types.h` / `main.c` | 3 行 | 低 | #4 |
| 11 | 测试：256 并发 TCP | `tests/` | 60 行 | 低 | #1-#10 |
| 12 | listener 在 shutdown 中统一清理 | `channel.c` | 3 行 | 低 | #2 |

---

# Part II: 动态通道配置热重载

## 1. 背景与目标

当前 `config_reload()`（SIGHUP）仅支持软参数，通道 `channels[]` 增删改必须重启。

**目标**：reload 后新增/修改/删除 listener，已有动态通道不受影响。

## 2. 数据结构

- 无需新增结构体字段
- 新增宏 `CH_FLAG_RELOAD_MARKED 0x02`（临时标记位）

## 3. 新增函数

| 函数 | 位置 | 用途 |
|------|------|------|
| `proxy_stop_listen()` | proxy.c | 关闭 listen_fd + epoll_del，不销毁子通道 |
| `proxy_port_probe()` | proxy.c | bind 预检端口可用性 |
| `proxy_port_conflict()` | proxy.c | 检测端口与已有 listener 冲突 |
| `channel_config_changed()` | channel.c | 比较新旧配置差异 |
| `channel_update_config()` | channel.c | 写入新配置（不碰 KCP/运行时状态），**含 source_port_min/max** |
| `config_reload_channels()` | main.c | 核心：diff 旧/新 channels[]，增删改 |

## 4. config_reload_channels() 流程

### Step 1: 标记
遍历哈希表 → 所有 `CH_FLAG_STATIC_LISTENER` 通道打上 `RELOAD_MARKED`

### Step 2: Diff + 增/改
遍历新配置 `new_cfg->channels[]`：
- **匹配 + 禁用** (`enabled=false`)：清除 `STATIC_LISTENER` → `channel_destroy`
- **匹配 + 变更**：端口预检 → `proxy_stop_listen` → `channel_update_config` → `proxy_start_listen`。**注意**：`remote_addr`/`remote_port` 变更仅对新 RESPONDER 生效，存量动态通道保留创建时的地址
- **匹配 + 无变更**：仅更新 `listener_idx`（**仅作用于 STATIC_LISTENER 通道，不碰动态数据通道**）
- **不匹配 + 启用**：新建 `CHANNEL_ROLE_LISTENER` → `proxy_start_listen`（端口冲突检测）。**创建前**端口冲突检测，**创建失败**直接 `channel_destroy` 清理。`proxy_start_listen` 失败后同样 `channel_destroy`，不留"无 listener 空壳"

### Step 3: 清理
仍带 `RELOAD_MARKED` 的 listener → 删除。`channel_destroy` 销毁。

### Step 4: 刷新 channels[]
不物理删除 disabled 条目（保护 `listener_idx` 映射和 source_port 归还路径）。
被删除条目保留在数组中、标记 `enabled=false`。
**`channel_update_config()` 需同步更新 `source_port_min/max` 字段**，确保 reload 后 source_port 池信息与配置一致。

**索引稳定性说明**：动态数据通道通过 `(id-257)/256` 反向映射到 `channels[]` 索引。
保留 disabled 条目可确保已有动态通道的 source_port 归还路径不因数组收缩而错位。

## 5. 操作影响矩阵

| 操作 | 存量动态通道 | 旧 listener | 新 listener |
|------|------------|-------------|-------------|
| 新增通道 | 不受影响 | — | 创建监听 |
| 修改通道 | 不受影响 | 关闭重建 | 预检后创建 |
| 删除/禁用 | 继续至自然结束 | 销毁 | — |

## 6. 改动量

| 文件 | 行数 |
|------|------|
| `types.h` | +2 |
| `channel.h` / `channel.c` | +52 |
| `proxy.h` / `proxy.c` | +98 |
| `main.c` | +150 |
| **合计** | **~302** |

零新文件，零删除现有代码。

---

# Part III: uint16_t → uint32_t channel_id 升级

## 1. 动机

| 参数 | 当前 | 目标 |
|------|------|------|
| 最大静态 listener | 254 | 50000+ |
| 每 listener 并发 | 256 (固定) | 可配（`max_sessions`） |
| channel_id 类型 | `uint16_t` | `uint32_t` |

## 2. 帧格式变更

```
旧 (8 bytes):                          新 (10 bytes):
┌────────┬─────┬─────┬────────┬──────┐  ┌───────────────┬─────┬────────┬──────┐
│ chan_id│flags│rsvd │pay_len │ crc  │  │   chan_id     │flags│pay_len │ crc  │
│ uint16 │ u8  │ u8  │ uint16 │ u16  │  │   uint32      │ u8  │ uint16 │ u16  │
└────────┴─────┴─────┴────────┴──────┘  └───────────────┴─────┴────────┴──────┘
   0   1   2   3   4   5   6   7             0   1   2   3   4   5   6   7   8   9
```

`reserved` 字段消灭——合并到 `channel_id` 高 16 位。

## 3. 数据结构变更

### types.h

```c
// types.h: 全局替换 uint16_t channel_id → uint32_t channel_id
typedef uint32_t channel_id_t;  // 新增类型别名

typedef struct {
    channel_id_t channel_id;     // 原 uint16_t
    uint16_t     listen_port;
    ...
} channel_config_t;

typedef struct channel_s {
    channel_id_t   channel_id;   // 原 uint16_t
    ...
} channel_t;
```

`HEARTBEAT_CH_ID`: `0xFFFF` → `0xFFFFFFFF`

### myproto.h

```c
typedef struct __attribute__((packed)) {
    uint32_t channel_id;   // 原 uint16_t
    uint8_t  flags;
    uint16_t payload_len;
    uint16_t header_crc;
} myproto_hdr_t;

_Static_assert(sizeof(myproto_hdr_t) == 10, "must be 10 bytes");
```

### channel.h / channel.c

```c
// alloc_channel_id 重写：去掉 256 硬上限，改为 max_sessions 决定池宽
uint32_t alloc_channel_id(global_ctx_t *ctx, int listener_idx);

// channel_find / channel_hash_insert: hash 函数适配 uint32_t
static uint32_t channel_hash(uint32_t id, uint32_t size) {
    return id % size;
}
```

## 4. ID 池重设计

```
旧：每个 listener 固定 256 槽位
  listener 0: [257,  512]
  listener 1: [513,  768]
  ...

新：每个 listener 可配 max_sessions 个槽位
  listener 0 (max_sessions=10):    [65536, 65545]
  listener 1 (max_sessions=5000):  [65546, 70545]
  listener 2 (max_sessions=1):     [70546, 70546]
  ...

基址起始: DYNAMIC_CHANNEL_BASE = 65536
累积偏移: ctx->listener_base[i] (启动时预计算)
```

```c
void build_listener_bases(global_ctx_t *ctx) {
    uint32_t offset = DYNAMIC_CHANNEL_BASE;
    for (int i = 0; i < ctx->config.channel_count; i++) {
        ctx->listener_base[i] = offset;
        ctx->listener_next[i] = offset;
        offset += ctx->config.channels[i].max_sessions;
    }
}

uint32_t alloc_channel_id(global_ctx_t *ctx, int listener_idx) {
    uint32_t base = ctx->listener_base[listener_idx];
    uint32_t max  = base + ctx->config.channels[listener_idx].max_sessions - 1;
    // round-robin within bounds
    for (int attempt = 0; attempt < ctx->config.channels[listener_idx].max_sessions; attempt++) {
        uint32_t id = ctx->listener_next[listener_idx]++;
        if (id > max) ctx->listener_next[listener_idx] = base;
        if (channel_find(ctx, id) == NULL) return id;
    }
    return 0;
}
```

RESPONDER 反向映射：
```c
int find_listener_by_id(uint32_t data_id) {
    if (data_id < DYNAMIC_CHANNEL_BASE) return -1;
    for (int i = channel_count - 1; i >= 0; i--) {
        if (data_id >= listener_base[i]) return i;
    }
    return -1;
}
```

## 5. 改动清单

| 文件 | 改动 | 行数 |
|------|------|------|
| `myproto.h` | 帧头 8→10 字节，`channel_id` `uint32_t` | ±5 |
| `types.h` | 全局 `uint16_t`→`uint32_t`，新增 `listener_base[MAX_CHANNELS]`、`listener_next[MAX_CHANNELS]` | ±15 |
| `channel.h` | 函数声明适配 | ±5 |
| `channel.c` | alloc 重写，`channel_lookup_config` 适配，hash 函数适配 | ±40 |
| `proxy.c` | `proxy_accept` 适配 `uint32_t` | ±5 |
| `main.c` | 启动时调 `build_listener_bases()` | ±5 |
| `tests/` | 4 个测试文件适配 | ±30 |
| **合计** | | **~105** |

## 6. 迁移步骤

```bash
# 1. 停止两端服务
systemctl stop kcp-afpacket  # frontend + backend

# 2. 替换二进制
cp kcp-afpacket-v3 /usr/local/bin/kcp-afpacket

# 3. 更新配置（无变更）
# config.json 不变，channel_id 仍是 int，JSON 自动转 uint32_t

# 4. 启动
systemctl start kcp-afpacket  # 先 backend，再 frontend
```

零数据库迁移，零配置变更，仅替换二进制。

## 7. 兼容性声明

| 方向 | 结果 |
|------|------|
| 新→新 | ✅ |
| 新→旧 | ❌ 帧 CRC 失败，静默丢弃 |
| 旧→新 | ❌ 8 字节帧 → 读 10 字节越界 |
| 混合运行 | ❌ 不可混跑，必须统一停机升级 |

## 8. 常量上限调整

| 常量 | 旧值 | 新值 | 原因 |
|------|------|------|------|
| `MAX_CHANNELS` | 4096 | 65536 | 50000 listener + 冗余 |
| `max_channels` 默认 | 4096 | 65536 | 与 MAX_CHANNELS 一致 |
| `channel_hash_size` | 2×max_channels | 2×max_channels | 不变 |
