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
| **listen_fd** | 属于 static_channel，`local_fd` 唯一 | 属于 static_channel，**仅用于 accept** |
| **static_channel** | 承载连接状态 | 变为 **listener**（不承载数据） |
| **dynamic_channel** | 仅 peer SYN 触发创建（responder） | 也由本地 accept 触发创建（initiator） |
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

不再将 channel_id 用于实际数据通道。它作为 listen_fd 的标识。实际数据通道的 channel_id 动态分配。

### 3. channel_id 管理

引入 **ID 池**，将 channel_id 划分为两个层级：

```
    0 ──────────────────────────── 65535
    │ listener 0│ listener 1│ ...   │
    │ (0-255)   │ (256-511) │       │
    └───────────┴───────────┴───────┘
```

**每个 listener 独占 256 个 ID**：
- listener channel_id = 0  → 数据通道 ID 范围 256-511
- listener channel_id = 1  → 数据通道 ID 范围 512-767
- 类推

**RESPONDER 通道通过 `channel_id / 256` 找到对应的 listener**，从中取 `remote_addr:remote_port` 进行 `proxy_connect_remote`。

管理算法：
```c
/* 按 listener 分配 ID。listener_idx = listener->channel_id */
uint16_t alloc_channel_id(global_ctx_t *ctx, uint16_t base_channel_id)
{
    uint16_t base = (uint16_t)(base_channel_id * 256) + 1;
    uint16_t max  = base + 255;
    if (base < 256) base = 256;

    for (int attempt = 0; attempt < 256; attempt++) {
        if (next_data_channel_id < base) next_data_channel_id = base;
        if (next_data_channel_id > max)  next_data_channel_id = base;
        uint16_t id = next_data_channel_id++;
        if (channel_find(ctx, id) == NULL) return id;
    }
    return 0;  /* 耗尽 */
}
```

- `base_channel_id`：listener 的 channel_id（0-255）

### 4. accept 流程改造

```c
/* proxy_accept() 改造 */
int proxy_accept(global_ctx_t *ctx, channel_t *listener)
{
    while (1) {
        client_fd = accept4(listener->listen_fd, NULL, NULL,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd < 0) break;  /* EAGAIN */

        uint16_t new_id = alloc_channel_id(ctx, listener->channel_id);
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
  client1 ────TCP──────▶│  local_fd=5                     │
                        │  chan_id=256 ──SYN──▶ AF_PACKET │
                        │                    ┌───────────▶│  chan_id=256
                        │                    │            │  connect──▶ 目标服务
                        │  local_fd=6         │            │
  client2 ────TCP──────▶│  chan_id=257 ──SYN─┘            │  chan_id=257
                        │                                 │  connect──▶ 目标服务
```

- 每个 channel **独立 KCP 实例**，KCP segment 中由 `channel_id` 区分
- frontend 的 `local_fd` → `proxy_handle_local_read` → `channel_send_data` → kcp_output → AF_PACKET
- backend 的 AF_PACKET → `channel_process_frame` → 按 `channel_id` 路由到对应 KCP → `proxy_write_to_local` → `local_fd`

### 6. 响应方通道创建（已有实现，需改造）

backend 收到 SYN 时，需要 `remote_addr:remote_port` 才能 `proxy_connect_remote`。

**当前代码的局限**（channel.c:688）：
```c
cfg = channel_lookup_config(hdr->channel_id);  // 255+ 查不到 → raddr = "0.0.0.0"
```

`channel_lookup_config` 按 `channel_id` 查静态配置。动态 ID（256+）不在配置中，返回 NULL，导致 `raddr = "0.0.0.0"`、`rport = 0`。

**修复方案**：引入 `channel_id → listener_id` 的映射。

```
config.channels[0].channel_id = 1    (listener, remote_addr = "192.168.1.67", remote_port = 22)
config.channels[0].base_channel_id = 1

动态 channel_id = 256 → 提取 base = channel_id & 0xFF00  → 找到 listener
```

更简洁的方案：**SYN 帧的 data_len 携带 channel_id 和 remote 映射**。但改动协议不兼容。

**最终方案**：每个 listener 绑定一个 `target_base`（在 channel_config_t 额外存储），RESPONDER 创建时用 `hdr->channel_id >> 8` 找到对应的 listener：

```c
/* SYN arrive at channel_id=256 → base=256/256=1 → listener #1 */
uint16_t base = hdr->channel_id / 256;  // 0-255 区间
cfg = &g_ctx->config.channels[base];    // 直接用 base 索引
raddr = cfg->remote_addr;
rport = cfg->remote_port;
```

同时收紧 `alloc_channel_id` 为每个 listener 隔离区间：
| listener base | 动态 ID 范围 |
|---------------|-------------|
| 0 | 256–511 |
| 1 | 512–767 |
| ... | ... |

### 7. 资源上限

| 资源 | 单会话 | 多会话 | 限制因素 |
|------|--------|--------|---------|
| 最大通道数 | 256 | 每个 listener 256 | KCP 内存 + hash 表 |
| 最大并发连接 | 1 | 每个 listener 最大 255 | `max_sessions` 配置项 |
| 每个通道内存 | ~2KB | ~2KB | KCP 控制块 + 缓冲区 |
| 每个 KCP 内存 | ~8KB | ~8KB | KCP segment 池 + recv/send 窗口 |
| **256 并发约需** | — | ~2.5MB | 可接受 |
| **4096 并发约需** | — | ~40MB | 可接受（需多个 listener） |

### 8. 清理与生命周期

| 事件 | 动作 | 通道类型 |
|------|------|---------|
| 客户端 TCP 断开 | `proxy_handle_local_read` 读回 0 → `proxy_close_local(ch)` → 发 FIN → 等待 FIN_ACK → `channel_destroy` | 数据通道 |
| 对端 TCP 断开 | 收到 FIN → `proxy_close_local(ch)` → 回 FIN → TIME_WAIT → `channel_destroy` | 数据通道 |
| 心跳超时 | `channel_timeout_check` → `channel_destroy` | 数据通道 |
| SYN 重试超限 | `channel_timeout_check` → `channel_destroy` | 数据通道 |
| 通道 ID 耗尽 | accept 返回错误，日志告警 | — |
| **listen_fd 错误** | `LOG_ERROR` + `close(listen_fd)` → 重新 `socket/bind/listen` → 恢复监听 | listener 通道 |

**关键区别：listener 通道不会被 `channel_destroy` 销毁。** 其 `listen_fd` 仅由自身错误处理逻辑关闭和重建。`channel_destroy()` 添加 listener/dynamic 区分。

### 9. UDP 设计

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

### 10. 兼容性

- **无需改动 AF_PACKET 帧格式**（`channel_id` 字段已在 MyProto 协议中，16bit）
- **无需改动 KCP 集成**（读写接口不变，只有 channel 数量变化）
- **配置向后兼容**（旧配置只有一个 channel，外加 256 并发上限，行为与现在一致）
- **对端无需升级**（dynamic_initiator 发出的 SYN 对 responder 来说就是正常 SYN）

### 11. 需修复的代码缺陷（更新）

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
+    /* 动态 ID: 用 channel_id/256 映射到 listener，从 listener 取目标地址 */
+    uint16_t base_idx = hdr->channel_id / 256;
+    cfg = (base_idx < g_ctx->config.channel_count)
+          ? &g_ctx->config.channels[base_idx] : NULL;
```

**N3: accept 失败路径泄漏** (proxy.c take-accept)

```diff
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

### 12. 工作分解（终版）

| # | 步骤 | 文件 | 改动 | 风险 | 依赖 |
|---|------|------|------|------|------|
| 1 | `CH_FLAG_STATIC_LISTENER` + destroy 防护 | `types.h` / `channel.c` | 5 行 | 低 | — |
| 2 | listen_fd 错误恢复（epoll_del + 重建） | `proxy.c` | 8 行 | 低 | #1 |
| 3 | `alloc_channel_id` ID 池（按 listener 分区） | `channel.c` | 35 行 | 低 | — |
| 4 | SYN handler：RESPONDER 目标地址继承 | `channel.c` | 5 行 | 低 | #3 |
| 5 | `proxy_accept` 多会话 + 泄漏修复 | `proxy.c` | 30 行 | 中 | #3, #4 |
| 6 | listener 通道 init 设标志位 | `main.c` | 3 行 | 低 | #1 |
| 7 | ACK 移到 connect 成功后 | `channel.c` | 5 行 | 低 | #4 |
| 8 | UDP 跳过 accept 多会话 | `proxy.c` | 3 行 | 低 | #5 |
| 9 | 测试：256 并发 TCP | `tests/` | 60 行 | 低 | #1-#8 |
| 10 | listener 在 shutdown 中统一清理 | `channel.c` | 3 行 | 低 | #1 |
