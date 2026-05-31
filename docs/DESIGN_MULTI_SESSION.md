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

引入 **ID 池**，将 channel_id 划分为两个区间：

```
    0 ────────── 65535
    │ listener │  data channels       │
    │ (0-255)  │  (256-65535)         │
    └──────────┴──────────────────────┘
```

- **0-255**：静态 listener 通道（配置定义，固定 ID）
- **256-65535**：动态数据通道（accept 或 SYN 触发，循环使用）

管理算法：
```c
static uint16_t next_data_channel_id = 256;

uint16_t alloc_channel_id(global_ctx_t *ctx) {
    for (int attempt = 0; attempt < MAX_CHANNEL_ID; attempt++) {
        uint16_t id = next_data_channel_id++;
        if (id < 256) id = 256;              /* 跳过 listener 区间 */
        if (id >= MAX_CHANNEL_ID) id = 256;   /* 回绕 */
        if (channel_find(ctx, id) == NULL) {
            return id;  /* 找到空闲 ID */
        }
    }
    return 0;  /* 耗尽 */
}
```

### 4. accept 流程改造

```c
/* proxy_accept() 改造 */
int proxy_accept(global_ctx_t *ctx, channel_t *listener)
{
    while (1) {
        client_fd = accept4(listener->listen_fd, ...);
        if (client_fd < 0) break;  /* EAGAIN */

        uint16_t new_id = alloc_channel_id(ctx);
        if (new_id == 0) {
            close(client_fd);
            LOG_WARN("proxy_accept: channel ID exhausted");
            continue;
        }

        /* 创建动态 initiator 通道 */
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

        /* 绑定客户端 fd 并触发 SYN */
        ch->local_fd = client_fd;
        proxy_epoll_add(ctx, client_fd, ch);
        channel_send_ctrl(ch, MPF_SYN);
        ch->state = CHANNEL_SYN_SENT;

        LOG_INFO("proxy_accept: new session chan=%u fd=%d from %s:%u",
                 new_id, client_fd, client_ip, client_port);
    }
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

### 6. 响应方通道创建（已有实现，无需大改）

backend 收到 SYN 时，`channel_process_frame` 的 SYN handler 已经支持动态创建 RESPONDER 通道：
```c
if (!ch) {
    ch = channel_alloc(ctx, hdr->channel_id);
    ch->role = CHANNEL_ROLE_RESPONDER;
    ...
    proxy_connect_remote(ch);
    channel_send_ctrl(ch, MPF_ACK);
}
```
基本上可用。需要增加跨 listener 区间（>255）的 ID 检查。

### 7. 资源上限

| 资源 | 单会话 | 多会话 | 限制因素 |
|------|--------|--------|---------|
| 最大通道数 | 256 | 256-65535 | 配置 `max_channels` |
| 最大并发连接 | 1 | max_channels - 1 | KCP 内存 + hash 表 |
| 每个通道内存 | ~2KB | ~2KB | KCP 控制块 + 缓冲区 |
| 每个 KCP 内存 | ~8KB | ~8KB | KCP segment 池 + recv/send 窗口 |
| **256 并发约需** | — | ~2.5MB | 可接受 |
| **4096 并发约需** | — | ~40MB | 可接受 |

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

### 11. 需修复的代码缺陷

以下三个问题需在实现时同步修复，否则会导致服务停摆：

**R3: `channel_destroy` 会误关 static listener 的 `listen_fd`** (channel.c:584)

```diff
-    if (ch->listen_fd >= 0) {
+    if (ch->listen_fd >= 0 && !(ch->flags & CH_FLAG_STATIC_LISTENER)) {
         close(ch->listen_fd);
```

新增 `CH_FLAG_STATIC_LISTENER` 标志位，listener 通道设置此标志，`channel_destroy` 据此跳过 listen_fd 关闭。

**R6: static listener EPOLLERR 不应 CHANNEL_CLOSED** (proxy.c:1088-1089)

```diff
-    ch->state = CHANNEL_CLOSED;
+    close(ch->listen_fd);
+    proxy_start_listen(ctx, ch);  /* 重建监听套接字 */
```

listener 的 listen_fd 错误后，关闭旧 fd，重新 socket/bind/listen，恢复服务。

**R5: UDP 多会话不支持** → 设计层面明确不实现，UDP 保持单通道语义。配置中 `is_tcp: false` 的通道不进入多会话流程。

### 12. 工作分解（更新）

| 步骤 | 文件 | 改动量 | 风险 |
|------|------|--------|------|
| 1. 新增 `CH_FLAG_STATIC_LISTENER` 标志 + `channel_destroy` 防护 | `types.h` / `channel.c` | ~5 行 | 低 |
| 2. listen_fd 错误恢复机制 | `proxy.c` | ~8 行 | 低 |
| 3. 引入 ID 池分配函数 | `channel.c` | ~30 行 | 低 |
| 4. `proxy_accept()` 改为创建新通道 | `proxy.c` | ~25 行 | 中 |
| 5. listener 通道 init 时设置 `CH_FLAG_STATIC_LISTENER` | `main.c` | ~3 行 | 低 |
| 6. UDP 通道跳过 accept 多会话逻辑 | `proxy.c` | ~3 行 | 低 |
| 7. 动态 CLOSED 通道自动销毁 | `channel.c`（已有） | 0 行 | 已验证 |
| 8. 测试：256 并发 TCP 连接 | `tests/` | ~60 行 | 低 |
| 9. 通道 ID 回绕安全 | `channel.c` | ~5 行 | 低 |
| 10. listener 通道在 `channel_shutdown` 中统一清理 | `channel.c` | ~3 行 | 低 |
