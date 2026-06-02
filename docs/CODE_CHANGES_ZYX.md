# 代码变动记录

## 2026-06-02 修复 SSH 退出后动态通道占用

Commit: `0e6dd92`

### 背景

测试拓扑中，服务器 A 通过服务器 B 的 `:55222` 登录到后端服务器 D。首次 SSH 登录正常，但退出后出现以下问题：

- 服务器 C 报 `kcp_wrap_recv: ikcp_recv error -2`
- 服务器 B 报 `proxy_handle_local_read: read(...) failed: Connection reset by peer`
- 服务器 A 再次登录失败，服务器 B 报 `proxy_accept: channel ID exhausted`

### 根因

1. `channel_process_frame()` 使用 `CHANNEL_RECV_BUF_SIZE`（8 KiB）作为 KCP 应用层接收缓冲，而 `proxy_handle_local_read()` 单次可向 KCP 写入 64 KiB。KCP 重组出大于 8 KiB 的完整应用消息时，`ikcp_recv()` 返回 `-2`。
2. 本地 TCP 连接 `ECONNRESET` 被当作硬错误返回，上层只关闭 fd，没有发送关闭控制帧，也没有立即销毁动态通道。`max_sessions=1` 时，第一次会话的动态 ID `65536` 仍在哈希表中，第二次登录无法分配新 ID。

### 变更

- 新增 `KCP_APP_RECV_BUF_SIZE`（64 KiB），用于 KCP 应用层完整消息接收。
- `channel_process_frame()` 改用 `KCP_APP_RECV_BUF_SIZE` 读取 KCP 重组数据，避免 SSH 大块数据触发 `ikcp_recv -2`。
- `proxy_handle_local_read()` 将 `ECONNRESET` 视为本地连接已关闭：记录 `INFO`、关闭本地 fd、发送 `RST`、销毁动态通道。
- `proxy_handle_event()` 识别本地读路径已释放动态通道的返回码，立即返回，避免继续访问已释放的 `channel_t`。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-02 允许握手期通道发送数据

Commit: `f9a1d9b`

### 背景

服务器 A 再次 SSH 登录时失败，服务器 B 和服务器 C 分别出现：

- B：`channel_send_data: channel 65536 not ESTABLISHED (state=1)`
- C：`channel_send_data: channel 65536 not ESTABLISHED (state=2)`

其中 `state=1` 为 `CHANNEL_SYN_SENT`，`state=2` 为 `CHANNEL_SYN_RCVD`。

### 根因

SSH 客户端和 SSH 服务端都可能在隧道控制面握手刚开始时发送首批数据。原 `channel_send_data()` 只允许 `CHANNEL_ESTABLISHED` 状态发送数据，导致握手期的客户端 banner 或服务端 banner 被拒绝，进而触发本地读失败路径。

### 变更

- `channel_send_data()` 允许 `CHANNEL_SYN_SENT`、`CHANNEL_SYN_RCVD`、`CHANNEL_ESTABLISHED` 三种状态发送数据。
- 保留关闭态、异常态的数据发送保护，避免已关闭通道继续写入 KCP。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-02 将未完整 KCP 分片按暂无数据处理

Commit: `a9080c5`

### 背景

服务器 A 已能成功 SSH 登录，但服务器 C 仍出现：

- `kcp_wrap_recv: ikcp_recv error -2`
- `channel_process_frame: kcp_wrap_recv error for channel 65536`

### 根因

`ikcp_recv()` 返回 `-2` 的路径对应 `ikcp_peeksize()` 判断队首 KCP 分片链尚未收齐。这是 KCP 正常收包过程中的“暂无完整应用消息”状态，不是协议错误。原封装把 `-2` 记录为错误并向上传播，导致 `channel_process_frame()` 报错。

### 变更

- `kcp_wrap_recv()` 将 `ikcp_recv()` 的 `-1` 和 `-2` 都按 EAGAIN 语义处理，返回 0。
- 保留 `-3` 等真实错误的错误日志和失败返回。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-02 提高 SSH 样例并发会话数

Commit: `0ad3749`

### 背景

服务器 A 保持一个 SSH 登录不断开时，再打开第二个 SSH 登录失败，服务器 B 出现：

- `proxy_accept: channel ID exhausted for listener 1`

### 根因

`max_sessions` 决定每个 listener 的动态通道 ID 池大小。B/C 样例配置没有显式配置 `max_sessions`，默认值为 1，因此同一 `:55222` listener 只允许 1 个并发 SSH 会话。第一个会话未断开时，第二个 accept 无可用动态 ID。

### 变更

- `sample/config-node-b.json` 为 SSH listener 增加 `"max_sessions": 256`。
- `sample/config-node-c.json` 为对应 listener 增加 `"max_sessions": 256`。
- 两端必须保持一致，否则 backend 无法按动态 ID 区间反查到正确 listener 配置。

### 验证

已执行：

```bash
make test
```

结果：全部通过。

## 2026-06-02 处理 iperf 关闭期滞后数据

Commit: `af762ee`

### 背景

iperf3 测试结束或连接收尾时，B/C 两端出现关闭期错误：

- B：`channel_send_data: channel 65537 cannot send data in state=6`
- C：`proxy_write_to_local: invalid local_fd for channel 65537`
- C：`Reached max frames per cycle (64), possible frame flood`

### 根因

高吞吐 TCP 测试下，控制面 FIN/TIME_WAIT 和 KCP DATA 的到达顺序可能交错。通道已进入关闭流程后，B 端仍可能收到本地 socket 的滞后读事件，C 端也可能在本地 fd 已关闭后收到隧道内延迟 DATA。原逻辑把这些关闭期滞后事件当作错误处理。

### 变更

- `proxy_handle_local_read()` 对 `FIN_SENT`、`FIN_RCVD`、`TIME_WAIT`、`CLOSED` 状态的本地读事件直接关闭本地 fd 并返回，不再调用 `channel_send_data()`。
- `channel_process_frame()` 在本地 fd 已关闭且通道处于关闭流程时，丢弃 KCP 中的延迟 DATA 并记录 `DEBUG`。
- `MAX_FRAMES_PER_CYCLE` 从 64 提高到 1024，降低 iperf 高吞吐下的误报概率。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-02 支持本地写缓冲按需扩容

Commit: `4e54e75`

### 背景

iperf3 高吞吐测试中，服务器 C 向本地 iperf3 server 写入数据时出现：

- `proxy_write_to_local: recv_buf overflow (channel=65539, pending=376, new=65536, capacity=8192)`
- `proxy_write_to_local: remaining data too large (channel=65543, remaining=8688, capacity=8192)`

### 根因

`proxy_write_to_local()` 使用固定 8 KiB 的 `recv_buf` 保存非阻塞 socket 的待写数据。iperf3 下 KCP 单条应用消息可达 64 KiB，本地 TCP 写缓冲一旦短暂阻塞或部分写入，剩余数据很容易超过 8 KiB，原逻辑会把可恢复的写阻塞误判为本地连接丢失。

### 变更

- `channel_t.recv_buf` 从固定数组改为按需分配指针。
- 新增 `recv_buf_cap` 记录当前容量，初始不分配，按 `CHANNEL_RECV_BUF_SIZE` 起步扩容。
- 新增 `CHANNEL_RECV_BUF_MAX`，限制单通道待写缓冲最大 1 MiB。
- `proxy_write_to_local()` 在追加、EAGAIN/EINTR、部分写入路径中按需扩容，不再因 64 KiB 数据块直接溢出。
- `proxy_close_local()` 和 `channel_destroy()` 释放动态缓冲。
- 更新测试用例，确认缓冲区初始为空并按需分配。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-02 优化本地关闭收尾处理

Commit: `c0842ac`

### 背景

连续执行 iperf3 时，两端出现不同的收尾错误：

- C：`proxy_write_to_local: write/sendto(fd=6) failed: Connection reset by peer`
- C：`channel_process_frame: proxy_write_to_local failed ... local connection lost`
- C：旧通道在 `FIN_SENT` 中等待到 heartbeat timeout 后被记录为错误。

### 根因

本地 iperf3 server 在测试结束或异常收尾时可能主动 reset 某个连接。该场景应视为本地连接已关闭，而不是隧道错误。同时，`FIN_SENT` 已经处于关闭流程，不应继续使用 heartbeat timeout 作为错误路径；如果等不到对端 FIN，应按优雅关闭超时清理。

### 变更

- `proxy_write_to_local()` 将 `ECONNRESET`/`EPIPE` 降级为 `INFO`，返回 `PROXY_WRITE_LOCAL_CLOSED`。
- `channel_process_frame()` 收到 `PROXY_WRITE_LOCAL_CLOSED` 后发送 RST、销毁动态通道，避免继续处理已关闭的本地连接。
- `FIN_SENT` 从 heartbeat timeout 检查中移除，改用 `CHANNEL_GRACEFUL_TIMEOUT` 后清理。
- 所有进入 `FIN_SENT` 的主要路径更新 `last_active`，保证关闭超时基于进入关闭状态的时间计算。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-02 18:39 清理本地读失败和残留事件日志

Commit: `d198d1e`

### 背景

连续执行 iperf3 时，服务器 B/C 在部分连接被本地 peer reset 或会话已关闭后仍输出偏错误级别的收尾日志：

- B：`proxy_handle_event: proxy_handle_local_read failed (channel=65537, fd=7)`
- C：`proxy_handle_event: no channel found for fd=6`

### 根因

本地 fd 可读事件中继续转发数据时，如果通道已经进入关闭流程，`channel_send_data()` 会失败。原逻辑直接返回错误，导致事件层继续按异常记录。另一方面，通道销毁后 epoll 中可能仍有旧 fd 的残留事件，原逻辑把该场景作为 WARN 返回错误。

### 变更

- `proxy_handle_local_read()` 在 `channel_send_data()` 失败时主动关闭本地 fd，发送 RST，销毁动态通道，并返回本地连接关闭结果，避免上层重复记录错误。
- `proxy_handle_event()` 对找不到通道的 fd 残留事件降级为 `DEBUG` 并忽略，避免关闭竞态产生 WARN。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。
