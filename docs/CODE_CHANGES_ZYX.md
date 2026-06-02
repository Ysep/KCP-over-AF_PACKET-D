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
