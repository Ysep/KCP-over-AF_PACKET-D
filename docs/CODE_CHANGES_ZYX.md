# 代码变动记录

## 2026-06-03 14:02 新增端口范围配置注意事项文档

Commit: ba61044

### 背景

在连续端口范围扩展到数百、数千乃至数万端口时，实际遇到的问题已经不只是配置语法本身，还包括：

- frontend 监听 socket 的 fd 上限
- `nmap -sT` 等扫描触发的运行期动态通道创建限速
- 超大范围配置的实际可用性判断

这些注意点之前分散在变更记录和对话结论里，没有单独文档可供部署时直接参考。

### 变更

- 新增 `docs/PORT_RANGE_NOTES.md`
- 汇总端口范围展开规则、frontend/backend 差异、fd 上限、动态通道 `1000/sec` 限速和推荐范围
- 补充适合当前实现的建议配置：`9100-9599` 和 `9100-9899`

### 验证

本次仅新增文档，无代码变更，无需重新编译或执行测试。

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

## 2026-06-03 17:15 立即刷新 KCP 发送队列

Commit: `06bd957`

### 背景

前一次修复后隧道吞吐从约 304 Mbit/s 提升到约 429 Mbit/s，但发送端仍出现 `Retr=862`，且 TCP `Cwnd` 长时间保持在约 89.1 KBytes，说明服务器 B 的入口 TCP 仍持续承压，数据进入 KCP 后的发送节奏仍不够平滑。

### 根因

当前 KCP 主要依赖 10ms 周期 `channel_kcp_update()` 统一 flush。高吞吐时服务器 B 会先从本地 TCP 读入较多数据，再在周期点集中向 AF_PACKET 发送，容易造成 KCP/AF_PACKET 突发发送和网卡队列压力，进而让入口 TCP 出现重传和窗口收缩。

### 变更

- 新增 `kcp_wrap_flush()`，支持在 KCP 数据入队后立即刷新输出队列。
- `channel_send_data()` 在 `kcp_wrap_send()` 成功后立即调用 `kcp_wrap_flush()`，减少 10ms 周期批量突发。
- 首次 flush 时自动执行一次 `ikcp_update()` 初始化 KCP 时间基准，后续 flush 直接更新 `current` 并调用 `ikcp_flush()`。
- 保留周期 `channel_kcp_update()`，继续负责 ACK、重传、超时和背压恢复。
- 本次提交同时按要求纳入当前已变动文件和重编译后的二进制。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 17:05 减少隧道高吞吐发送丢帧

Commit: `0a2f84a`

### 背景

服务器 A 直连服务器 D 执行 `iperf3 -c 192.168.1.149 -n 1G` 时约为 2.14 Gbit/s；经过 `kcp-afpacket` 隧道执行 `iperf3 -c 192.168.1.198 -n 1G` 时约为 304 Mbit/s，且发送端出现 `Retr=237`，说明隧道路径存在明显丢帧或发送侧背压处理不当。

### 根因

AF_PACKET 原始 socket 使用非阻塞发送。高吞吐场景下发送缓冲短暂打满会返回 `EAGAIN/EWOULDBLOCK`；如果 KCP output 路径没有等到帧真正进入内核发送队列，KCP 数据帧会在发送层丢失，最终表现为上层 TCP 大量重传、窗口收缩和吞吐下降。同时本地 TCP 连接未主动扩大 socket 收发缓冲，在 iperf 大流量下更容易形成内核侧背压。

### 变更

- `af_packet_send()` 对 `EAGAIN/EWOULDBLOCK` 增加短等待 `poll(POLLOUT)` 重试，减少 AF_PACKET 发送缓冲瞬时满导致的 KCP 帧丢失。
- 保留重试上限，避免单个发送点长时间阻塞主循环。
- frontend accept 出来的客户端 TCP fd 和 backend connect 到服务端的 TCP fd 均设置 4 MiB `SO_RCVBUF/SO_SNDBUF`。
- 本次提交同时按要求纳入当前已变动文件和重编译后的 `kcp-afpacket`。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 16:45 提升默认性能参数以满足吞吐目标

Commit: `c2f1af5`

### 背景

修改后的 `kcp-afpacket` 二进制在数据传输时吞吐没有达到预期，目标传输速率约为 700 MBytes/s。

### 根因

代码默认 KCP 发送/接收窗口仍为 128 段，低于项目文档和配置建议中的 1024 段；同时 AF_PACKET socket 缓冲和主循环单轮收帧预算偏保守，在高吞吐场景下容易形成额外背压，限制发送端到接收端的持续转发能力。

### 变更

- 将默认 `KCP_SEND_WINDOW` 和 `KCP_RECV_WINDOW` 从 128 提升到 1024。
- 将 AF_PACKET 发送/接收 socket 缓冲从 4 MiB 提升到 16 MiB。
- 将主循环单轮最大处理帧数从 1024 提升到 8192，减少高吞吐下的收包预算限制。
- 将 KCP 本地读背压水位调整为发送窗口的 4 倍暂停、2 倍恢复，配合更大的默认窗口避免无限堆积。
- 更新 v5 集成测试，窗口校验跟随 `KCP_SEND_WINDOW`/`KCP_RECV_WINDOW` 常量。
- 本次提交同时按要求纳入当前已变动文件和重编译二进制。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 13:46 前端监听 FD 预算预检与静态 listener 关闭清理修正

Commit: 07a9ae4

### 背景

服务器 B 使用超大连续端口范围：

```json
"listen_port_range": "9100-54326",
"remote_port_range": "9100-54326"
```

仍会在 frontend 启动监听阶段报错：

- `proxy_start_listen: socket(TCP) failed: Too many open files`
- `Failed to start listen for channel id=1020`

随后清理阶段又继续出现：

- `af_packet_send: sendto failed ... Resource temporarily unavailable`
- `channel_close_all: failed to send FIN to channel ...`

### 根因

- frontend 每个静态 TCP 监听端口都需要一个独立监听 socket。`9100-54326` 会展开为 45227 个 listener，远超常见进程 `RLIMIT_NOFILE` 软限制，因此 `socket()` 在启动到一部分端口后必然触发 `EMFILE`。
- 启动失败进入清理路径时，`channel_close_all()` 还会把静态 `CHANNEL_ROLE_LISTENER` 当作普通已建立通道发送 FIN/RST，进一步制造无意义的 AF_PACKET 发送压力和连带错误日志。

### 变更

- 在 frontend 启动、热重载新增通道、`ctl add` 新增通道前，新增 `RLIMIT_NOFILE` 预算预检。
- 预检会结合当前已打开 fd 数、待新增 listener 数和保留余量，提前报出明确错误，提示缩小 `listen_port_range` 或提高 `ulimit -n`。
- `channel_close_all()` 现在跳过静态 listener 和 `CHANNEL_ROLE_LISTENER`，清理时只对真实会话通道发送 FIN/RST。
- 新增回归测试，验证 `channel_close_all()` 不会把静态 listener 错误推进到 `FIN_SENT`。

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

## 2026-06-02 18:52 将本地读错误按连接关闭处理

Commit: `d2fbaef`

### 背景

服务器 A 执行 `iperf3 -c 192.168.1.198 -P 1 -t 10` 时，客户端出现：

- `iperf3: error - unable to receive results:`

服务器 B 同时仍出现：

- `proxy_handle_event: proxy_handle_local_read failed (channel=65537, fd=7)`

### 根因

本地 TCP fd 在 iperf3 收尾期可能返回非 `ECONNRESET` 的读错误。原逻辑只把 `ECONNRESET` 归类为连接关闭，其它 `read()` 错误仍返回 `-1`，事件层随后输出 `proxy_handle_local_read failed`。UDP 分支的 `channel_send_data()` 失败也有同类冒泡路径。

### 变更

- 新增本地读侧关闭辅助逻辑，统一关闭 local fd、发送 RST、置为 `CHANNEL_CLOSED` 并销毁动态通道。
- TCP `read()` 非阻塞之外的错误统一按本地连接关闭处理，不再向事件层冒泡为 ERROR。
- TCP/UDP `channel_send_data()` 失败时统一走本地读侧关闭收尾。
- `proxy_handle_event()` 对本地读返回负值的兜底路径改为关闭/RST/销毁并返回成功，避免再次输出 `proxy_handle_local_read failed`。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 10:35 忽略动态通道关闭后的延迟 ACK

Commit: 20f64f7

### 背景

服务器 A 执行连接扫描：

```bash
nmap -sT 192.168.1.198 -p 5201
```

服务器 B 在接受新会话后，本地 TCP 连接很快被扫描端 reset：

- `proxy_accept: new session chan=65541 fd=6 (listener=1)`
- `proxy_handle_local_read: connection reset by peer on fd=6 (channel=65541), closing session`
- `channel_process_frame: ACK for unknown channel 65541, dropping`

### 根因

`nmap -sT` 的 TCP connect 扫描会建立连接后快速关闭或 reset。本端收到 `ECONNRESET` 后会通过本地读侧关闭路径发送 RST 并销毁动态通道。此时对端已经发出的 ACK 控制帧可能仍在 AF_PACKET 链路上，晚到后 `channel_process_frame()` 找不到对应 channel，原逻辑把该竞态按 ERROR 返回。

该 ACK 属于关闭竞态中的延迟控制帧，行为上应与未知 FIN/RST、关闭后的延迟 DATA 一样被静默丢弃，不应污染错误日志，也不应向上层返回失败。

### 变更

- `channel_process_frame()` 收到未知通道的 ACK 时改为 `DEBUG` 级别记录 `late ACK for unknown channel ...`，并返回成功。
- 新增回归测试覆盖 destroyed/unknown dynamic channel 收到 ACK 的路径。

### 验证

已执行：

```bash
make test-integ5
make
```

结果：全部通过。

## 2026-06-03 11:33 增加端口范围配置语法

Commit: 4cf690a

### 背景

连续代理多个端口时，原配置必须在 `channels[]` 中逐条手写每个端口映射。例如代理 `5201-5203` 需要写 3 条 channel；端口数量增加时配置冗长，也更容易出现 `channel_id`、监听端口或远端端口不连续的人工错误。

### 根因

配置解析只支持单个 `listen_port` 和 `remote_port` 字段，没有端口范围语法。运行时通道和热重载已经基于展开后的 `channels[]` 工作，因此更合适的实现方式是在 `config_load()` 阶段把范围配置展开为多条现有 `channel_config_t`，保持代理、通道状态机和动态会话分配逻辑不变。

### 变更

- 新增 `listen_port_range` 配置字段，支持 `"5201-5203"` 和 `[5201, 5203]` 两种写法。
- 新增 `remote_port_range` 配置字段；也支持只写 `remote_port` 作为起始端口，按监听范围偏移自动递增。
- 端口范围展开时，`channel_id` 作为起始 ID，内部通道按 `channel_id + offset` 递增。
- 增加范围合法性检查：端口范围必须在 `1-65535`，起止顺序必须有效，监听范围和远端范围长度必须一致，展开数量不能超过 `MAX_CHANNELS`。
- 新增配置加载回归测试，验证 `listen_port_range` 能展开为多条通道，并正确递增 `channel_id`、`listen_port` 和 `remote_port`。
- 更新 `docs/CONFIG.md` 和 `docs/DEPLOYMENT.md`，记录新语法和示例。
- 重新编译 `kcp-afpacket` 主二进制。

### 验证

已执行：

```bash
make test-integ
make
make test
```

结果：全部通过。

## 2026-06-03 12:05 新增端口范围配置示例

Commit: 7786cb7

### 背景

端口范围功能已经支持 `listen_port_range` 和 `remote_port_range`，但 `sample` 目录里仍只有单端口配置示例。使用新功能时，用户需要一个可直接参考的前后端配置样例，尤其是与你当前 B/C 拓扑一致的 `54320-54326` 连续端口代理场景。

### 变更

- 新增 `sample/config-node-b-port-range.json`，提供 frontend 端口范围代理示例。
- 新增 `sample/config-node-c-port-range.json`，提供 backend 对应配置示例。
- 两个示例均使用 `listen_port_range: "54320-54326"` 和 `remote_port_range: "54320-54326"`，并保留 `max_sessions: 256`。

### 验证

已执行：

```bash
python3 -m json.tool sample/config-node-b-port-range.json
python3 -m json.tool sample/config-node-c-port-range.json
make
```

结果：全部通过。

## 2026-06-03 12:23 补充 remote_port 起始端口递增样例

Commit: 81e3471

### 背景

此前新增的 `sample/config-node-*-port-range.json` 仅展示了显式 `remote_port_range` 的写法，没有覆盖 `listen_port_range` 搭配单个 `remote_port` 起始端口、由加载器自动按偏移递增远端端口的用法。

### 变更

- 新增 `sample/config-node-b-port-range-base-remote.json`，展示 frontend 侧使用 `listen_port_range: "5201-5203"` 与 `remote_port: 5201` 的配置。
- 新增 `sample/config-node-c-port-range-base-remote.json`，展示 backend 对应配置。
- 两个样例都使用 `channel_id: 100` 作为展开起始 ID，对应内部展开为 `100/101/102`。

### 验证

已执行：

```bash
python3 -m json.tool sample/config-node-b-port-range-base-remote.json
python3 -m json.tool sample/config-node-c-port-range-base-remote.json
make
```

结果：全部通过。

## 2026-06-03 12:23 修正异步 connect 失败的事件处理顺序

Commit: 7748cc6

### 背景

服务器 C 使用端口范围配置时，服务器 A 执行：

```bash
nmap -sT -p 54320-55326 192.168.1.198
```

后端日志出现：

- `proxy_connect_remote: connecting to 192.168.1.67:54321 ...`
- `proxy_handle_local_read: read(fd=5) ended with No route to host ...`

这类日志出现在目标端口不可达或路由失败的收尾阶段，容易误导为“本地读错误”，而不是“异步 connect 失败”。

### 根因

后端 `proxy_connect_remote()` 对目标服务使用非阻塞 `connect()`。当连接还处于 `connect_pending` 时，`proxy_handle_event()` 先按 `EPOLLIN` 调用 `proxy_handle_local_read()`，而没有先通过 `getsockopt(SO_ERROR)` 确认异步连接结果。内核把连接失败通过事件返回时，当前代码就把它错误归类成了读路径上的 `No route to host`。

### 变更

- 新增异步连接完成辅助逻辑，统一通过 `getsockopt(SO_ERROR)` 确认 `connect_pending` 套接字的结果。
- `proxy_handle_event()` 在处理 `EPOLLIN/EPOLLOUT/EPOLLERR/EPOLLHUP` 前，若通道仍处于 `connect_pending`，优先完成连接状态确认。
- 连接失败时直接按会话关闭路径处理，不再先落入 `proxy_handle_local_read()` 并输出误导性的 `read(...): No route to host` 日志。
- `proxy_handle_local_write()` 复用同一套异步连接确认逻辑，避免写路径和事件路径重复维护。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 12:36 降低预期连接失败日志级别

Commit: c4044e0

### 背景

修正异步连接事件顺序后，`nmap -sT` 扫描范围端口时，后端日志不再错误显示 `proxy_handle_local_read: ... No route to host`，但仍会在 `INFO` 级别输出：

- `proxy_finish_async_connect: async connect failed ... No route to host`

对于扫描命中不存在或不可达的后端目标端口，这类连接失败是预期结果，不属于代理自身错误。

### 变更

- 将 `ECONNREFUSED`、`EHOSTUNREACH`、`ENETUNREACH`、`ETIMEDOUT` 这类预期的异步连接失败从 `INFO` 降级为 `DEBUG`。
- 保留其它非预期异步连接失败为 `INFO`，便于继续观察真实异常。
- 不改变失败时的会话收尾逻辑，仍然关闭本地 fd、发送 RST 并销毁动态通道。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 12:47 静态端口范围启动不再触发创建限速

Commit: 8ef72b7

### 背景

将配置改为：

```json
"listen_port_range": "9100-54326",
"remote_port_range": "9100-54326"
```

后，启动阶段需要一次性展开并创建大量静态 listener。此前启动到第 1001 个通道时会报：

- `channel_create: rate limit exceeded (1000/sec)`
- `Failed to create channel id=1001`

随后清理阶段又伴随 AF_PACKET 发送缓冲相关错误日志。

### 根因

`channel_create()` 的每秒 1000 个通道创建限速原本用于运行期动态通道创建的防护，但实现上同样作用于启动阶段的静态 `CHANNEL_ROLE_LISTENER` 创建。端口范围展开为数万条静态 listener 后，会在进程启动的同一秒内命中该限速，导致配置合法却无法完成初始化。

### 变更

- 将通道创建限速收窄到非 `CHANNEL_ROLE_LISTENER` 的运行期通道创建。
- 静态 listener 的启动和热重载创建不再受 `1000/sec` 限速影响。
- 新增回归测试，验证在同一秒内已达到限速计数时，`INITIATOR` 仍会被限速，而 `LISTENER` 可以继续成功创建。

### 验证

已执行：

```bash
make test-integ5
make
make test
```

结果：全部通过。

## 2026-06-03 15:35 忽略未知通道滞后心跳

Commit: `0d9d56e`

### 背景

服务器 A 执行 `iperf3 -c 192.168.1.198 -P 1 -t 10` 时，服务器 B 出现：

- `channel_process_frame: PING for unknown channel 65538, dropping`

### 根因

iperf3 连接收尾后，动态通道可能已经被 RST/FIN 路径销毁，但对端之前排队的通道级心跳帧仍可能延迟到达。`ACK/FIN/RST` 对未知通道已按延迟控制帧忽略，只有 `PING/PONG` 仍按错误返回，导致关闭竞态下输出 ERROR。

### 变更

- 未知通道的 `PING` 从 `ERROR` 降级为 `DEBUG`，并返回成功。
- 未知通道的 `PONG` 同样按延迟心跳忽略，不再返回错误。
- 新增 v5 集成测试，覆盖 unknown channel 的 late `PING/PONG` 都应返回 0。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 15:46 修复本地读计数溢出

Commit: `f2f6bcc`

### 背景

服务器 B 在 iperf3 高吞吐传输中出现：

- `proxy_handle_event: proxy_handle_local_read returned -862076032 (channel=65537, fd=7), closing session`

### 根因

`proxy_handle_local_read()` 在 edge-triggered TCP 读事件中会循环读取直到 `EAGAIN`。iperf3 高吞吐下，单次事件累计读取字节数可能超过 32 位 `int` 上限，`total_read` 溢出成负数后被事件层误判为本地读失败，从而关闭会话。

### 变更

- 将 `proxy_handle_local_read()` 的累计读取计数从 `int` 改为 `size_t`。
- 调整调试日志格式为 `%zu`。
- 返回给事件层前将超过 `INT_MAX` 的成功读取计数截断为 `INT_MAX`，保证成功读不会变成负返回值。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 16:14 为 KCP 发送队列增加本地读背压

Commit: `e8f3740`

### 背景

服务器 A 执行 `iperf3 -c 192.168.1.198 -P 1 -t 10` 时，A 端显示发送 2.86 GB、2.45 Gbit/s，但服务器 C 端只收到 363 KB、296 Kbit/s。

### 根因

B 端代理在本地 TCP fd 可读时会一直读取到 `EAGAIN`，并把数据持续送入 KCP 发送队列。缺少 KCP 发送队列背压时，A 到 B 的本地 TCP 可以高速完成，但实际 AF_PACKET/KCP 链路无法同步发送，导致数据大量积压在 B 端 KCP 队列，C 端接收速率远低于 A 端显示的发送速率。

### 变更

- 新增 `CH_FLAG_KCP_READ_PAUSED` 标志，表示通道本地读因 KCP 发送队列高水位暂停。
- 新增 KCP 发送队列高/低水位：`waitsnd >= 2048` 段暂停本地 `EPOLLIN`，`waitsnd <= 1024` 段恢复。
- `proxy_get_events()` 根据背压标志动态移除或恢复本地 fd 的 `EPOLLIN`。
- `proxy_handle_local_read()` 在入队数据后检查 KCP 队列水位，达到高水位即停止继续读取本地 TCP。
- `channel_kcp_update()` 在 KCP 周期更新后检查是否已降到低水位，自动恢复本地读。
- 为未链接 `proxy.c` 的无网络测试提供弱符号 no-op fallback，保持测试可独立链接。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 16:23 处理 AF_PACKET 发送缓冲暂满

Commit: `4a7c537`

### 背景

服务器 A 执行 `iperf3 -c 192.168.1.198 -P 10 -t 10` 时，服务器 B 出现大量：

- `af_packet_send: sendto failed ... Resource temporarily unavailable`
- `kcp_output_cb: af_packet_send failed ... Resource temporarily unavailable`

### 根因

`iperf3 -P 10` 并发流量会短时间内打满 AF_PACKET 原始 socket 发送缓冲。`sendto()` 返回 `EAGAIN/EWOULDBLOCK` 表示暂时不可写，是发送侧背压，不是永久错误。原逻辑按 ERROR 记录并计入通道发送错误，导致日志刷屏。

### 变更

- 将 AF_PACKET 发送/接收 socket 缓冲区提升到 4 MiB，降低并发发送下触发 `EAGAIN` 的概率。
- `af_packet_send()` 对 `EAGAIN/EWOULDBLOCK` 降级为 `DEBUG`，保留 errno 返回给上层。
- `kcp_output_cb()` 对 AF_PACKET 发送缓冲暂满按可恢复背压处理，不再输出 ERROR，也不计入 `tx_errors`。
- 保留其它 `sendto()` 失败为 ERROR。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。

## 2026-06-03 16:28 避免 EOF 后重复处理本地错误事件

Commit: `9f9ba46`

### 背景

服务器 A 执行 `iperf3 -c 192.168.1.198 -P 10 -t 10` 时，服务器 C 在多个通道上出现先 EOF 后 ERROR 的日志：

- `proxy_handle_local_read: EOF on fd=8 (channel=65539), starting graceful close`
- `proxy_handle_event: error on local_fd=8 (channel=65539, events=0x19)`

### 根因

`events=0x19` 同时包含 `EPOLLIN|EPOLLERR|EPOLLHUP`。事件层先处理 `EPOLLIN`，读到 EOF 后已经关闭 local fd 并进入优雅关闭，但随后仍继续处理同一事件中的 `EPOLLERR`，把正常收尾误报为 ERROR。

### 变更

- `proxy_handle_event()` 在 `EPOLLIN` 处理后，如果 local fd 已关闭，立即返回，不再继续处理同一事件中的 ERR/HUP。
- 本地连接事件中优先处理 `EPOLLHUP`，再处理单独的 `EPOLLERR`，避免 `HUP|ERR` 组合被误判为硬错误。
- 本次提交同时按要求纳入当前已变动文件。

### 验证

已执行：

```bash
make
make test
```

结果：全部通过。
