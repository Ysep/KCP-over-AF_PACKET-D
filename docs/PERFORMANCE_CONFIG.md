# 性能调优配置说明

本文说明 `performance` 配置段。该配置段用于把影响传输速度的运行参数从代码常量改为 JSON 配置，方便现场按吞吐、重传和日志表现调试。

示例：

```json
{
    "performance": {
        "af_packet_sndbuf": 16777216,
        "af_packet_rcvbuf": 16777216,
        "af_packet_send_retry_max": 8,
        "af_packet_send_wait_ms": 1,
        "proxy_tcp_sockbuf": 4194304,
        "proxy_recv_buf_max": 16777216,
        "kcp_read_pause_waitsnd": 4096,
        "kcp_read_resume_waitsnd": 2048,
        "kcp_immediate_flush": true,
        "max_frames_per_cycle": 8192
    }
}
```

如果不配置 `performance`，程序使用以上默认值。

## 默认值与资源影响

这些默认值已经写入代码。配置文件不写 `performance` 时，程序仍会使用同一组默认参数。

`proxy_recv_buf_max` 需要特别注意：它不是启动时立即分配的固定内存，而是单个动态连接在“本地 TCP socket 暂时写不进去”时允许增长到的进程内待写缓冲上限。

实际内存占用近似为：

```text
实际占用 = 当前写阻塞连接数 × 每个连接实际积压数据量
理论上限 = 当前写阻塞连接数 × proxy_recv_buf_max
```

默认 `proxy_recv_buf_max = 16777216` 时：

```text
1 个写阻塞连接：最多约 16 MiB
10 个写阻塞连接：最多约 160 MiB
100 个写阻塞连接：最多约 1.6 GiB
```

对功能的影响：

- SSH、小流量 TCP、短连接：通常不会实际增长到该上限，影响很小。
- iperf3、高吞吐、大突发：更不容易因 `recv_buf overflow` 直接断流。
- 大量并发连接且后端服务写入变慢：进程可占用内存上限会增加，需要配合 `max_sessions` 控制并发。

使用建议：

- iperf3 或大流量压测：保留默认 `16777216`，必要时再按日志调大。
- SSH 或低流量生产：默认值可以保留，正常情况下不会额外占用 16 MiB。
- 高并发生产：根据内存预算设置 `max_sessions`，并按 `max_sessions × proxy_recv_buf_max` 估算最坏情况下的内存上限。

## 参数说明

| 参数 | 默认值 | 作用 | 调大影响 | 调小影响 |
|------|--------|------|----------|----------|
| `af_packet_sndbuf` | `16777216` | AF_PACKET 发送 socket 缓冲，单位字节 | 降低高吞吐下 `EAGAIN`/`ENOBUFS` 概率 | 更早触发发送背压 |
| `af_packet_rcvbuf` | `16777216` | AF_PACKET 接收 socket 缓冲，单位字节 | 降低接收突发丢帧概率 | 更容易因收包不及时丢帧 |
| `af_packet_send_retry_max` | `8` | AF_PACKET 发送遇到 `EAGAIN`/`EWOULDBLOCK`/`ENOBUFS` 时的最大重试次数 | 减少 KCP 帧因发送缓冲满而丢失 | 降低主循环阻塞风险，但可能增加丢帧 |
| `af_packet_send_wait_ms` | `1` | 每次 AF_PACKET 发送重试前等待可写的毫秒数 | 更愿意等待网卡队列恢复 | 减少等待，突发时更容易失败 |
| `proxy_tcp_sockbuf` | `4194304` | 本地 TCP 连接 `SO_SNDBUF`/`SO_RCVBUF`，单位字节 | 降低本地 TCP 背压 | 更快把背压传给客户端/服务端 |
| `proxy_recv_buf_max` | `16777216` | 本地 TCP 写阻塞时，进程内待写缓冲上限，单位字节 | 减少高吞吐下 `recv_buf overflow` 断流 | 更早暴露后端写入不及时的问题，占用内存更低 |
| `kcp_read_pause_waitsnd` | `4096` | `ikcp_waitsnd()` 达到该段数时暂停读本地 TCP | 允许 KCP 队列堆更多数据 | 更早对本地 TCP 施加背压 |
| `kcp_read_resume_waitsnd` | `2048` | `ikcp_waitsnd()` 降到该段数时恢复读本地 TCP | 更早恢复读取 | 恢复更保守，波动更小 |
| `kcp_immediate_flush` | `true` | `kcp_wrap_send()` 后立即 flush KCP | 减少 10ms 周期批量突发和排队延迟 | 仅靠周期 flush，CPU 调用少但突发更明显 |
| `max_frames_per_cycle` | `8192` | 主循环一次 raw socket 可读事件最多处理的 AF_PACKET 帧数 | 提高收包处理预算 | 避免 raw socket 饿死其它 fd 事件 |

## 取值范围

- `af_packet_sndbuf`: `>= 4096`
- `af_packet_rcvbuf`: `>= 4096`
- `af_packet_send_retry_max`: `0..1000`
- `af_packet_send_wait_ms`: `0..1000`
- `proxy_tcp_sockbuf`: `>= 4096`
- `proxy_recv_buf_max`: `>= 65536`
- `kcp_read_pause_waitsnd`: `> 0`
- `kcp_read_resume_waitsnd`: `1..kcp_read_pause_waitsnd`
- `kcp_immediate_flush`: `true` 或 `false`
- `max_frames_per_cycle`: `1..1000000`

## B/C 系统层调优

`performance` 中的 socket 缓冲配置会受 Linux 系统上限限制。如果系统 `net.core.wmem_max` / `net.core.rmem_max` 仍保持较小默认值，即使 JSON 中配置了较大的 `af_packet_sndbuf`、`af_packet_rcvbuf` 或 `proxy_tcp_sockbuf`，实际生效值也可能被内核截断。

在 B/C 两台运行 `kcp-afpacket` 的服务器上，可先临时设置：

```bash
sysctl -w net.core.wmem_max=134217728
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_default=4194304
sysctl -w net.core.rmem_default=4194304
ip link set dev ens19 txqueuelen 10000
```

参数作用：

| 参数 | 建议值 | 作用 |
|------|--------|------|
| `net.core.wmem_max` | `134217728` | 允许进程设置更大的发送 socket 缓冲上限 |
| `net.core.rmem_max` | `134217728` | 允许进程设置更大的接收 socket 缓冲上限 |
| `net.core.wmem_default` | `4194304` | 提高默认发送 socket 缓冲 |
| `net.core.rmem_default` | `4194304` | 提高默认接收 socket 缓冲 |
| `txqueuelen` | `10000` | 放大网卡发送队列长度，降低短时突发下排队过早失败的概率 |

注意事项：

- 上述命令只临时生效，重启后会恢复。
- `ip link set dev ens19 txqueuelen 10000` 中的 `ens19` 需要替换为实际运行 `kcp-afpacket` 的网卡名。
- 放大系统缓冲上限不等于立即占用对应内存；实际占用取决于 socket 数量和积压数据量。
- 系统层调优只能避免配置被内核上限截断，不能单独解决所有吞吐或重传问题。

如需持久化 sysctl，可写入 `/etc/sysctl.d/99-kcp-afpacket.conf`：

```text
net.core.wmem_max = 134217728
net.core.rmem_max = 134217728
net.core.wmem_default = 4194304
net.core.rmem_default = 4194304
```

然后执行：

```bash
sysctl --system
```

`txqueuelen` 持久化方式取决于系统网络管理工具，可放入 systemd-networkd、NetworkManager dispatcher 脚本，或启动 `kcp-afpacket` 前的部署脚本中。

## 调试建议

1. 如果发送端 `Retr` 很高，优先观察 `af_packet_send` 是否仍出现发送缓冲满。可以适当调大 `af_packet_sndbuf`，或调大 `af_packet_send_retry_max`。
2. 如果接收端出现 `proxy_ensure_recv_buf: pending buffer too large` 或 `recv_buf overflow`，说明后端本地 TCP 写入速度短时低于隧道输入速度。可先调大 `proxy_recv_buf_max`，再结合服务端 socket 状态判断是否需要降低入口速率或优化后端服务。
3. 如果发送端 TCP `Cwnd` 长时间很小，说明入口 TCP 被明显背压。可以尝试打开 `kcp_immediate_flush`，并降低 `kcp_read_pause_waitsnd`，让背压更早、更平滑。
4. 如果接收端速率周期性归零，优先调大 `max_frames_per_cycle` 和 `af_packet_rcvbuf`，避免 raw socket 收包预算不足。
5. 如果 CPU 占用过高或其它 fd 事件被饿死，降低 `max_frames_per_cycle`，或关闭 `kcp_immediate_flush` 做对比。
6. socket 缓冲设置可能受系统 `net.core.wmem_max` 和 `net.core.rmem_max` 限制。若配置很大但效果不明显，需要同步检查系统 sysctl。

5 路及以上 iperf3 并发压测时，如果 B 端出现 `af_packet_send: sendto failed ... No buffer space available`，说明 AF_PACKET 发送队列短时打满。可先尝试：

```json
"performance": {
    "af_packet_sndbuf": 33554432,
    "af_packet_rcvbuf": 33554432,
    "af_packet_send_retry_max": 32,
    "af_packet_send_wait_ms": 1,
    "max_frames_per_cycle": 100000
}
```

这组参数会让发送侧更愿意等待网卡队列恢复，并提高单轮 raw socket 收包预算。代价是单次事件循环可能停留更久，CPU 占用和其它 fd 的调度延迟可能上升。若 SSH 等低延迟业务与 iperf3 混跑，需要分别对比 `8/1`、`16/1`、`32/1` 的重传和延迟。

## 热重载说明

SIGHUP 热重载会更新：

- AF_PACKET 发送重试参数
- 本地 TCP 新连接的 socket 缓冲大小
- 本地 TCP 写阻塞待写缓冲上限
- KCP 读背压水位
- KCP 立即 flush 开关
- `max_frames_per_cycle`

已创建的 AF_PACKET socket 缓冲大小由 socket 创建时设置，调整 `af_packet_sndbuf` / `af_packet_rcvbuf` 后建议重启进程以确保生效。
