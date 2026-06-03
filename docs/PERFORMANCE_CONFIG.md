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
        "kcp_read_pause_waitsnd": 4096,
        "kcp_read_resume_waitsnd": 2048,
        "kcp_immediate_flush": true,
        "max_frames_per_cycle": 8192
    }
}
```

如果不配置 `performance`，程序使用以上默认值。

## 参数说明

| 参数 | 默认值 | 作用 | 调大影响 | 调小影响 |
|------|--------|------|----------|----------|
| `af_packet_sndbuf` | `16777216` | AF_PACKET 发送 socket 缓冲，单位字节 | 降低高吞吐下 `EAGAIN` 概率 | 更早触发发送背压 |
| `af_packet_rcvbuf` | `16777216` | AF_PACKET 接收 socket 缓冲，单位字节 | 降低接收突发丢帧概率 | 更容易因收包不及时丢帧 |
| `af_packet_send_retry_max` | `8` | AF_PACKET 发送遇到 `EAGAIN` 时的最大重试次数 | 减少 KCP 帧因发送缓冲满而丢失 | 降低主循环阻塞风险，但可能增加丢帧 |
| `af_packet_send_wait_ms` | `1` | 每次 AF_PACKET 发送重试前等待可写的毫秒数 | 更愿意等待网卡队列恢复 | 减少等待，突发时更容易失败 |
| `proxy_tcp_sockbuf` | `4194304` | 本地 TCP 连接 `SO_SNDBUF`/`SO_RCVBUF`，单位字节 | 降低本地 TCP 背压 | 更快把背压传给客户端/服务端 |
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
- `kcp_read_pause_waitsnd`: `> 0`
- `kcp_read_resume_waitsnd`: `1..kcp_read_pause_waitsnd`
- `kcp_immediate_flush`: `true` 或 `false`
- `max_frames_per_cycle`: `1..1000000`

## 调试建议

1. 如果发送端 `Retr` 很高，优先观察 `af_packet_send` 是否仍出现发送缓冲满。可以适当调大 `af_packet_sndbuf`，或调大 `af_packet_send_retry_max`。
2. 如果发送端 TCP `Cwnd` 长时间很小，说明入口 TCP 被明显背压。可以尝试打开 `kcp_immediate_flush`，并降低 `kcp_read_pause_waitsnd`，让背压更早、更平滑。
3. 如果接收端速率周期性归零，优先调大 `max_frames_per_cycle` 和 `af_packet_rcvbuf`，避免 raw socket 收包预算不足。
4. 如果 CPU 占用过高或其它 fd 事件被饿死，降低 `max_frames_per_cycle`，或关闭 `kcp_immediate_flush` 做对比。
5. socket 缓冲设置可能受系统 `net.core.wmem_max` 和 `net.core.rmem_max` 限制。若配置很大但效果不明显，需要同步检查系统 sysctl。

## 热重载说明

SIGHUP 热重载会更新：

- AF_PACKET 发送重试参数
- 本地 TCP 新连接的 socket 缓冲大小
- KCP 读背压水位
- KCP 立即 flush 开关
- `max_frames_per_cycle`

已创建的 AF_PACKET socket 缓冲大小由 socket 创建时设置，调整 `af_packet_sndbuf` / `af_packet_rcvbuf` 后建议重启进程以确保生效。
