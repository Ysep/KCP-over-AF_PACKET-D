# iperf3 隧道吞吐调试记录 - 2026-06-04

## 拓扑

- 客户端 A: `192.168.1.148`
- 前端 B: `192.168.1.198`, `ens19`, MAC `16:95:e8:30:eb:91`
- 后端 C: `192.168.1.199`, `ens19`, MAC `1a:af:4e:ed:9d:91`
- 服务端 D: `192.168.1.149`

隧道路径：

```text
A iperf3 client -> B:5201 -> kcp-afpacket -> C -> D:5201
```

直连基线：

```text
A -> D:5201, iperf3 -P 1 -t 10
sender:   12.0 GBytes, 10.3 Gbits/sec, Retr=54
receiver: 12.0 GBytes, 10.3 Gbits/sec
```

## 初始配置

B/C 使用：

- `/root/kcp/kcp-afpacket`
- `/root/kcp/iperf-node-b.json`
- `/root/kcp/iperf-node-c.json`

初始 `performance`：

```json
{
    "af_packet_sndbuf": 16777216,
    "af_packet_rcvbuf": 16777216,
    "af_packet_send_retry_max": 8,
    "af_packet_send_wait_ms": 1,
    "proxy_tcp_sockbuf": 4194304,
    "kcp_read_pause_waitsnd": 4096,
    "kcp_read_resume_waitsnd": 2048,
    "kcp_immediate_flush": true,
    "max_frames_per_cycle": 100000
}
```

## 测试方法

每轮操作：

1. 修改 B/C 的 `performance` 或 `kcp` 参数。
2. 重启 B/C 的 `/root/kcp/kcp-afpacket`。
3. D 启动 `iperf3 -s`。
4. A 执行 `iperf3 -c 192.168.1.198 -P 1 -t 10`。

除特别说明外，表中结果均为标准 P1 隧道测试。

可手动复现本次矩阵测试：

```bash
./scripts/iperf_matrix_test.sh
```

只执行某一组：

```bash
CASE_FILTER=base4096 ./scripts/iperf_matrix_test.sh
```

同时临时应用 B/C sysctl 调优：

```bash
APPLY_SYSCTL=1 ./scripts/iperf_matrix_test.sh
```

## 测试结果

| 轮次 | 关键参数 | sender | receiver | Retr | 结论 |
|------|----------|--------|----------|------|------|
| baseline | 初始配置 | 578 MB / 484 Mbit/s | 572 MB / 480 Mbit/s | 195 | 当前稳定基线约 480 Mbit/s |
| early1024 | pause/resume `1024/512` | 连接拒绝 | - | - | B 端口未及时释放，结果无效 |
| early512 | pause/resume `512/256` | 240 MB / 201 Mbit/s | 240 MB / 201 Mbit/s | 247 | 过早背压显著降速 |
| bigbuf1024 | AF 64MiB, TCP 16MiB, pause `1024/512` | 连接拒绝 | - | - | B 端口未及时释放，结果无效 |
| bigbuf2048 | AF 64MiB, TCP 16MiB, pause `2048/1024` | 691 MB / 579 Mbit/s | 689 MB / 577 Mbit/s | 229 | 本轮最高，但后续不可重复 |
| noflush1024 | AF 64MiB, TCP 16MiB, immediate flush=false | 连接拒绝 | - | - | B 端口未及时释放，结果无效 |
| sysctl+bigbuf2048 | sysctl buffer 上限 128MiB, AF 64MiB, TCP 16MiB | 457 MB / 384 Mbit/s | 427 MB / 358 Mbit/s | 187 | 放大系统缓冲后未改善 |
| base4096 | AF 16MiB, TCP 4MiB, pause `4096/2048` | 509 MB / 426 Mbit/s | 498 MB / 417 Mbit/s | 176 | 与基线接近但略低 |
| p2048 | pause/resume `2048/1024` | 409 MB / 343 Mbit/s | 403 MB / 338 Mbit/s | 177 | 降速 |
| p8192 | pause/resume `8192/4096` | 507 MB / 425 Mbit/s | 496 MB / 415 Mbit/s | 209 | 无改善 |
| retry0 | retry/wait `0/0` | 508 MB / 425 Mbit/s | 502 MB / 421 Mbit/s | 173 | 无明显改善 |
| frames8192 | max_frames_per_cycle `8192` | 482 MB / 405 Mbit/s | 482 MB / 404 Mbit/s | 173 | 无改善 |
| kcp1478w4096 | KCP MTU 1478, wnd 4096 | 375 MB / 314 Mbit/s | 375 MB / 314 Mbit/s | 165 | KCP MTU/窗口放大降速 |
| kcp1478w8192 | KCP MTU 1478, wnd 8192 | 401 MB / 336 Mbit/s | 396 MB / 328 Mbit/s | 194 | 降速 |
| kcp1400w4096 | KCP MTU 1400, wnd 4096 | 362 MB / 303 Mbit/s | 362 MB / 303 Mbit/s | 176 | 降速 |
| default1024 | KCP MTU 1400, wnd 1024 | 464 MB / 389 Mbit/s | 454 MB / 381 Mbit/s | 175 | 恢复默认 KCP 仍未超过基线 |
| default_noflush | immediate flush=false | 448 MB / 376 Mbit/s | 436 MB / 366 Mbit/s | 117 | 重传下降但吞吐下降 |
| default_retry0 | retry/wait `0/0` | 500 MB / 419 Mbit/s | 492 MB / 411 Mbit/s | 174 | 无明显改善 |
| restored | 恢复初始 B/C 配置 | 503 MB / 422 Mbit/s | 496 MB / 416 Mbit/s | 175 | 初始配置仍是较稳选择 |

辅助测试：

| 命令 | sender | receiver | 结论 |
|------|--------|----------|------|
| `iperf3 -c 192.168.1.198 -P 1 -t 10 -l 8K` | 568 MB / 477 Mbit/s, Retr=171 | 538 MB / 450 Mbit/s | 小包仅轻微改善 |
| `iperf3 -c 192.168.1.198 -P 1 -t 10 -l 1400` | 563 MB / 472 Mbit/s, Retr=197 | 533 MB / 447 Mbit/s | 小于 MSS 也没有根本改善 |
| `iperf3 -c 192.168.1.198 -P 4 -t 10` | SUM 817 MB / 685 Mbit/s, Retr=378 | SUM 689 MB / 575 Mbit/s | 多连接聚合有提升，但仍远低于直连 |

## 系统参数发现

初始 B/C：

```text
net.core.wmem_max = 212992
net.core.rmem_max = 212992
net.core.wmem_default = 212992
net.core.rmem_default = 212992
```

这会截断 `performance.af_packet_sndbuf`、`performance.af_packet_rcvbuf` 和 `performance.proxy_tcp_sockbuf` 的实际效果。

临时调整：

```bash
sysctl -w net.core.wmem_max=134217728
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_default=4194304
sysctl -w net.core.rmem_default=4194304
sysctl -w net.core.netdev_max_backlog=250000
ip link set dev ens19 txqueuelen 10000
```

调整后，标准 P1 吞吐没有稳定提升。

网卡统计曾观察到较高累计 RX drop：

```text
B ens19 RX dropped: 1468090
C ens19 RX dropped: 5492772
```

放大 backlog 后，后续短测中该计数没有明显继续增长，但吞吐仍停留在约 400-500 Mbit/s。

## 当前结论

1. 仅通过 `performance` 参数调优，未能稳定接近 A->D 直连的 10.3 Gbit/s。
2. 可重复的标准 P1 隧道吞吐大多在 400-480 Mbit/s，偶发最高 577 Mbit/s 不能稳定复现。
3. `kcp_read_pause_waitsnd` 过低会明显降速；放大 KCP 窗口或 MTU 也会降速。
4. 关闭 `kcp_immediate_flush` 可降低发送端重传，但吞吐也下降。
5. B/C 的系统 socket buffer 上限过低是配置生效的前置问题，但临时放大后仍不是主要瓶颈。
6. 继续接近直连速率需要代码层面的性能改造，而不是继续扩大现有配置值。

## 5202 端口调试记录

时间：`2026-06-04 16:07`

现象：

```text
C: iperf3 -s -p 5202
A: iperf3 -c 192.168.1.198 -P 1 -t 10 -p 5202
iperf3: error - control socket has closed unexpectedly
```

排查结果：

1. B 当前运行进程使用的是 `/root/kcp/config-node-b.json`，不是 `/root/kcp/iperf-node-b.json`。
2. B 的 `config-node-b.json` 已监听 `5201-5205`，其中 `5202` 通道存在。
3. C 当前运行进程使用的是 `/root/kcp/config-node-c.json`，其中 `5202` 通道原本仍指向 `192.168.1.149:5202`，不符合“iperf3 服务端启动在 C 本机 5202”的测试方式。
4. C 上 `/usr/bin/iperf3` 原本不是 dpkg 管理的正式安装文件，只安装了 `libiperf0`；执行 `/usr/bin/iperf3 -s -p 5202` 会直接打印 usage 并退出，导致隧道后端连接很快关闭。

现场处理：

```bash
# C: 修复 iperf3 安装
DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall iperf3

# C: 将 config-node-c.json 中 channel_id=101 的目标改为本机 5202
"remote_addr": "127.0.0.1"
"remote_port": 5202

# C: 启动本机 iperf3 服务端并重启 kcp-afpacket
iperf3 -s -p 5202
/root/kcp/kcp-afpacket /root/kcp/config-node-c.json
```

验证：

```text
A: iperf3 -c 192.168.1.198 -P 1 -t 10 -p 5202
sender:   528 MBytes, 442 Mbits/sec, Retr=169
receiver: 517 MBytes, 433 Mbits/sec
```

本次验证未再出现 `control socket has closed unexpectedly`。C 端 kcp 日志中仍可见 iperf3 控制连接结束时的 `Connection reset by peer`，但数据连接已完整跑完 10 秒。

## 推荐保留配置

目前建议保留初始 `performance`，不要使用本次测试中的大窗口 KCP 或过低背压水位：

```json
"performance": {
    "af_packet_sndbuf": 16777216,
    "af_packet_rcvbuf": 16777216,
    "af_packet_send_retry_max": 8,
    "af_packet_send_wait_ms": 1,
    "proxy_tcp_sockbuf": 4194304,
    "kcp_read_pause_waitsnd": 4096,
    "kcp_read_resume_waitsnd": 2048,
    "kcp_immediate_flush": true,
    "max_frames_per_cycle": 100000
}
```

## 下一步建议

优先考虑代码层优化：

1. 增加可配置的本地 TCP read chunk，验证 64KB 应用消息分片是否造成 KCP 队头阻塞。
2. 增加 AF_PACKET RX/TX ring 或 `PACKET_MMAP` 批量收发，降低 per-frame syscall 成本。
3. 拆分 raw socket 收包、KCP update、proxy TCP I/O 到独立线程，避免单线程事件循环互相拖慢。
4. 增加每通道 KCP/AF_PACKET 统计日志：`waitsnd`、发送重试次数、KCP 重传、raw recv batch、local write stall。
5. 对 B->C raw 链路和 C->D 本地 TCP 输出分别做可观测性采样，确认瓶颈位置。
