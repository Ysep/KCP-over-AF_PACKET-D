# 架构设计文档 — KCP-over-AF_PACKET

本文档深入描述 KCP-over-AF_PACKET 系统的架构设计，包括数据流、协议帧格式、状态机、模块交互以及 MTU 预算分析。

---

## 目录

1. [整体架构](#1-整体架构)
2. [数据流图](#2-数据流图)
3. [协议帧格式](#3-协议帧格式)
4. [通道状态机](#4-通道状态机)
5. [模块交互图](#5-模块交互图)
6. [MTU 预算表](#6-mtu-预算表)
7. [主事件循环](#7-主事件循环)
8. [连接建立与断开流程](#8-连接建立与断开流程)

---

## 1. 整体架构

KCP-over-AF_PACKET 采用**分层模块化**设计，各模块职责清晰：

```
┌──────────────────────────────────────────────────────────────┐
│                         main.c                               │
│  配置加载 · 信号处理 · 启动/清理编排 · 主事件循环              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐      │
│  │   proxy.c    │   │  channel.c   │   │  channel.c   │      │
│  │  (代理模块)   │◄──│  (通道管理)   │──►│  (通道管理)   │      │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘      │
│         │                  │                  │               │
│         │    TCP/UDP       │    KCP           │  MyProto      │
│         │    Socket I/O    │    可靠传输       │  帧协议       │
│         │                  │                  │               │
│  ┌──────▼───────┐   ┌──────▼───────┐   ┌──────▼───────┐      │
│  │  Local App   │   │  kcp_wrap.c  │   │  myproto.c   │      │
│  │  (应用进程)   │   │  (KCP 包装)   │   │  (协议封装)   │      │
│  └──────────────┘   └──────┬───────┘   └──────┬───────┘      │
│                            │                  │               │
│                     ┌──────▼──────────────────▼───────┐      │
│                     │        af_packet.c               │      │
│                     │    AF_PACKET 原始套接字           │      │
│                     │    BPF · MAC · MTU · 帧收发       │      │
│                     └──────────────┬───────────────────┘      │
│                                    │                          │
├────────────────────────────────────┼──────────────────────────┤
│                           Linux Kernel                        │
│                    AF_PACKET · 网卡驱动 (ethX)                 │
└────────────────────────────────────┼──────────────────────────┘
                                     │
                              以太网物理链路
```

---

## 2. 数据流图

### 2.1 正向代理 — 发送路径（本地应用 → 远端服务）

```
本地应用
   │
   │ connect/connectto → TCP/UDP
   ▼
[ proxy.c: listen_fd/local_fd ]
   │
   │ proxy_handle_local_read() — 从 local_fd 读取数据
   ▼
[ kcp_wrap.c: kcp_wrap_send() ]
   │
   │ ikcp_send() — 数据分段入队 KCP 发送缓冲区
   ▼
[ KCP 内部处理 ]
   │
   │ ikcp_update() → kcp_output_cb() — 触发 KCP 输出回调
   ▼
[ channel.c: kcp_output_cb() ]
   │
   │ myproto_build_data_frame() — 封装 MyProto 帧头 + 可选加密/CRC
   ▼
[ myproto.c: myproto_build_data_frame() ]
   │
   │ 帧结构: [MyProto Hdr(8)] [IV(16)] [Payload] [HMAC(32)] [CRC32(4)]
   ▼
[ af_packet.c: af_packet_send() ]
   │
   │ 附加以太网头: [Eth Hdr(14)] [MyProto Frame]
   ▼
Linux AF_PACKET 套接字 → 网卡驱动 → 物理链路
```

### 2.2 正向代理 — 接收路径（远端服务 → 本地应用）

```
物理链路 → 网卡驱动 → BPF 过滤 (EtherType 匹配)
   │
   ▼
[ af_packet.c: af_packet_recv() ]
   │
   │ 剥离以太网头，提取 MyProto 帧
   ▼
[ myproto.c: myproto_parse_frame() ]
   │
   │ 解析帧头 → 可选解密/CRC 校验 → myproto_process_data_frame()
   ▼
[ channel.c: channel_process_frame() ]
   │
   │ 根据 frame flags 路由:
   │   - 控制帧 → 状态机处理
   │   - 数据帧 → kcp_wrap_input()
   ▼
[ kcp_wrap.c: kcp_wrap_input() → ikcp_input() ]
   │
   │ KCP 内部重组、ACK、重传处理 → kcp_wrap_recv()
   ▼
[ channel.c → proxy.c: proxy_write_to_local() ]
   │
   │ 写入 recv_buf → proxy_flush_to_local() → write() 到 local_fd
   ▼
本地应用 (TCP/UDP socket)
```

### 2.3 反向代理 — 数据流

反向代理模式下数据流方向为：
```
远端客户端 → AF_PACKET → [接收路径] → [KCP] → proxy_connect_remote() → 本地服务
本地服务 → [proxy] → [KCP] → [发送路径] → AF_PACKET → 远端客户端
```

---

## 3. 协议帧格式

### 3.1 以太网帧布局（线缆字节序）

```
┌──────────────────────────────────────────────────────────────────┐
│  字节偏移    0         6          12       14                  │
│         ┌──────────┬──────────┬──────────┬──────────────────┐  │
│         │ Dst MAC  │ Src MAC  │ EtherType│ MyProto 负载     │  │
│         │  (6B)    │  (6B)    │  (2B)    │  (可变长度)      │  │
│         └──────────┴──────────┴──────────┴──────────────────┘  │
│          ← 以太网头部 14 字节 →│← MyProto 帧 (含协议头+负载) →│  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 MyProto 协议头（8 字节，紧凑打包 `__attribute__((packed))`）

```
┌──────┬──────┬──────┬──────┬──────────────┬──────────────┐
│ Byte │ 0-1  │  2   │  3   │    4-5       │    6-7       │
├──────┼──────┼──────┼──────┼──────────────┼──────────────┤
│ 字段  │ magic│ vers │flags │ channel_id   │  data_len    │
│ 类型  │ u16  │ u8   │ u8   │    u16       │    u16       │
│ 值    │0x4D50│ 0x01 │ 见下 │  1-65535     │  0-65535     │
└──────┴──────┴──────┴──────┴──────────────┴──────────────┘

magic     = 0x4D50 ('M''P' 的 ASCII，大端序)
version   = 0x01 (协议版本)
flags     = 帧标志位（位掩码）
channel_id = 通道标识符（网络字节序）
data_len  = 有效负载长度（网络字节序）
```

### 3.3 帧标志位定义

```
Bit:   7      6      5      4      3      2      1      0
    ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
    │ CRYPTO│ PONG │ PING │ RST  │ FIN  │ ACK  │ SYN  │(res.)│
    │ 0x40  │ 0x20 │ 0x10 │ 0x08 │ 0x04 │ 0x02 │ 0x01 │ 0x00 │
    └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘

控制帧掩码: MPF_CTRL_MASK = 0x3F (覆盖 SYN/ACK/FIN/RST/PING/PONG)
加密标志:   MPF_CRYPTO = 0x40
数据帧:     flags & MPF_CTRL_MASK == 0 (无控制标志)
```

| 标志 | 值 | 语义 | 触发场景 |
|------|-----|------|----------|
| `MPF_SYN` | `0x01` | 通道建立请求 | Initiator 创建通道时发送 |
| `MPF_ACK` | `0x02` | 通道建立确认 | Responder 收到 SYN 后响应 |
| `MPF_FIN` | `0x04` | 通道关闭请求 | 本地连接关闭时发送 |
| `MPF_RST` | `0x08` | 强制复位 | 错误状态或拒绝连接 |
| `MPF_PING` | `0x10` | 心跳探测 | 空闲超时触发 |
| `MPF_PONG` | `0x20` | 心跳响应 | 收到 PING 后响应 |
| `MPF_CRYPTO` | `0x40` | 加密帧标志 | 加密启用时与数据帧组合使用 |

### 3.4 加密帧布局（SM4-CTR + HMAC-SM3）

```
┌──────────────┬──────────────┬──────────────────┬──────────────────┬──────────────┐
│ MyProto Hdr  │   IV         │   密文负载        │   HMAC-SM3 Tag   │   CRC32      │
│   (8B)       │  (16B)       │   (data_len)      │     (32B)        │   (4B)       │
└──────────────┴──────────────┴──────────────────┴──────────────────┴──────────────┘
                                   ← 加密覆盖范围 →

总加密开销 = 16 (IV) + 32 (HMAC) = 48 字节  (= CRYPTO_OVERHEAD)
```

### 3.5 非加密帧布局

```
┌──────────────┬──────────────────┬──────────────┐
│ MyProto Hdr  │   原始负载        │   CRC32      │
│   (8B)       │   (data_len)      │   (4B) 可选   │
└──────────────┴──────────────────┴──────────────┘
```

---

## 4. 通道状态机

```
                    ┌──────────┐
                    │  CLOSED  │  ← 初始状态
                    └────┬─────┘
                         │
            Initiator:   │           Responder:
         发送 SYN        │          收到 SYN
                         │
              ┌──────────▼──────────┐
              │                     │
         ┌────▼─────┐          ┌────▼─────┐
         │ SYN_SENT │          │ SYN_RCVD │
         └────┬─────┘          └────┬─────┘
              │                     │
         收到 ACK              发送 ACK
              │                     │
         ┌────▼─────────────────────▼─────┐
         │         ESTABLISHED            │  ← 数据可双向传输
         └──┬──────────────────────┬─────┘
            │                      │
     发送 FIN                 收到 FIN
            │                      │
       ┌────▼─────┐           ┌────▼─────┐
       │ FIN_SENT │           │ FIN_RCVD │
       └────┬─────┘           └────┬─────┘
            │ 收到 FIN              │ 发送 FIN
            │ 或收到 FIN 且          │
            │ 本地已 FIN             │
            ▼                      ▼
       ┌──────────────────────────────────┐
       │           TIME_WAIT              │  ← 超时等待 (30s)
       └──────────────┬───────────────────┘
                      │ 超时到期
                      ▼
                 ┌──────────┐
                 │  CLOSED  │  ← 通道销毁
                 └──────────┘

RST (任意状态) ──────────────────→ CLOSED (强制终止)
```

### 状态转换表

| 当前状态 | 事件 | 下一状态 | 动作 |
|----------|------|----------|------|
| CLOSED | 发送 SYN | SYN_SENT | 构造并发送 MPF_SYN 帧 |
| CLOSED | 收到 SYN | SYN_RCVD | 创建通道，发送 MPF_ACK |
| SYN_SENT | 收到 ACK | ESTABLISHED | 连接就绪 |
| SYN_SENT | 超时 | SYN_SENT | SYN 重传（有限重试） |
| SYN_RCVD | (等待对端 ACK) | ESTABLISHED | 应用层开始传输 |
| ESTABLISHED | 发送 FIN | FIN_SENT | 发送 MPF_FIN，等待对端 |
| ESTABLISHED | 收到 FIN | FIN_RCVD | 发送 MPF_FIN 确认 |
| FIN_SENT | 收到 FIN | TIME_WAIT | 双向关闭确认，等待超时 |
| FIN_RCVD | 发送 FIN | TIME_WAIT | 本地也关闭，等待超时 |
| TIME_WAIT | 超时 (30s) | CLOSED | 销毁通道资源 |
| 任意 | 收到 RST | CLOSED | 强制关闭，销毁通道 |

---

## 5. 模块交互图

### 5.1 启动流程（main.c 编排）

```
main(argc, argv)
  │
  ├─ 1. 命令行解析 (getopt_long)
  │
  ├─ 2. 初始化全局上下文 (memset → zero)
  │
  ├─ 3. config_load(config_path, &ctx.config)
  │     └─ json_object_from_file() → 解析 JSON → 填充 global_config_t
  │
  ├─ 4. validate_config(&ctx.config)
  │     └─ 检查 interface, ethertype, KCP params, channels, crypto key
  │
  ├─ 5. setup_signals(&ctx)
  │     └─ sigaction(SIGINT, SIGTERM, SIGHUP, SIGPIPE)
  │
  ├─ 6. proxy_init(&ctx)
  │     └─ epoll_create1(EPOLL_CLOEXEC)
  │
  ├─ 7. channel_init(&ctx)
  │     └─ 初始化哈希表 (512 槽位清零)
  │
  ├─ 8. af_packet_create(interface, ethertype, &ifindex)
  │     └─ socket(AF_PACKET, SOCK_RAW, htons(ethertype))
  │     └─ setsockopt(PACKET_VERSION, TPACKET_V2)
  │     └─ bind() → fcntl(O_NONBLOCK)
  │
  ├─ 9. af_packet_get_mac() (如果 local_mac 未配置)
  │
  ├─ 10. 设置 peer_mac (配置或广播)
  │
  ├─ 11. auto_set_nic_mtu? → af_packet_set_mtu()
  │
  ├─ 12. af_packet_set_bpf(raw_sock, ethertype)
  │     └─ setsockopt(SO_ATTACH_FILTER)
  │
  ├─ 13. 循环: channel_create() + proxy_start_listen()
  │     ├─ channel_create() → kcp_wrap_create() → kcp_wrap_set_params()
  │     │   └─ INITIATOR: channel_send_ctrl(MPF_SYN)
  │     └─ proxy_start_listen() → socket()+bind()+listen() → epoll_ctl(ADD)
  │
  ├─ 14. proxy_epoll_add(raw_sock) → epoll 注册 AF_PACKET fd
  │
  └─ 15. 主事件循环 (while ctx.running) ... 见 §7
```

### 5.2 运行时模块交互

```
     ┌─────────┐         ┌──────────┐         ┌──────────┐
     │  proxy  │◄───────►│ channel  │◄───────►│  kcp_wrap│
     └────┬────┘         └────┬─────┘         └────┬─────┘
          │                   │                    │
          │ epoll 事件        │ 帧路由/状态机      │ KCP 输入/输出
          │                   │                    │
          ▼                   ▼                    ▼
     ┌─────────┐         ┌──────────┐         ┌──────────┐
     │ epoll   │         │ myproto  │         │  ikcp    │
     │ (内核)  │         │ (帧协议) │         │ (KCP核心)│
     └────┬────┘         └────┬─────┘         └──────────┘
          │                   │
          ▼                   ▼
     ┌─────────────────────────────────┐
     │          af_packet              │
     │  AF_PACKET 原始套接字收发        │
     └─────────────────────────────────┘
```

---

## 6. MTU 预算表

KCP-over-AF_PACKET 链路层各协议层开销明细，用于指导 MTU 配置以确保以太网帧不超过 NIC MTU（默认 1500 字节）。

### 6.1 各层开销

| 层 | 组件 | 大小 (字节) | 是否必须 |
|----|------|-------------|----------|
| 以太网头 | Dst MAC + Src MAC + EtherType | 14 | 是 |
| MyProto 头 | magic + version + flags + channel_id + data_len | 8 | 是 |
| KCP 头 | ikcp 内部段头 (conv + cmd + frg + wnd + ts + sn + una + len) | 24 | 是 |
| 加密 IV | SM4-CTR 初始化向量 | 16 | 仅加密 |
| 加密 HMAC | SM3-HMAC 完整性标签 | 32 | 仅加密 |
| CRC32 | 帧尾校验值 | 4 | 可选 |
| **总开销（无加密，无 CRC）** | | **46** | |
| **总开销（加密 + CRC）** | | **98** | |

### 6.2 可用负载空间（基于 1500 字节标准 MTU）

| 配置 | 总开销 | 可用负载 | 有效载荷占比 |
|------|--------|----------|-------------|
| 无加密，无 CRC | 14 + 8 + 24 = **46** | **1454** | 96.9% |
| 无加密，含 CRC | 14 + 8 + 24 + 4 = **50** | **1450** | 96.7% |
| 含加密，无 CRC | 14 + 8 + 24 + 48 = **94** | **1406** | 93.7% |
| 含加密，含 CRC | 14 + 8 + 24 + 48 + 4 = **98** | **1402** | 93.5% |

### 6.3 KCP MTU 推荐值

KCP MTU 应基于可用负载空间设置（KCP MTU = 可用负载 + KCP 头 24 字节）：

| 配置 | 可用负载 | 推荐 KCP MTU | 常量 |
|------|----------|-------------|------|
| 无加密，无 CRC | 1454 | 1478 | `KCP_MTU_PERFORMANCE` |
| 无加密，含 CRC | 1450 | 1474 | — |
| 含加密 | 1406 | 1430 | — |
| 保守默认 | — | 1400 | `KCP_MTU_CONSERVATIVE` |

### 6.4 巨帧（Jumbo Frame, 9000 字节 MTU）

若链路支持巨帧，可大幅提升性能：

| 配置 | 总开销 | 可用负载 | 推荐 KCP MTU |
|------|--------|----------|-------------|
| 无加密，无 CRC | 46 | **8954** | **8978** |
| 含加密，含 CRC | 98 | **8902** | **8926** |

---

## 7. 主事件循环

```
while (ctx.running):
    
    epoll_wait(timeout=10ms)
        │
        ├─ EINTR → 检查 reload_requested / 继续
        │
        ├─ 处理就绪事件:
        │   │
        │   ├─ fd == raw_sock (AF_PACKET 可读):
        │   │   └─ af_packet_recv() → myproto_parse_frame()
        │   │       └─ channel_process_frame()
        │   │           ├─ 控制帧 → 状态机
        │   │           └─ 数据帧 → kcp_wrap_input()
        │   │
        │   └─ fd == local_fd/listen_fd (应用套接字):
        │       └─ proxy_handle_event()
        │           ├─ EPOLLIN  → proxy_handle_local_read()
        │           │   └─ read → kcp_wrap_send()
        │           └─ EPOLLOUT → proxy_handle_local_write()
        │               └─ recv_buf → write to socket
        │
        ├─ 定期任务 (每 10ms):
        │   ├─ channel_kcp_update(ctx)
        │   │   └─ 遍历所有通道 → kcp_wrap_update()
        │   │       └─ ikcp_update() → kcp_output_cb() → af_packet_send()
        │   ├─ channel_heartbeat(ctx)
        │   │   └─ 空闲通道发送 PING
        │   └─ channel_timeout_check(ctx)
        │       └─ 超时通道清理
        │
        └─ 统计输出 (每 60 秒)
```

---

## 8. 连接建立与断开流程

### 8.1 TCP 正向代理 — 连接建立

```
本地应用                  本地代理 (Initiator)                   远端代理 (Responder)              远端服务
   │                           │                                    │                              │
   │── TCP connect() ─────────→│                                    │                              │
   │                           │── MPF_SYN ────────────────────────→│ (channel_id=N)                │
   │                           │                                    │── TCP connect() ────────────→│
   │                           │←─────── MPF_ACK ──────────────────│                              │
   │←── TCP accept OK ────────│                                    │←── TCP connect OK ──────────│
   │                           │  === ESTABLISHED ===               │  === ESTABLISHED ===         │
   │                           │                                    │                              │
   │── TCP send(data) ────────→│── MPF_DATA (via KCP) ────────────→│── TCP send(data) ───────────→│
   │                           │                                    │                              │
```

### 8.2 TCP 正向代理 — 连接断开（优雅关闭）

```
本地应用                  本地代理                                 远端代理                    远端服务
   │                           │                                    │                              │
   │── close() ───────────────→│                                    │                              │
   │                           │── MPF_FIN ────────────────────────→│                              │
   │                           │  (FIN_SENT)                        │── shutdown(SHUT_WR) ────────→│
   │                           │                                    │←── close() ─────────────────│
   │                           │←─────── MPF_FIN ──────────────────│  (FIN_RCVD)                   │
   │                           │  (TIME_WAIT)                       │  (TIME_WAIT)                  │
   │                           │         ... 30s 超时 ...          │         ... 30s 超时 ...     │
   │                           │  → CLOSED                          │  → CLOSED                     │
```

### 8.3 连接异常 — RST 强制复位

```
任意状态 ── MPF_RST 收到 ──→ CLOSED → channel_destroy()
                                  │
                                  ├─ 关闭 local_fd (应用连接)
                                  ├─ 销毁 KCP 实例
                                  └─ 释放通道内存
```

---

## 9. 内存布局

### 9.1 关键结构体大小

| 结构体 | 大小 (近似) | 说明 |
|--------|------------|------|
| `myproto_hdr_t` | 8 字节 | 协议头，`_Static_assert` 保证 |
| `channel_t` | ~300 字节 | 通道运行时状态 |
| `global_config_t` | ~4 KB | 含 256 个 `channel_config_t` |
| `global_ctx_t` | ~6 KB | 含配置 + 512 槽位哈希表指针 |
| KCP 实例 (`ikcpcb`) | ~2 KB | 每个通道一个实例 |

### 9.2 缓冲区大小

| 缓冲区 | 大小 | 用途 |
|--------|------|------|
| `MAX_FRAME_SIZE` | 1550 字节 | MyProto 帧构建栈缓冲区 |
| `AF_PACKET_FRAME_SIZE` | 1600 字节 | AF_PACKET 接收栈缓冲区 |
| `CHANNEL_RECV_BUF_SIZE` | 8192 字节 | 每通道 KCP→socket 接收缓冲 |
| `PROXY_READ_BUF_SIZE` | 64 KB | 本地套接字读取栈缓冲区 |
| AF_PACKET SO_SNDBUF | 256 KB | 套接字内核发送缓冲 |
| AF_PACKET SO_RCVBUF | 512 KB | 套接字内核接收缓冲 |

---

## 10. 并发模型

- **单线程事件驱动**：基于 epoll 的单线程事件循环，无多线程竞争。
- **非阻塞 I/O**：所有套接字（AF_PACKET、TCP/UDP listen/local）均设为 `O_NONBLOCK`。
- **边缘触发 (EPOLLET)**：epoll 使用 EPOLLET 边缘触发模式，配合 `EPOLL_CLOEXEC`。
- **KCP 输出回调**：kcp_output_cb 在 `ikcp_update()` 期间同步调用，无并发问题。
- **信号安全**：信号处理器仅设置 `volatile` 标志位（`running`、`reload_requested`），主循环轮询检查。
