# 架构设计文档 — KCP-over-AF_PACKET

本文档深入描述 KCP-over-AF_PACKET 系统的完整架构设计，包括系统概览、模块职责、数据流、状态机、协议帧格式、通道哈希表、Epoll 事件模型、加密管线、节点角色及所有关键常量。

---

## 目录

1. [系统概览](#1-系统概览)
2. [模块职责](#2-模块职责)
3. [完整数据流](#3-完整数据流)
4. [通道状态机](#4-通道状态机)
5. [协议帧格式（字节级图解）](#5-协议帧格式字节级图解)
6. [通道哈希表设计](#6-通道哈希表设计)
7. [Epoll 事件模型](#7-epoll-事件模型)
8. [加密管线](#8-加密管线)
9. [节点类型（Frontend/Backend）](#9-节点类型frontendbackend)
10. [关键常量及其含义](#10-关键常量及其含义)
11. [MTU 预算分析](#11-mtu-预算分析)
12. [主事件循环](#12-主事件循环)
13. [连接建立与断开流程](#13-连接建立与断开流程)

---

## 1. 系统概览

KCP-over-AF_PACKET 是一个 Linux 用户空间代理隧道系统，通过 **AF_PACKET 原始套接字**直接在数据链路层（OSI 第 2 层）进行通信，完全绕过 Linux 内核 TCP/IP 协议栈。系统集成 **KCP 协议**提供 ARQ 可靠传输能力，支持透明 TCP/UDP 代理和多流复用。

### 系统架构 ASCII 图

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              main.c                                      │
│         配置加载 · 信号处理 · 启动/清理编排 · 主事件循环                    │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐        │
│  │    proxy.c/h     │   │   channel.c/h    │   │   channel.c/h    │        │
│  │   (代理模块)      │◄──│  (通道管理 #1)    │──►│  (通道管理 #N)    │        │
│  └────────┬────────┘   └────────┬────────┘   └────────┬────────┘        │
│           │                     │                      │                 │
│     TCP/UDP Socket I/O          │  KCP 可靠传输        │ MyProto 帧协议  │
│           │                     │                      │                 │
│  ┌────────▼────────┐   ┌────────▼────────┐   ┌────────▼────────┐        │
│  │   本地应用       │   │   kcp_wrap.c/h   │   │   myproto.c/h    │        │
│  │  (应用进程)       │   │  (KCP 包装层)     │   │  (私有协议封装)   │        │
│  └─────────────────┘   └────────┬────────┘   └────────┬────────┘        │
│                                 │                      │                 │
│                          ┌──────▼──────────────────────▼──────┐         │
│                          │          af_packet.c/h              │         │
│                          │    AF_PACKET 原始套接字              │         │
│                          │    BPF · MAC · MTU · 以太网帧收发    │         │
│                          └──────────────────┬──────────────────┘         │
│                                             │                            │
├─────────────────────────────────────────────┼────────────────────────────┤
│                                    Linux Kernel                          │
│                           AF_PACKET · 网卡驱动 (ethX)                     │
└─────────────────────────────────────────────┼────────────────────────────┘
                                              │
                                       以太网物理链路
```

### 端到端部署拓扑

```
┌──────────┐   TCP/UDP   ┌────────────────┐  AF_PACKET  ┌────────────────┐  TCP/UDP   ┌──────────┐
│  主机 A   │ ──────────→ │   Frontend 节点  │ ───────────→│   Backend 节点   │ ──────────→│  主机 B   │
│  (客户端)  │ ←────────── │  (kcp-afpacket)  │ ←───────────│  (kcp-afpacket)  │ ←──────────│  (服务端)  │
└──────────┘             └────────────────┘             └────────────────┘             └──────────┘
    127.0.0.1:8080           eth0 (raw)                    eth0 (raw)              192.168.1.100:80
                             EtherType: 0x88B5             EtherType: 0x88B5
```

---

## 2. 模块职责

| 模块 | 文件 | 职责 |
|------|------|------|
| **main** | `src/main.c` | 入口点：命令行解析、配置加载/验证、加密初始化、信号处理、启动序列编排、主事件循环、优雅退出清理 |
| **af_packet** | `src/af_packet.c/h` | AF_PACKET 原始套接字生命周期：创建 `socket(AF_PACKET, SOCK_RAW)`、绑定网卡、TPACKET_V2 高性能模式、BPF 内核过滤器、MAC 地址获取（`ioctl(SIOCGIFHWADDR)`）、NIC MTU 读写（`SIOCGIFMTU`/`SIOCSIFMTU`）、以太网帧收发 |
| **myproto** | `src/myproto.c/h` | MyProto 私有链路层协议：8 字节协议头封装/解析、帧验证（魔数/版本/长度）、控制帧（SYN/ACK/FIN/RST/PING/PONG）构造、数据帧构造（含可选加密标志）、CRC32 计算/附加/校验（标准 CRC-32/ISO-HDLC 多项式 0xEDB88320） |
| **crypto** | `src/crypto.c/h` | 国密加密模块：SM4-CBC 对称加密（128-bit 分组密码，PKCS7 填充）、SM3-HMAC 消息认证码（256-bit）、HMAC 密钥派生（HKDF 式：`HMAC-SM3("KCP-HMAC", sm4_key)`）、帧级加密/解密 API、密钥材料安全擦除 |
| **kcp_wrap** | `src/kcp_wrap.c/h` | KCP（ikcp）库封装：实例创建/销毁、参数配置（MTU/窗口/nodelay/interval/resend/nc）、`kcp_wrap_send()`/`kcp_wrap_recv()`/`kcp_wrap_input()` 数据接口、`kcp_wrap_update()` 定时驱动、输出回调绑定 |
| **channel** | `src/channel.c/h` | 核心模块：通道生命周期管理、7 状态机驱动、哈希表（链地址法）查找、帧路由分发（控制帧→状态机，数据帧→KCP）、心跳探测（PING/PONG）、超时检测、KCP 定时更新调度、统计算法 |
| **proxy** | `src/proxy.c/h` | TCP/UDP 透明代理：监听套接字创建/绑定、`accept()` 新连接、`connect()` 远端服务、epoll 事件注册/分发、数据桥接（`local_fd ↔ recv_buf ↔ KCP`）、背压流控 |
| **ikcp** | `src/ikcp.c/h` | KCP 协议核心库（第三方）：可靠传输、自动重传（ARQ）、流量控制、拥塞控制、分段与重组 |

### 模块依赖图

```
main.c
  ├── af_packet.c    (链路层帧收发)
  ├── myproto.c      (帧协议封装/解析)
  │     └── crypto.c (SM4-CBC + SM3-HMAC)
  ├── kcp_wrap.c     (KCP 包装)
  │     └── ikcp.c   (KCP 核心)
  ├── channel.c      (通道管理)
  │     ├── kcp_wrap.c
  │     ├── myproto.c
  │     ├── af_packet.c
  │     └── proxy.c
  └── proxy.c        (代理桥接)
```

---

## 3. 完整数据流

### 3.1 发送路径：客户端 → Frontend → AF_PACKET → Backend → 服务端

```
客户端应用 (127.0.0.1:8080)
   │
   │ connect() / send() → TCP/UDP Socket
   ▼
[proxy.c: listen_fd  →  accept() → local_fd]
   │
   │ epoll_wait 触发 EPOLLIN → proxy_handle_local_read()
   │ 从 local_fd read() → 数据写入 channel->recv_buf
   ▼
[proxy.c: proxy_flush_to_local() 反向 → 实际是 kcp_wrap_send()]
   │
   │ kcp_wrap_send(ch->kcp, data, len)
   │ → ikcp_send() 数据分段入队 KCP 发送缓冲区
   ▼
[KCP 内部: ikcp_update() 定时触发]
   │
   │ KCP 组装数据段 → 调用 kcp_output_cb()
   ▼
[channel.c: kcp_output_cb()]
   │
   │ myproto_build_data_frame() 封装 MyProto 帧
   │ 若 crypto_enabled: myproto_build_data_frame 中加密 → [IV(16) | 密文 | HMAC(32)]
   │ 若 crc_enabled: 附加 CRC32 尾部
   │ 帧结构: [MyProto Hdr(8)] [Payload(N)] [CRC32(4,可选)]
   ▼
[af_packet.c: af_packet_send()]
   │
   │ 附加以太网头: [Eth Hdr(14)] [MyProto Frame]
   │ sendto() → AF_PACKET 套接字
   ▼
Linux 内核 → 网卡驱动 → 物理链路 ────→ 对端
```

### 3.2 接收路径：物理链路 → AF_PACKET → KCP → 客户端

```
物理链路 → 网卡驱动 → BPF 内核过滤器 (仅匹配目标 EtherType)
   │
   ▼
[af_packet.c: af_packet_recv()]
   │
   │ recvfrom() → 剥离以太网头 [Eth Hdr(14)]
   │ 提取 MyProto 帧: [MyProto Hdr(8)] [Payload] [CRC32(4,可选)]
   ▼
[myproto.c: myproto_parse_frame()]
   │
   │ 解析 MyProto 头 → 验证魔数/版本
   │ 若 crc_enabled: myproto_verify_crc() 校验 CRC32
   │ 若加密帧 (MPF_CRYPTO): myproto_process_data_frame() → 解密 + HMAC 验证
   ▼
[channel.c: channel_process_frame()]
   │
   │ 根据 flags 路由:
   │   IS_CTRL_FRAME? → channel_process_ctrl() → 状态机处理
   │   IS_DATA_FRAME? → kcp_wrap_input() → KCP 内部重组
   ▼
[kcp_wrap.c: kcp_wrap_input() → ikcp_input()]
   │
   │ KCP 内部重组、ACK、重传处理
   │ kcp_wrap_recv() 读取已重组完成的用户数据
   ▼
[channel.c → proxy.c: proxy_write_to_local()]
   │
   │ 数据写入 ch->recv_buf → proxy_flush_to_local()
   │ → write() 到 local_fd (TCP/UDP socket)
   ▼
客户端应用 (读取数据)
```

### 3.3 反向代理模式数据流

```
远端客户端 → AF_PACKET → [接收路径] → [KCP重组] → proxy_connect_remote() → 本地服务
本地服务   → [proxy]   → [KCP发送] → [发送路径] → AF_PACKET → 远端客户端
```

---

## 4. 通道状态机

系统采用 7 状态 TCP 风格有限状态机，每个通道独立维护状态。

```
                      ┌──────────┐
                      │  CLOSED  │  ← 初始状态 / 终态
                      └────┬─────┘
                           │
                ┌──────────┴──────────┐
                │                     │
          发起方发送 SYN         响应方收到 SYN
                │                     │
           ┌────▼──────┐       ┌──────▼──────┐
           │  SYN_SENT  │       │  SYN_RCVD   │
           └────┬──────┘       └──────┬──────┘
                │                     │
          收到 ACK              收到首个数据帧
                │                     │
                └──────────┬──────────┘
                           │
                  ┌────────▼─────────┐
                  │   ESTABLISHED    │  ← 稳定数据传输状态
                  └────────┬─────────┘
                           │
                ┌──────────┼──────────┐
                │                     │
        本地主动关闭 FIN        收到对端 FIN
                │                     │
           ┌────▼──────┐       ┌──────▼──────┐
           │  FIN_SENT  │       │  FIN_RCVD   │
           └────┬──────┘       └──────┬──────┘
                │                     │
          收到 FIN              发送 FIN
                │                     │
                └──────────┬──────────┘
                           │
                  ┌────────▼─────────┐
                  │    TIME_WAIT     │  ← 等待 30s (CHANNEL_GRACEFUL_TIMEOUT)
                  └────────┬─────────┘
                           │
                      超时到期
                           │
                  ┌────────▼─────────┐
                  │     CLOSED       │  ← 销毁通道，释放资源
                  └──────────────────┘
```

### 状态转换规则

| 状态 | 值 | 说明 | 触发事件 → 下一状态 |
|------|-----|------|-------------------|
| `CHANNEL_CLOSED` | 0 | 关闭/初始状态 | 发送 SYN → `SYN_SENT`；收到 SYN → `SYN_RCVD` |
| `CHANNEL_SYN_SENT` | 1 | 等待对端 ACK | 收到 ACK → `ESTABLISHED`；超时(重试3次)→ `CLOSED`；收到 RST → `CLOSED` |
| `CHANNEL_SYN_RCVD` | 2 | 已回复 ACK，等待确认 | 收到数据帧 → `ESTABLISHED`；收到 RST → `CLOSED` |
| `CHANNEL_ESTABLISHED` | 3 | 稳定连接，数据传输 | 发送 FIN → `FIN_SENT`；收到 FIN → `FIN_RCVD`；心跳超时 → `CLOSED`；收到 RST → `CLOSED` |
| `CHANNEL_FIN_SENT` | 4 | 等待对端 FIN 确认 | 收到 FIN → `TIME_WAIT`；心跳超时 → `CLOSED`；收到 RST → `CLOSED` |
| `CHANNEL_FIN_RCVD` | 5 | 已收到对端 FIN | 发送 FIN → `TIME_WAIT`；超时 → `TIME_WAIT`；收到 RST → `CLOSED` |
| `CHANNEL_TIME_WAIT` | 6 | 等待 2MSL | 30s 超时 → `CLOSED` (销毁) |

**特殊规则：**
- **RST 强制复位**：任意状态收到 RST 帧 → 直接转换至 `CLOSED` + 立即销毁通道
- **SYN_SENT 超时重试**：默认 3 次重试，全部失败 → `CLOSED`
- **心跳超时**：`ESTABLISHED` 和 `FIN_SENT` 状态下心跳超时 → `CLOSED`

---

## 5. 协议帧格式（字节级图解）

### 5.1 以太网帧布局（线缆字节序，大端）

```
字节偏移:  0              6             12        14
     ┌──────────────┬──────────────┬───────────┬──────────────────────────┐
     │  Dst MAC     │  Src MAC     │ EtherType │  MyProto 负载 (可变长度)  │
     │  (6 字节)     │  (6 字节)     │  (2 字节)  │                          │
     └──────────────┴──────────────┴───────────┴──────────────────────────┘
     ←── 以太网头部 14 字节 ──→│←──── MyProto 帧 (协议头 + 负载 + CRC) ──→│
```

### 5.2 MyProto 协议头（9 字节，大端序）

```
字节偏移:    0..3             4       5..6           7..8
     ┌──────────────┬───────┬───────────┬──────────────┐
     │ channel_id   │ flags │payload_len│ header_crc   │
     │  (u32, BE)   │ (u8)  │ (u16, BE) │ (u16, BE)    │
     ├──────────────┼───────┼───────────┼──────────────┤
     │  1 ~ 2³²-1   │ 见下表│  0 ~ 65535 │ CRC-16/CCITT │
     └──────────────┴───────┴───────────┴──────────────┘

channel_id  = 通道标识符（4 字节，网络字节序），0 号保留
flags       = 帧标志位（位掩码），1 字节
payload_len = 有效负载长度（2 字节，网络字节序），不含 CRC32
header_crc  = 帧头 CRC-16/CCITT（2 字节，多项式 0x1021）
              覆盖前 7 字节（channel_id + flags + payload_len）
              构建时计算，解析时校验，CRC 不匹配 → 直接丢弃
```

### 5.3 帧标志位定义（位掩码）

```
Bit:   7         6         5         4        3       2       1       0
   ┌─────────┬─────────┬─────────┬─────────┬───────┬───────┬───────┬───────┐
   │ CRYPTO  │  PONG   │  PING   │   RST   │  FIN  │  ACK  │  SYN  │ DATA  │
   │  0x40   │  0x20   │  0x10   │  0x08   │ 0x04  │ 0x02  │ 0x01  │ 0x00  │
   └─────────┴─────────┴─────────┴─────────┴───────┴───────┴───────┴───────┘

MPF_DATA   = 0x00   纯数据帧（无控制标志）
MPF_SYN    = 0x01   通道建立请求
MPF_ACK    = 0x02   通道建立确认
MPF_FIN    = 0x04   通道关闭请求
MPF_RST    = 0x08   强制复位
MPF_PING   = 0x10   心跳探测
MPF_PONG   = 0x20   心跳响应
MPF_CRYPTO = 0x40   加密标志（SM4-CBC + HMAC-SM3）

MPF_CTRL_MASK = 0x3F  (SYN|ACK|FIN|RST|PING|PONG)
IS_CTRL_FRAME(flags) = (flags & 0x3F) != 0
IS_DATA_FRAME(flags) = (flags & 0x3F) == 0
IS_CRYPTO_FRAME(flags) = (flags & 0x40) != 0
```

### 5.4 完整帧结构总结

#### 明文数据帧（crypto=off, crc=on）

```
┌─ 以太网头 (14) ─┬─ MyProto头 (8) ─┬─── 负载 (data_len, 0~1500) ───┬─ CRC32 (4) ─┐
│ dst(6)│src(6)│ET│magic│ver│flg│chid│len│  raw_data (N bytes)       │  CRC32 (LE)  │
└─────────────────┴──────────────────┴──────────────────────────────┴──────────────┘
最小帧: 14 + 8 + 0 + 4 = 26 字节
最大帧: 14 + 8 + 1500 + 4 = 1526 字节
```

#### 加密数据帧（crypto=on, crc=on）

```
┌─ 以太网头 (14) ─┬─ MyProto头 (8) ─┬────────────────── 加密负载 ──────────────────┬─ CRC32 (4) ─┐
│ dst(6)│src(6)│ET│hdr(8), flg=0x40│ IV(16) │ SM4-CBC 密文(16B对齐) │ HMAC(32) │  CRC32 (LE)  │
└─────────────────┴──────────────────┴────────┴───────────────────────┴──────────┴──────────────┘
加密开销: 16(IV) + 32(HMAC) = 48 字节
带加密最大帧: 14 + 8 + 1500 + 48 + 4 = 1574 字节
```

#### 控制帧（无负载，无 CRC）

```
┌─ 以太网头 (14) ─┬─ MyProto头 (8) ─┐
│ dst(6)│src(6)│ET│hdr(8), data_len=0│
└─────────────────┴──────────────────┘
控制帧固定大小: 14 + 8 = 22 字节
```

---

## 6. 通道哈希表设计

### 数据结构

```
global_ctx_t
  ├── channel_hash: channel_t**     (桶指针数组)
  ├── channel_hash_size: uint32_t   (桶数量)
  └── channel_count: int            (当前活跃通道数)

channel_t
  ├── channel_id: uint16_t          (哈希键)
  ├── state: channel_state_t        (通道状态)
  ├── kcp: struct IKCPCB*           (KCP 实例)
  ├── ...                           (网络参数、缓冲区、统计)
  └── hash_next: struct channel_s*  (冲突链表指针)
```

### 哈希策略

- **哈希函数**: `hash = channel_id % channel_hash_size`（取模法）
- **冲突解决**: 链地址法（Separate Chaining），每个桶指向一个 `channel_t` 单向链表
- **桶数量**: `max_channels * 2`，限制在 `[64, 65535]` 范围内
- **默认值**: `CHANNEL_HASH_SIZE_DEFAULT = 1024`
- **装载因子**: 理想情况下 < 0.5，保证 O(1) 查找效率
- **查找复杂度**: 平均 O(1)，最坏 O(n)（链长受 max_channels 限制）

```
channel_hash (channel_t**)
  │
  ├── [0] → NULL
  ├── [1] → ch(id=1) → ch(id=1025) → NULL    ← 冲突链
  ├── [2] → NULL
  ├── ...
  ├── [257] → ch(id=257) → NULL
  ├── ...
  └── [hash_size-1] → NULL
```

### 帧路由流程

```
channel_process_frame(ctx, hdr, payload, payload_len)
  │
  ├── IS_CTRL_FRAME(hdr->flags)?
  │     ├── hdr->channel_id == HEARTBEAT_CH_ID (0xFFFF)?
  │     │     └── channel_heartbeat_handler() — 全局心跳处理
  │     └── else:
  │           ├── channel_find(ctx, channel_id) → 找已有通道
  │           │     └── 找到 → channel_process_ctrl(ch, flags) → 状态机
  │           └── 未找到:
  │                 ├── MPF_SYN? → 检查 channel_lookup_config()
  │                 │     └── 配置中有 → channel_create() → SYN_RCVD
  │                 │     └── 配置中无 → 丢弃帧
  │                 └── 其他控制帧 → 丢弃
  │
  └── IS_DATA_FRAME(hdr->flags)?
        └── channel_find(ctx, channel_id)
              ├── 找到 && state == ESTABLISHED? → kcp_wrap_input()
              ├── 找到 && state == SYN_RCVD? → 升级为 ESTABLISHED → 处理数据
              └── 未找到 → 丢弃帧
```

---

## 7. Epoll 事件模型

### 架构

```
epoll_fd (epoll_create1(EPOLL_CLOEXEC))
  │
  ├── [FD: raw_sock]    — AF_PACKET 原始套接字 (EPOLLIN | EPOLLET)
  │     触发: 有以太网帧到达 (经 BPF 过滤)
  │     处理: af_packet_recv() → myproto_parse_frame() → channel_process_frame()
  │
  ├── [FD: listen_fd_1] — 通道 1 的 TCP 监听套接字 (EPOLLIN | EPOLLET)
  │     触发: 新客户端连接
  │     处理: proxy_accept() → 建立 local_fd → 加入 epoll
  │
  ├── [FD: listen_fd_N] — 通道 N 的 TCP 监听套接字
  │
  ├── [FD: local_fd_A]  — 客户端连接套接字 (EPOLLIN | EPOLLET, 动态注册)
  │     触发: 客户端发送数据或对端关闭
  │     处理: proxy_handle_local_read() 或 EPOLLERR/EPOLLHUP
  │
  └── [FD: local_fd_B]  — 另一个客户端连接套接字
        触发: KCP 数据就绪后可能需要 EPOLLOUT 事件
```

### 事件处理流程

```
epoll_wait(epoll_fd, events, MAX_EVENTS=64, timeout=10ms)
  │
  ├── for each triggered event:
  │     ├── fd == raw_sock?        → af_packet_recv() → 帧处理
  │     ├── fd == listen_fd?       → proxy_accept() → 新连接
  │     ├── fd == local_fd (EPOLLIN)? → proxy_handle_local_read()
  │     ├── fd == local_fd (EPOLLOUT)?→ proxy_handle_local_write()
  │     └── fd == local_fd (EPOLLERR/EPOLLHUP)? → proxy_close_local()
  │
  └── 周期性任务 (每 ~10ms):
        ├── channel_kcp_update() — 驱动所有 KCP 实例 ikcp_update()
        ├── channel_heartbeat()  — 空闲通道发送 PING
        ├── channel_timeout_check() — 超时通道清理
        └── 统计输出 (每 60 秒)
```

### Epoll 参数

| 参数 | 值 | 说明 |
|------|-----|------|
| `EPOLL_MAX_EVENTS` | 64 | 每次 epoll_wait 最大返回事件数 |
| `EPOLL_TIMEOUT_MS` | 10 | epoll_wait 超时 (ms)，也作为周期任务间隔 |
| `PERIODIC_INTERVAL_MS` | 10 | KCP 更新/心跳/超时检查间隔 (ms) |
| `MAX_FRAMES_PER_CYCLE` | 64 | 单周期最大处理帧数，防饥饿 |
| 触发模式 | EPOLLET | 边缘触发 (Edge-Triggered)，高性能非阻塞 I/O |

---

## 8. 加密管线

### 加密算法组合

| 层 | 算法 | 标准 | 用途 |
|----|------|------|------|
| 对称加密 | SM4-CBC | GB/T 32907-2016 | 128-bit 分组密码，CBC 模式，PKCS7 填充 |
| 消息认证 | SM3-HMAC | GB/T 32905-2016 | 256-bit 哈希消息认证码 |
| 随机数 | /dev/urandom | Linux 内核熵池 | 每帧独立 16 字节 IV |
| 密钥派生 | HMAC-SM3 | - | `g_hmac_key = HMAC-SM3(key="KCP-HMAC", message=sm4_key)` |
| 底层库 | GNU Nettle | libnettle | SM4、CBC、HMAC 实现 |

### 加密帧线格式

```
┌───────┬──────────────────────┬────────────────┐
│  IV   │  SM4-CBC Ciphertext  │  SM3-HMAC      │
│ 16 B  │  (PKCS7 padded, N)   │  32 B          │
└───────┴──────────────────────┴────────────────┘
  │                              │
  └── HMAC 计算域 ──────────────┘
  (HMAC 覆盖 [IV | Ciphertext])
```

### 加密流程（发送方向）

```
明文 in[in_len]
  │
  ├── 1. 从 /dev/urandom 读取 16 字节随机 IV
  ├── 2. PKCS7 填充：pad = 16 - (in_len % 16)，追加 pad 字节 (每字节值为 pad)
  ├── 3. SM4-CBC 加密 (使用 g_enc_ctx，独立轮密钥上下文)
  ├── 4. SM3-HMAC 计算：覆盖 [IV | 密文] (使用 g_hmac_key)
  └── 5. 组装输出：out = [IV(16) | Ciphertext(N) | HMAC(32)]
```

### 解密流程（接收方向）

```
加密帧 in[in_len]
  │
  ├── 1. 边界检查：in_len ≥ 48 (16+32)，密文长度 > 0 且 16 字节对齐
  ├── 2. 提取 IV (前 16 字节)，计算期望 HMAC
  ├── 3. HMAC 校验：memcmp(期望HMAC, 帧内HMAC, 32) → 失败: 丢弃帧
  ├── 4. SM4-CBC 解密 (使用 g_dec_ctx，与加密分离)
  ├── 5. PKCS7 去填充：检查 pad 值范围 [1,16] + 逐字节一致性验证
  └── 6. 返回明文数据
```

### 安全设计要点

1. **IV 随机性**：每帧独立 16 字节随机 IV，杜绝固定 IV 或计数器 IV 的重放攻击
2. **密钥分离**：SM4 加密/解密使用独立轮密钥上下文（`g_enc_ctx` / `g_dec_ctx`）；HMAC 密钥从 SM4 密钥独立派生
3. **Encrypt-then-MAC**：先加密，后计算 HMAC；解密时先验证 HMAC，后解密——最早发现篡改，防止 padding oracle 攻击
4. **临时密钥擦除**：`crypto_init()` 结束后 `memset` 清零栈上临时密钥；`crypto_cleanup()` 擦除所有全局密钥材料
5. **PKCS7 完整校验**：去填充时逐字节验证，防止 padding oracle

### 已知限制

- `memcmp` 非恒定时间实现，理论上存在 timing leak（LAN 威胁模型下可接受）
- 不支持 AEAD 模式（如 GCM），无法提供关联数据认证
- IV 生成依赖 `/dev/urandom` 设备节点，容器/沙箱环境需确保可用

---

## 9. 节点类型（Frontend/Backend）

### Frontend（前端节点）

```
角色: 面向客户端，接收来自本地应用的 TCP/UDP 连接
行为:
  - 在本地 listen_addr:listen_port 上监听
  - accept() 客户端连接 → 创建 local_fd
  - 从 local_fd 读取数据 → 经 KCP → AF_PACKET 发送到 Backend
  - 从 AF_PACKET 接收数据 → 经 KCP → write() 到 local_fd
  - 发起通道建立: 发送 SYN
  - channel_role = INITIATOR
```

### Backend（后端节点）

```
角色: 面向服务端，将隧道数据转发到本地服务
行为:
  - 从 AF_PACKET 接收数据 → 经 KCP → connect() 到本地服务
  - 从本地服务读取响应 → 经 KCP → AF_PACKET 发送回 Frontend
  - 接受通道建立: 收到 SYN → 回复 ACK
  - channel_role = RESPONDER
```

### 配置中的体现

```json
{
    "node_type": "frontend"   // 或 "backend"
}
```

前端/后端决定的是连接发起方向和代理行为，同一二进制通过配置切换角色。一个典型部署中，Frontend 在客户端侧，Backend 在服务端侧。

---

## 10. 关键常量及其含义

### MyProto 协议常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `MYPROTO_MAGIC` | `0x4D50` | 帧识别魔数 ('M''P') |
| `MYPROTO_VERSION` | `0x01` | 协议版本 |
| `MYPROTO_HDR_SIZE` | `8` | 协议头大小（字节） |
| `MYPROTO_ETHERTYPE` | `0x88B5` | 自定义 EtherType（十进制 35013） |

### 帧标志位

| 常量 | 值 | 说明 |
|------|-----|------|
| `MPF_DATA` | `0x00` | 数据帧 |
| `MPF_SYN` | `0x01` | 连接建立请求 |
| `MPF_ACK` | `0x02` | 连接建立确认 |
| `MPF_FIN` | `0x04` | 连接关闭请求 |
| `MPF_RST` | `0x08` | 强制复位 |
| `MPF_PING` | `0x10` | 心跳探测 |
| `MPF_PONG` | `0x20` | 心跳响应 |
| `MPF_CRYPTO` | `0x40` | 加密标志 |
| `MPF_CTRL_MASK` | `0x3F` | 控制帧掩码 |

### 以太网常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `ETH_HDR_SIZE` | `14` | 以太网头部（不含 VLAN） |
| `ETH_MTU` | `1500` | 标准以太网 MTU |
| `ETH_MAX_PAYLOAD` | `1500` | 最大以太网载荷 |
| `MAX_FRAME_SIZE` | `1550` | 最大帧缓冲（含加密开销） |
| `ETH_MAC_ADDR_LEN` | `6` | MAC 地址长度 |

### KCP 参数

| 常量 | 值 | 说明 |
|------|-----|------|
| `KCP_MTU_CONSERVATIVE` | `1400` | 保守 KCP MTU（MSS=1376） |
| `KCP_MTU_PERFORMANCE` | `1478` | 高性能 KCP MTU（MSS=1454） |
| `KCP_SEND_WINDOW` | `1024` | 默认发送窗口 |
| `KCP_RECV_WINDOW` | `1024` | 默认接收窗口 |
| `KCP_NODELAY` | `1` | 启用 nodelay 模式 |
| `KCP_INTERVAL` | `10` | KCP 内部更新间隔 (ms) |
| `KCP_RESEND` | `2` | 快速重传阈值 |
| `KCP_NC` | `1` | 禁用拥塞控制 |

### 通道常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `MAX_CHANNELS` | `4096` | 最大通道配置数 |
| `CHANNEL_HASH_SIZE_DEFAULT` | `1024` | 默认哈希表大小 |
| `CHANNEL_RECV_BUF_SIZE` | `8192` | 通道接收缓冲区（8KB） |
| `CHANNEL_ID_STATIC_MIN` | `1` | 静态通道 ID 最小值 |
| `HEARTBEAT_CH_ID` | `0xFFFF` | 全局心跳通道 ID（特殊保留值） |

### 超时与心跳

| 常量 | 值 | 说明 |
|------|-----|------|
| `HEARTBEAT_INTERVAL` | `10` | 心跳发送间隔（秒） |
| `HEARTBEAT_TIMEOUT` | `60` | 心跳超时（秒） |
| `CHANNEL_IDLE_TIMEOUT` | `300` | 通道空闲超时（秒） |
| `CHANNEL_GRACEFUL_TIMEOUT` | `30` | TIME_WAIT 优雅关闭超时（秒） |

### 加密常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `SM4_KEY_SIZE` | `16` | SM4 密钥长度（128 位） |
| `SM4_IV_SIZE` | `16` | SM4-CBC IV 长度 |
| `SM3_HMAC_SIZE` | `32` | SM3-HMAC 输出长度 |
| `CRYPTO_OVERHEAD` | `48` | 加密总开销 (IV+HMAC) |

### 其他常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `AF_PACKET_FRAME_SIZE` | `1600` | AF_PACKET 帧缓冲区 |
| `BPF_FILTER_MAX` | `256` | BPF 过滤器最大长度 |
| `MAX_LISTEN_ADDR` | `64` | 监听地址最大长度 |
| `MAX_REMOTE_ADDR` | `64` | 远端地址最大长度 |
| `MAX_INTERFACE_NAME` | `32` | 网卡名称最大长度 (`IFNAMSIZ`) |

---

## 11. MTU 预算分析

```
以太网 MTU (ETH_MTU):                                    1500 字节
  ├── 以太网头 (ETH_HDR_SIZE):                             14 字节
  ├── MyProto 协议头 (MYPROTO_HDR_SIZE):                    8 字节
  ├── 可用负载空间 (ETH_MTU - HDR):                       1478 字节
  │     ├── 若启用加密 (CRYPTO_OVERHEAD):                  -48 字节 (IV+HMAC)
  │     │     └── 实际可用:                                1430 字节
  │     └── 若明文模式:
  │           ├── 若启用 CRC (CRC32_SIZE):                  -4 字节
  │           │     └── 实际可用:                           1474 字节
  │           └── 若不启用 CRC:
  │                 └── 实际可用:                           1478 字节
  └── 总结:
        KCP MTU 保守值 = 1400 (留足余量)
        KCP MTU 高性能 = 1478 (充分利用带宽，明文无 CRC)
```

| 配置组合 | KCP MTU | KCP MSS | 加密开销 | CRC | 实际数据承载 |
|---------|---------|---------|---------|------|-------------|
| 保守 + 明文 + CRC | 1400 | 1376 | 0 | 4 | 1372 |
| 保守 + 加密 + CRC | 1400 | 1376 | 48 | 4 | 1324 |
| 高性能 + 明文 + 无CRC | 1478 | 1454 | 0 | 0 | 1454 |
| 高性能 + 加密 + 无CRC | 1478 | 1454 | 48 | 0 | 1406 |

---

## 12. 主事件循环

```
main_loop():
  │
  ├── while (ctx.running):
  │     │
  │     ├── epoll_wait(epoll_fd, events, 64, 10ms)
  │     │     │
  │     │     └── for each event:
  │     │           ├── fd == raw_sock (EPOLLIN):
  │     │           │     └── loop (max 64 frames):
  │     │           │           af_packet_recv() → myproto_parse_frame()
  │     │           │           → channel_process_frame()
  │     │           │
  │     │           ├── fd == listen_fd (EPOLLIN):
  │     │           │     └── proxy_accept() → 建立 local_fd → epoll_ctl(ADD)
  │     │           │
  │     │           └── fd == local_fd:
  │     │                 ├── EPOLLIN  → proxy_handle_local_read()
  │     │                 ├── EPOLLOUT → proxy_handle_local_write()
  │     │                 └── EPOLLERR/EPOLLHUP → proxy_close_local()
  │     │
  │     ├── 周期任务 (每 ~10ms):
  │     │     ├── channel_kcp_update(ctx)      — ikcp_update() 驱动所有 KCP 实例
  │     │     ├── channel_heartbeat(ctx)       — 空闲通道发送 PING
  │     │     └── channel_timeout_check(ctx)   — 超时通道清理/回收
  │     │
  │     ├── 统计输出 (每 60s):
  │     │     └── 打印 tx/rx 帧数/字节数/错误数
  │     │
  │     └── 配置热重载 (SIGHUP):
  │           └── 若 reload_requested → 重新加载配置文件
  │
  └── cleanup():
        ├── channel_close_all() — 所有通道发送 FIN，优雅关闭
        ├── KCP 缓冲区排空 (最多等待 5s)
        ├── crypto_cleanup() — 擦除密钥材料
        ├── proxy_shutdown() — 关闭所有套接字
        ├── channel_shutdown() — 释放哈希表和所有通道
        └── af_packet_close() — 关闭原始套接字
```

---

## 13. 连接建立与断开流程

### TCP 三次握手等价流程（KCP 通道建立）

```
Frontend (Initiator)                          Backend (Responder)
       │                                              │
       │  ──────── SYN (ch_id=X) ────────────────►    │
       │  state: CLOSED → SYN_SENT                    │ state: CLOSED → SYN_RCVD
       │                                              │
       │  ◄──────── ACK (ch_id=X) ────────────────    │
       │  state: SYN_SENT → ESTABLISHED               │
       │                                              │
       │  ──────── DATA (ch_id=X) ───────────────►    │
       │                                              │ state: SYN_RCVD → ESTABLISHED
       │  ◄──────── DATA (ch_id=X) ────────────────   │
       │                                              │
       │         [双向数据传输]                         │
```

### 四次挥手等价流程（KCP 通道关闭）

```
Frontend (主动关闭方)                         Backend (被动关闭方)
       │                                              │
       │  ──────── FIN (ch_id=X) ────────────────►    │
       │  state: ESTABLISHED → FIN_SENT               │ state: ESTABLISHED → FIN_RCVD
       │                                              │
       │  ◄──────── FIN (ch_id=X) ────────────────    │
       │  state: FIN_SENT → TIME_WAIT                 │ state: FIN_RCVD → TIME_WAIT
       │                                              │
       │  [等待 30s]                                   │ [等待 30s]
       │  state: TIME_WAIT → CLOSED                   │ state: TIME_WAIT → CLOSED
```

### RST 强制断开

```
任意一方                                   另一方
       │                                              │
       │  ──────── RST (ch_id=X) ────────────────►    │
       │  state: ANY → CLOSED + destroy              │ state: ANY → CLOSED + destroy
```

---

## 附录

### 启动序列（17 步骤）

1. 命令行参数解析（`-v`/`--version`、`-h`/`--help`、配置文件路径）
2. 初始化全局上下文（`memset` 清零，`raw_sock=-1`，`epoll_fd=-1`，`running=1`）
3. 加载 JSON 配置文件（`config_load`）
4. 验证配置（`validate_config`）
5. 初始化加密模块（`crypto_init`）
6. 安装信号处理器（`SIGINT/SIGTERM → running=0`，`SIGHUP → reload_requested=1`，`SIGPIPE → 忽略`）
7. 初始化代理子系统（`proxy_init`，创建 epoll 实例）
8. 初始化通道子系统（`channel_init`，分配哈希表）
9. 创建 AF_PACKET 原始套接字（`af_packet_create`，TPACKET_V2）
10. 获取本地 MAC 地址（`af_packet_get_mac`）
11. 确定对端 MAC 地址（配置或广播 `ff:ff:ff:ff:ff:ff`）
12. 可选自动设置 NIC MTU（`SIOCSIFMTU`）
13. 设置 BPF 过滤器（仅接收目标 EtherType）
14. 创建通道并启动代理监听（`channel_create` + `proxy_start_listen`）
15. 将 AF_PACKET 套接字加入 epoll
16. 主事件循环
17. 清理退出

### 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | C (GNU11/C11) |
| 构建系统 | GNU Make（自动依赖追踪） |
| 链路层 | Linux AF_PACKET + TPACKET_V2 |
| 可靠传输 | KCP (ikcp) |
| 序列化 | JSON (libjson-c) |
| 加密 | SM4-CBC + SM3-HMAC (GNU Nettle) |
| I/O 模型 | epoll 边缘触发 (EPOLLET) |
| 包过滤 | BPF (Berkeley Packet Filter) |
| 编译选项 | `-Wall -Wextra -Werror -std=gnu11 -D_GNU_SOURCE -O2` |
| 链接库 | `-ljson-c -lrt -lnettle` |
