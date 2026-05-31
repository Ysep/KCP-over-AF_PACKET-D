# KCP-over-AF_PACKET-D 术语表 (Glossary)

## A

| 术语 | 英文 | 定义 |
|------|------|------|
| **AF_PACKET** | AF_PACKET Socket | Linux 原始套接字类型，允许用户态程序绕过内核协议栈直接收发链路层（L2）以太网帧。本系统使用 TPACKET_V2 环形缓冲区模式实现零拷贝收发。 |
| **accept** | accept(2) | 系统调用，TCP 服务端从监听套接字的待连接队列中取出一条已完成三次握手的客户端连接，返回对应的新文件描述符。 |
| **ACK 帧** | ACK Frame | 控制帧类型（MPF_ACK），响应方收到 SYN 并成功建立连接后发送，标志多会话通道已就绪。 |
| **alloc_channel_id** | Channel ID Allocator | 动态通道 ID 分配器。从 `listener_base[idx]` 开始，循环扫描 `max_sessions` 个槽位，返回第一个未被占用的 ID。O(max_sessions) 时间复杂度。 |

## B

| 术语 | 英文 | 定义 |
|------|------|------|
| **Backend** | Backend Proxy | 后端代理节点。运行在目标服务所在网络的出口机器上，负责接受 AF_PACKET 隧道中的请求并转发至实际 TCP/UDP 服务。对应 `NODE_TYPE_BACKEND`。 |
| **BPF** | Berkeley Packet Filter | AF_PACKET 的内核级包过滤器。本系统使用 BPF 按 EtherType（0x88B5）过滤，只接收本协议帧，减少内核-用户态拷贝。 |
| **build_listener_bases** | Listener Base Builder | 启动时执行的初始化函数，为每个静态 listener 在 `listener_base[]` 数组中分配连续 ID 区间，区间宽度 = `max_sessions`。 |

## C

| 术语 | 英文 | 定义 |
|------|------|------|
| **channel** | Channel | 通道，系统核心抽象。每个通道拥有独立的 KCP 实例、本地 TCP/UDP 套接字、以及网络层参数（MAC 地址、EtherType）。 |
| **channel_config_changed** | Config Change Detector | 比较新旧通道配置的辅助函数，比较 5 个字段（listen_port、remote_port、listen_addr、remote_addr、is_tcp），任一不同即返回 1。 |
| **channel_create** | Channel Factory | 通道工厂函数。根据角色（LISTENER/INITIATOR/RESPONDER）采用不同的初始化路径：LISTENER 进入 ESTABLISHED，INITIATOR 发送 SYN，RESPONDER 进入 SYN_RCVD。 |
| **channel_destroy** | Channel Destructor | 通道销毁函数。清理顺序：从哈希表移除 → 关闭 KCP → 关闭 local_fd → 关闭 listen_fd（非静态通道） → 释放内存。静态 listener 的 listen_fd 受 `CH_FLAG_STATIC_LISTENER` 保护。 |
| **channel_id** | Channel Identifier | 通道唯一标识符，v2.0 起为 `uint32_t` 类型。静态配置通道使用小 ID（1~65535），动态数据通道使用 `≥65536` 的大 ID。 |
| **channel_lookup_config** | Config Lookup | 在 `channels[]` 配置数组中通过 channel_id 查找对应的通道配置。对动态 ID（≥65536）返回 NULL，需要调用者使用反向扫描 `listener_base` 区间回退查找。 |
| **channel_timeout_check** | Timeout Check | 周期性执行的心跳超时检查。遍历哈希表所有通道，跳过 STATIC_LISTENER 通道，对超时未收到心跳的数据通道发起 RST 关闭。 |
| **CH_FLAG_RELOAD_MARKED** | Reload Marker Flag | 通道标志位（0x02），仅在 `config_reload_channels()` 流程中临时使用。标记旧 listener 以便与新配置匹配，未匹配到的（仍带标记）将被销毁。 |
| **CH_FLAG_STATIC_LISTENER** | Static Listener Flag | 通道标志位（0x01）。标记由配置文件创建的静态监听通道，保护其 listen_fd 不被 channel_destroy 关闭，被 timeout_check 跳过。 |
| **CHANNEL_ROLE_INITIATOR** | Initiator Role | 通道角色。由 frontend 的 `proxy_accept` 在 TCP accept 后以动态 ID 创建，通道建立后主动发送 SYN 帧。 |
| **CHANNEL_ROLE_LISTENER** | Listener Role | 通道角色。仅负责监听本地端口并 accept 新连接，不承载数据，不发送 SYN，不参与定时超时检测。 |
| **CHANNEL_ROLE_RESPONDER** | Responder Role | 通道角色。由 backend 收到 SYN 帧后以动态 ID 创建，负责连接目标服务并回复 ACK。 |
| **CRC** | Cyclic Redundancy Check | 帧头校验和（2 字节），覆盖帧头前 7 字节。用于快速检测帧损坏和协议不匹配。 |
| **config_reload** | Configuration Reload | SIGHUP 触发的配置热重载。分两阶段：第一阶段调用 `config_reload_channels()` 做通道 diff，第二阶段刷新 KCP/加密等软参数。 |
| **config_reload_channels** | Channel Reload Engine | 通道热重载核心函数。四步算法：Step1 标记所有 listener → Step2 遍历新配置 diff 增删改 → Step3 清理未匹配旧 listener → Step4 重建 channels[] 数组（保留 disabled 条目）。 |

## D

| 术语 | 英文 | 定义 |
|------|------|------|
| **动态通道** | Dynamic Channel | 运行时由 accept（INITIATOR）或收到 SYN（RESPONDER）动态创建的通道。channel_id 从 listener 的 ID 池中分配，生命周期与 TCP 连接绑定。 |
| **DYNAMIC_CHANNEL_BASE** | Dynamic Channel ID Base | 动态通道 ID 起始值，固定为 65536。所有动态分配的 channel_id 均 ≥ 此值。 |
| **动态 ID 回退** | Dynamic ID Fallback | RESPONDER 收到 SYN 时，若 `channel_lookup_config` 未匹配到配置（channel_id ≥ 65536），则反向扫描 `listener_base[]` 找到所属 listener 以获取路由配置。 |

## E

| 术语 | 英文 | 定义 |
|------|------|------|
| **epoll** | epoll(7) | Linux I/O 事件通知机制。本系统使用边缘触发（EPOLLET）模式，一个 epoll 实例管理所有通道的 TCP/UDP 套接字和 AF_PACKET 套接字。 |
| **EtherType** | Ethernet Type | 以太网帧类型字段（2 字节）。本系统默认使用 0x88B5（IEEE 实验类型），可在配置中自定义。 |

## F

| 术语 | 英文 | 定义 |
|------|------|------|
| **FIN 帧** | FIN Frame | 控制帧类型（MPF_FIN），发起连接关闭的"四次挥手"。收到 FIN 后进入 TIME_WAIT 状态，短暂延迟后销毁。 |
| **Frontend** | Frontend Proxy | 前端代理节点。运行在客户端可达网络的入口机器上，负责监听端口、接受客户端连接、通过 AF_PACKET 隧道转发至 Backend。对应 `NODE_TYPE_FRONTEND`。 |

## H

| 术语 | 英文 | 定义 |
|------|------|------|
| **handle_channel_ctl** | Channel Control Handler | SIGUSR1 触发的快速通道增删处理函数。读取 `config-ctl.json`，解析 JSON 中的 `add`/`del` 操作，执行定点 O(1) 通道操作。 |
| **HEARTBEAT_CH_ID** | Heartbeat Channel ID | 心跳帧专用的特殊 channel_id，v2.0 起为 0xFFFFFFFF。接收方识别后触发心跳处理流程，更新全局心跳时间戳。 |
| **heartbeat** | Heartbeat | 保活心跳机制。按 `heartbeat_interval` 周期性发送心跳控制帧（MPF_HEARTBEAT），若 `heartbeat_timeout` 秒内未收到对方心跳则判定对端离线。 |

## I

| 术语 | 英文 | 定义 |
|------|------|------|
| **ID 池** | ID Pool | 每个静态 listener 的动态通道 ID 池。池大小 = `max_sessions`，区间从 `listener_base[idx]` 起连续排列，通过 `listener_next[idx]` 循环分配。 |

## K

| 术语 | 英文 | 定义 |
|------|------|------|
| **KCP** | KCP Protocol | 快速可靠传输协议（KCP — A Fast and Reliable ARQ Protocol）。在 UDP 风格不可靠链路上提供可靠、有序的数据交付，支持流量控制和前向纠错。本系统每个数据通道独占一个 KCP 实例。 |

## L

| 术语 | 英文 | 定义 |
|------|------|------|
| **listen_fd** | Listen File Descriptor | 静态 listener 的 TCP/UDP 监听套接字。仅用于 accept 新连接，不承载数据。生命周期受 `CH_FLAG_STATIC_LISTENER` 保护，与进程同寿。 |
| **listener** | Listener Channel | 静态监听通道，由配置文件 `channels[]` 定义。角色固定为 `CHANNEL_ROLE_LISTENER`，标志位固定为 `CH_FLAG_STATIC_LISTENER`。 |
| **listener_base** | Listener ID Base | 全局数组 `listener_base[MAX_CHANNELS]`，存储每个 listener 的动态 ID 池起始偏移（≥65536）。 |
| **listener_idx** | Listener Array Index | 静态 listener 在 `channels[]` 数组中的下标（从 0 起）。动态通道继承自其所属 listener 的 idx，用于反向找到配置信息。 |
| **listener_next** | Listener Next ID | 全局数组 `listener_next[MAX_CHANNELS]`，存储每个 listener 的下一个待分配动态 channel_id。循环递增，到达池上限后回绕至 base。 |
| **local_fd** | Local File Descriptor | 通道的本地 TCP/UDP 连接套接字。对于 LISTENER 始终为 -1，对于 INITIATOR 为 accept 得到的客户端 fd，对于 RESPONDER 为 connect 到目标服务的 fd。 |

## M

| 术语 | 英文 | 定义 |
|------|------|------|
| **MAC** | Media Access Control Address | 以太网 6 字节物理地址。本系统在 AF_PACKET 帧中直接填充源/目的 MAC，支持手动配置或自动学习（auto-learn）。 |
| **max_channels** | Max Channels | 全局最大通道数（默认 65536）。限制哈希表可存储的通道总数，包括静态 listener 和动态数据通道。 |
| **max_sessions** | Max Sessions Per Listener | 每个 listener 端口允许的最大并发会话数（1~65535）。同时决定该 listener 的 ID 池大小。默认 1（单会话向后兼容）。 |
| **MTU** | Maximum Transmission Unit | 最大传输单元。本系统涉及两层：NIC MTU（链路层，默认 1500）和 KCP MTU（协议层，默认 1400），确保 KCP 分段后不超过以太网帧承载上限。 |
| **MyProto** | MyProto Frame Protocol | 本系统自定义的 AF_PACKET 帧封装协议。v2.0 帧头 9 字节：channel_id(4B) + flags(1B) + payload_len(2B) + header_crc(2B)。 |
| **myproto_hdr_t** | MyProto Header | MyProto 帧头结构体。使用 `__attribute__((packed))` 确保紧密排列，`_Static_assert` 确保 sizeof == 9。 |

## N

| 术语 | 英文 | 定义 |
|------|------|------|
| **next_dynamic_channel_id** | Next Dynamic ID | 全局上下文字段（v2.0 已废弃）。保留字段，实际分配由 `listener_next[]` 按 listener 独立管理。 |
| **NODE_TYPE** | Node Type | 节点类型配置。FRONTEND = 1（接收客户端连接），BACKEND = 2（转发至目标服务）。 |

## O

| 术语 | 英文 | 定义 |
|------|------|------|
| **O(1) 通道控制** | O(1) Channel Control | SIGUSR1 触发的定点通道增删操作。通过哈希表查找目标 channel_id 实现常数时间复杂度，无需遍历所有通道。 |

## P

| 术语 | 英文 | 定义 |
|------|------|------|
| **proxy_accept** | Accept Handler | TCP 连接接受处理函数。多会话模式下为每个 accept 创建 INITIATOR 通道，单会话模式下绑定到 listener 自身（向后兼容）。 |
| **proxy_close_local** | Local FD Closer | 关闭通道本地套接字。关闭 local_fd（数据连接），若 listen_fd ≠ local_fd 也关闭 listen_fd（非静态情况下）。清空接收缓冲区。 |
| **proxy_connect_remote** | Remote Connector | 远端连接建立函数。Backend 侧为 RESPONDER 通道创建 socket 并非阻塞 connect 到 remote_addr:remote_port。 |
| **proxy_epoll_add / proxy_epoll_del** | Epoll Registration | epoll 事件注册/注销辅助函数。使用 EPOLLET（边缘触发）模式，注册 EPOLLIN / EPOLLOUT / EPOLLERR 事件。 |
| **proxy_handle_event** | Event Dispatcher | epoll 事件分发器。根据 fd 类型（AF_PACKET / listen_fd / local_fd）和事件类型（EPOLLIN / EPOLLOUT / EPOLLERR）路由到对应的读/写处理函数。 |
| **proxy_port_conflict** | Port Conflict Detector | 端口冲突检测函数。遍历哈希表所有 STATIC_LISTENER 通道，比较 listen_addr 和 listen_port 判断是否冲突。用于热重载时预检。 |
| **proxy_port_probe** | Port Prober | 端口可用性预检函数。创建临时 socket → bind → 成功后立即 close。用于热重载修改通道前确保新端口可用。 |
| **proxy_start_listen** | Listen Starter | TCP/UDP 监听启动函数。创建 socket → SO_REUSEADDR → bind → listen → epoll 注册。Frontend 侧由 listener 通道调用。 |
| **proxy_stop_listen** | Listen Stopper | 监听优雅关闭函数。仅关闭 listen_fd 并从 epoll 移除，不销毁动态子通道（数据通道独立于 listener 运行）。 |

## R

| 术语 | 英文 | 定义 |
|------|------|------|
| **RESPONDER 反向映射** | Responder Reverse Mapping | Backend 收到 SYN 时，若 data_id ≥ 65536，通过反向扫描 `listener_base[]` 找到所属 listener_idx，进而获取 remote_addr/remote_port 等路由配置。 |
| **RST 帧** | RST Frame | 控制帧类型（MPF_RST），强制关闭连接。不经过 TIME_WAIT，收到后立即销毁通道。 |
| **raw_sock** | AF_PACKET Raw Socket | AF_PACKET 原始套接字文件描述符。用于收发链路层以太网帧，通过 BPF 过滤特定 EtherType。 |

## S

| 术语 | 英文 | 定义 |
|------|------|------|
| **SIGHUP** | SIGHUP Signal | Unix 信号（Hangup），本系统用于触发完整配置热重载。包括软参数刷新和通道 diff（增删改）。 |
| **SIGUSR1** | SIGUSR1 Signal | Unix 用户自定义信号 1，本系统用于触发快速通道控制（从 `config-ctl.json` 读取 add/del 操作）。O(1) 定点操作，无需全量 diff。 |
| **SM4** | SM4 Encryption | 国密 SM4 对称加密算法。本系统支持可选的 SM4-CBC 模式加密 KCP 载荷，128 位密钥，需双方配置一致。 |
| **静态通道** | Static Channel | 由配置文件 `channels[]` 定义的通道。角色固定为 LISTENER，创建于启动时或热重载时，生命周期与进程一致。 |
| **SYN 帧** | SYN Frame | 控制帧类型（MPF_SYN），由 INITIATOR 通道创建后自动发送。收到 SYN 端的 Backend 创建 RESPONDER 通道并回复 ACK。 |

## T

| 术语 | 英文 | 定义 |
|------|------|------|
| **TIME_WAIT** | TIME_WAIT State | TCP 状态机概念。本系统在收到 FIN 后短暂进入 TIME_WAIT 状态，延迟 2 秒后销毁通道，防止延迟包干扰。 |
| **TPACKET_V2** | TPACKET_V2 | AF_PACKET 的零拷贝环形缓冲区模式。使用 `setsockopt(PACKET_TX_RING)` 和 `PACKET_RX_RING` 配置共享内存环形队列以降低系统调用开销。 |

## U

| 术语 | 英文 | 定义 |
|------|------|------|
| **uint32_t channel_id** | 32-bit Channel ID | v2.0 将 channel_id 从 16 位扩展至 32 位，支持 50000+ 静态 listener 和灵活的数据通道池。同时帧头从 8 字节扩展至 9 字节。 |

---

> 最后更新: 2026-05-31 | v2.0
