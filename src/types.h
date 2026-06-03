/*
 * types.h - KCP-over-AF_PACKET 公共类型定义
 *
 * 定义整个项目中所有模块共享的数据结构、枚举、常量和配置类型。
 * 所有其他头文件都应包含此文件。
 *
 * 本文件涵盖：
 *   1. MyProto 协议常量与帧格式定义（魔数、标志位、9字节帧头）
 *   2. 通道状态机（channel_state_t：7 状态，仿 TCP）
 *   3. 通道角色（channel_role_t：INITIATOR/RESPONDER/LISTENER）
 *   4. 代理节点类型（node_type_t：FRONTEND/BACKEND）
 *   5. 配置结构体（channel_config_t, global_config_t）
 *   6. 运行时核心结构体（channel_t, global_ctx_t）
 *   7. 加密配置、统计计数器、日志宏、工具宏
 *
 * 设计原则：
 *   - 所有结构体采用紧凑布局，减少内存占用
 *   - 以 channel_id 为全局标识，支持最多 65536 个并发通道
 *   - 动态通道 ID 分配采用分区机制，避免不同 listener 间冲突
 *   - 热重载通过标志位实现增量更新，不中断现有连接
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>

/* ============================================================================
 * 常量定义
 * ============================================================================ */

/* ── MyProto 协议概述 ────────────────────────────────────────────
 * MyProto 是一个轻量级二层隧道协议，运行在 AF_PACKET 原始套接字之上。
 *
 * 协议栈层次：
 *   应用数据 (TCP/UDP payload)
 *     → KCP (可靠传输、流控、ARQ)
 *       → MyProto (多路复用、通道管理、加密)
 *         → AF_PACKET (原始以太网帧，绕过内核协议栈)
 *
 * 帧结构（从外到内）：
 *   [Ethernet Header 14B] [MyProto Header 9B] [Optional: SM4-IV 16B]
 *     [Payload (KCP segment)] [Optional: SM3-HMAC 32B]
 *
 * 控制帧（SYN/ACK/FIN/RST/PING/PONG）仅含 9B 帧头，无 payload。
 * 数据帧含 MyProto 帧头 + KCP 段（可能加密）。
 */

/* MyProto 协议常量 */
#define MYPROTO_MAGIC           0x4D50      /* 'MP' - 魔数，用于帧识别 */
#define MYPROTO_VERSION         0x01        /* 协议版本号 */
#define MYPROTO_HDR_SIZE        9           /* 协议头大小（字节） */
#define MYPROTO_ETHERTYPE       0x88B5      /* 自定义 EtherType */

/* 帧标志位定义 */
#define MPF_DATA                0x00        /* 数据帧（无控制标志） */
#define MPF_SYN                 0x01        /* 通道建立请求 */
#define MPF_ACK                 0x02        /* 通道建立确认 */
#define MPF_FIN                 0x04        /* 通道关闭请求 */
#define MPF_RST                 0x08        /* 强制复位 */
#define MPF_PING                0x10        /* 心跳探测 */
#define MPF_PONG                0x20        /* 心跳响应 */
#define MPF_CRYPTO              0x40        /* 加密标志（SM4-CBC + HMAC-SM3） */
#define MPF_CTRL_MASK           0x3F        /* 控制帧标志掩码 */

/* 判断帧类型 */
#define IS_CTRL_FRAME(flags)    ((flags) & MPF_CTRL_MASK)
#define IS_DATA_FRAME(flags)    (((flags) & MPF_CTRL_MASK) == 0)
#define IS_CRYPTO_FRAME(flags)  ((flags) & MPF_CRYPTO)

/* 以太网帧常量 */
#define ETH_HDR_SIZE            14          /* 以太网头部大小（不含 VLAN） */
#define ETH_MTU                 1500        /* 标准以太网 MTU */
#define ETH_MAX_PAYLOAD         1500        /* 最大以太网载荷 */
#define MAX_FRAME_SIZE          1550        /* 最大帧缓冲（含加密开销） */
#define ETH_MAC_ADDR_LEN        6           /* MAC 地址长度 */

/* KCP 参数 */
#define KCP_MTU_CONSERVATIVE    1400        /* 保守 KCP MTU */
#define KCP_MTU_PERFORMANCE     1478        /* 高性能 KCP MTU */
#define KCP_MSS_CONSERVATIVE    1376        /* 保守 MSS */
#define KCP_MSS_PERFORMANCE     1454        /* 高性能 MSS */
#define KCP_SEND_WINDOW         1024        /* 发送窗口（段数） */
#define KCP_RECV_WINDOW         1024        /* 接收窗口（段数） */
#define KCP_NODELAY             1           /* 启用 nodelay 模式 */
#define KCP_INTERVAL            10          /* KCP 内部更新间隔（ms） */
#define KCP_RESEND              2           /* 快速重传阈值 */
#define KCP_NC                  1           /* 禁用拥塞控制 */
#define KCP_UPDATE_INTERVAL     10          /* ikcp_update 调用间隔（ms） */

/* 性能调优默认值 */
#define PERF_AF_PACKET_SNDBUF           (16 * 1024 * 1024) /* AF_PACKET 发送缓冲 */
#define PERF_AF_PACKET_RCVBUF           (16 * 1024 * 1024) /* AF_PACKET 接收缓冲 */
#define PERF_AF_PACKET_SEND_RETRY_MAX   8                  /* AF_PACKET EAGAIN 重试次数 */
#define PERF_AF_PACKET_SEND_WAIT_MS     1                  /* AF_PACKET 每次重试等待时间 */
#define PERF_PROXY_TCP_SOCKBUF          (4 * 1024 * 1024)  /* 本地 TCP socket 缓冲 */
#define PERF_KCP_READ_PAUSE_WAITSND     (KCP_SEND_WINDOW * 4) /* KCP 读暂停水位 */
#define PERF_KCP_READ_RESUME_WAITSND    (KCP_SEND_WINDOW * 2) /* KCP 读恢复水位 */
#define PERF_KCP_IMMEDIATE_FLUSH        1                  /* KCP 入队后立即 flush */
#define PERF_MAX_FRAMES_PER_CYCLE       8192               /* 每轮最多处理 AF_PACKET 帧 */

/* Channel 常量 */
#define MAX_CHANNELS            65536       /* 最大通道配置数 */
#define CHANNEL_HASH_SIZE_DEFAULT 1024      /* 默认哈希表大小 */
#define CHANNEL_RECV_BUF_SIZE   8192        /* socket 写阻塞待发送缓冲区初始大小 */
#define CHANNEL_RECV_BUF_MAX    (1024 * 1024) /* socket 写阻塞待发送缓冲区上限 */
#define KCP_APP_RECV_BUF_SIZE   (64 * 1024) /* KCP 单条应用消息接收缓冲区大小 */
#define CHANNEL_ID_STATIC_MIN   1           /* 静态通道 ID 最小值 */
#define HEARTBEAT_CH_ID         0xFFFFFFFF  /* 全局心跳通道ID */

/* 超时与心跳 */
#define HEARTBEAT_INTERVAL      10          /* 心跳发送间隔（秒） */
#define HEARTBEAT_TIMEOUT       60          /* 心跳超时（秒），对端无响应则断连 */
#define CHANNEL_IDLE_TIMEOUT    300         /* 通道空闲超时（秒） */
#define CHANNEL_GRACEFUL_TIMEOUT 30         /* 优雅关闭超时（秒） */

/* 加密常量 */
#define SM4_KEY_SIZE            16          /* SM4 密钥长度（128 位） */
#define SM4_IV_SIZE             16          /* SM4-CBC IV 长度 */
#define SM3_HMAC_SIZE           32          /* SM3-HMAC 输出长度 */
#define SM4_IV_LEN             SM4_IV_SIZE
#define SM3_HMAC_LEN           SM3_HMAC_SIZE
#define CRYPTO_OVERHEAD         (SM4_IV_SIZE + SM4_IV_SIZE + SM3_HMAC_SIZE) /* IV + PKCS7_max + HMAC = 64 */

/* CRC32 */
#define CRC32_SIZE              4           /* CRC32 校验值大小 */

/* AF_PACKET 常量 */
#define AF_PACKET_FRAME_SIZE    1600        /* AF_PACKET 帧缓冲区大小 */
#define BPF_FILTER_MAX          256         /* BPF 过滤器最大长度 */

/* 代理常量 */
#define MAX_LISTEN_ADDR         64          /* 监听地址最大长度 */
#define MAX_REMOTE_ADDR         64          /* 远端地址最大长度 */
#define MAX_INTERFACE_NAME      32          /* 网卡名称最大长度 */
#define MAX_CONFIG_PATH         256         /* 配置文件路径最大长度 */
#define MAX_PID_PATH            256         /* PID 文件路径最大长度 */
#define DEFAULT_LISTEN_ADDR     "127.0.0.1" /* 默认监听地址 */

/* ============================================================================
 * 枚举类型
 * ============================================================================ */

/* ── 通道状态机 ───────────────────────────────────────────────────
 * 模仿 TCP 状态机的简化版本，用于 MyProto 通道的生命周期管理。
 *
 * 状态迁移图：
 *   CLOSED ──(发送SYN)──▶ SYN_SENT ──(收到ACK)──▶ ESTABLISHED
 *      │                      │
 *      │                  (收到SYN,            ◀── 正常数据传输 ──▶
 *      │                   发送ACK)
 *      │                      ▼
 *      └────────────── SYN_RCVD
 *                            │
 *                       (收到ACK)
 *                            │
 *                            ▼
 *                      ESTABLISHED ──(主动关闭,发送FIN)──▶ FIN_SENT
 *                           │                                 │
 *                      (收到FIN,                           (收到ACK)
 *                       发送ACK)                               │
 *                           │                                 ▼
 *                           ▼                            等待对端FIN
 *                       FIN_RCVD ◀──(收到FIN,发送ACK)────────┘
 *                           │
 *                      (超时)
 *                           ▼
 *                      TIME_WAIT ──(超时)──▶ CLOSED
 *
 * 设计要点：
 * - SYN_SENT/SYN_RCVD: 握手中，使用指数退避重传 SYN/ACK
 * - ESTABLISHED: 正常通信，KCP 负责可靠传输
 * - FIN_SENT/FIN_RCVD: 优雅关闭，允许对端完成剩余数据传输
 * - TIME_WAIT: 防止延迟帧干扰后续新连接（2MSL 等待）
 */
/* 通道状态机 */
typedef enum {
    CHANNEL_CLOSED      = 0,    /* 关闭状态：初始状态，未建立连接或已完全关闭 */
    CHANNEL_SYN_SENT    = 1,    /* 已发送 SYN，等待 ACK */
    CHANNEL_SYN_RCVD    = 2,    /* 已收到 SYN，已发送 ACK，等待确认 */
    CHANNEL_ESTABLISHED = 3,    /* 已建立连接：双向数据通信中 */
    CHANNEL_FIN_SENT    = 4,    /* 已发送 FIN，等待对端 FIN */
    CHANNEL_FIN_RCVD    = 5,    /* 已收到 FIN，等待本地关闭 */
    CHANNEL_TIME_WAIT   = 6     /* 等待超时后彻底关闭：防止残余帧干扰 */
} channel_state_t;

/* 通道角色 */
/* ── 通道角色与标志位 ────────────────────────────────────────────
 * 每个通道在握手和通信过程中扮演一种角色，决定其行为：
 *
 * LISTENER:   被动监听角色，仅 accept 不主动发 SYN。
 *             用于 frontend 节点上的服务端口监听通道。
 *             它本身不参与 KCP 数据传输，仅负责为每个新进入的连接
 *             派生 INITIATOR/RESPONDER 子通道。
 *
 * INITIATOR:  主动发起方，向对端发送 SYN 建立连接。
 *             通常由 frontend LISTENER accept 新客户端连接后创建，
 *             或 backend 节点主动向 frontend 发起连接。
 *
 * RESPONDER:  被动响应方，收到 SYN 后回复 ACK。
 *             由对端的 INITIATOR 触发创建，完成握手后进入 ESTABLISHED。
 */

/* 通道标志位 */
#define CH_FLAG_STATIC_LISTENER 0x01        /* 静态 listener 通道（不被 destroy 销毁） */
#define CH_FLAG_RELOAD_MARKED   0x02        /* reload 临时标记（增删改匹配用） */
#define CH_FLAG_KCP_READ_PAUSED 0x04        /* KCP 发送队列高水位，暂停本地读 */

/* ── 通道角色枚举 ────────────────────────────────────────────────
 * INITIATOR (0): 主动连接方 —— 发送 SYN，驱动握手流程
 * RESPONDER (1): 被动响应方 —— 收到 SYN 后回复 ACK
 * LISTENER  (2): 纯监听方 —— 仅 accept 本地连接，不参与对端握手
 */
/* 通道角色 */
typedef enum {
    CHANNEL_ROLE_INITIATOR = 0, /* 发起方（主动连接） */
    CHANNEL_ROLE_RESPONDER = 1, /* 响应方（被动接受） */
    CHANNEL_ROLE_LISTENER  = 2  /* 监听方（仅 listen，不发 SYN） */
} channel_role_t;

/* ── 代理节点类型 ────────────────────────────────────────────────
 * 决定了节点在网络拓扑中的位置和职责：
 *
 * FRONTEND (0): 部署在客户端侧，面向用户。
 *   - 在本地 bind 端口，等待客户端 TCP/UDP 连接
 *   - 将客户端数据通过 KCP-over-AF_PACKET 隧道转发到 backend
 *   - 每个客户端连接对应一个动态 INITIATOR 通道
 *
 * BACKEND (1):  部署在服务端侧，面向真实服务。
 *   - 收到 frontend 发来的隧道数据后，转发到本地实际服务端口
 *   - 角色通常为 RESPONDER（被动接受 frontend 发起的连接）
 *   - 一个 backend 可同时服务多个 frontend 的对等连接
 *
 * 典型部署拓扑：
 *   客户端 ──TCP──▶ [FRONTEND] ──AF_PACKET──▶ [BACKEND] ──TCP──▶ 真实服务
 */
/* 代理模式 */
typedef enum {
    NODE_TYPE_FRONTEND  = 0,    /* 前端节点：面向客户端，接收连接 */
    NODE_TYPE_BACKEND   = 1     /* 后端节点：面向服务端，转发数据 */
} node_type_t;

/* 加密模式 */
typedef enum {
    CRYPTO_MODE_NONE    = 0,    /* 不加密 */
    CRYPTO_MODE_SM4_SM3 = 1     /* SM4-CBC 加密 + SM3-HMAC 完整性校验 */
} crypto_mode_t;

/* ============================================================================
 * 协议头结构体
 * ============================================================================ */

/* ── MyProto 帧头格式（9 字节紧凑布局）───────────────────────────
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         channel_id                            |  4B, 通道ID
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    flags      |           payload_len         |  header_crc  |  1B+2B+2B
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 字段说明：
 * - channel_id (4B): 通道标识，用于多路复用/解复用，也作为哈希表键
 * - flags      (1B): 帧标志位（MPF_SYN/ACK/FIN/RST/PING/PONG/CRYPTO）
 * - payload_len(2B): 负载长度（不含帧头），最大 65535 字节
 * - header_crc (2B): 帧头 CRC16 校验，防止帧头损坏导致错误路由
 *
 * 设计理由：
 * - 9 字节极小开销，适合低延迟场景
 * - __attribute__((packed)) 确保无填充，跨平台一致
 * - header_crc 保护关键路由信息，payload 由上层 KCP 保证完整性
 */
/* MyProto 协议头（9 字节，紧凑打包） */
typedef struct __attribute__((packed)) {
    uint32_t channel_id;   /* 通道标识符：唯一标识一个逻辑通道 */
    uint8_t  flags;        /* 帧标志位：控制帧类型和加密标记 */
    uint16_t payload_len;  /* 负载长度（字节）：紧随帧头的 payload 长度 */
    uint16_t header_crc;   /* 头部 CRC 校验：防止帧头位错误 */
} myproto_hdr_t;

/* 确保协议头大小为 9 字节 */
_Static_assert(sizeof(myproto_hdr_t) == 9, "myproto_hdr_t must be 9 bytes");

/* ============================================================================
 * 配置结构体
 * ============================================================================ */

/* ── 客户端访问控制 (ACL) ──────────────────────────────────────────
 * 每个 listener 通道可配置客户端 IP/端口白名单。
 * 存储在 channel_config_t 中，通过 channels[] 数组 + listener_idx 访问。
 */
#define MAX_ACL_IPS    16
#define MAX_ACL_PORTS  8

typedef enum {
    ACL_IP_SINGLE = 1,
    ACL_IP_CIDR   = 2,
    ACL_IP_RANGE  = 3
} acl_ip_type_t;

typedef enum {
    ACL_PORT_SINGLE = 1,
    ACL_PORT_RANGE  = 2
} acl_port_type_t;

typedef struct {
    uint8_t  type;           /* acl_ip_type_t: SINGLE / CIDR / RANGE */
    uint32_t addr;           /* 网络字节序: 起始 IP 或单 IP */
    uint32_t mask_or_end;    /* CIDR: 网络字节序掩码; RANGE: 结束 IP */
} acl_ip_entry_t;

typedef struct {
    uint8_t  type;           /* acl_port_type_t: SINGLE / RANGE */
    uint16_t port_start;     /* 起始端口 */
    uint16_t port_end;       /* 结束端口（SINGLE 时等于 port_start） */
} acl_port_entry_t;

typedef struct {
    uint8_t          enabled;     /* 是否启用 ACL */
    uint8_t          ip_count;    /* IP 规则有效条目数 */
    acl_ip_entry_t   ips[MAX_ACL_IPS];
    uint8_t          port_count;  /* 端口规则有效条目数 */
    acl_port_entry_t ports[MAX_ACL_PORTS];
} channel_acl_t;

/* ── 单通道配置 ──────────────────────────────────────────────────
 * 每个 channel_config_t 描述一条转发规则。
 *
 * channel_id:  全局唯一标识，静态配置的通道使用固定 ID，
 *              动态通道由 next_dynamic_channel_id 分配。
 * listen_addr/port: 本地监听端点（frontend 接受客户端连接的地址）。
 * remote_addr/port: 远端目标端点（backend 转发到的实际服务地址）。
 * is_tcp:      区分传输层协议，影响本地 socket 创建方式。
 * enabled:     0=跳过此配置项（热重载时可禁用某条规则）。
 * max_sessions: 此端口允许的最大并发会话数，0 表示使用默认值 1。
 *               frontend 上每 accept 一个新客户端连接即创建一个 session，
 *               达到上限后新连接将被拒绝。
 */
/* 单通道配置 */
typedef struct {
    uint32_t    channel_id;                 /* 通道 ID */
    uint16_t    listen_port;                /* 本地监听端口 */
    uint16_t    remote_port;                /* 远端目标端口 */
    char        listen_addr[MAX_LISTEN_ADDR];  /* 本地监听地址 */
    char        remote_addr[MAX_REMOTE_ADDR];  /* 远端目标地址 */
    uint8_t     is_tcp;                     /* 1=TCP, 0=UDP */
    uint8_t     enabled;                    /* 是否启用此通道：0=禁用（跳过），1=启用 */
    uint16_t    max_sessions;               /* 此端口最大并发数：0=默认1，超限拒绝新连接 */
    channel_acl_t client_acl;               /* 客户端 IP/端口访问控制 */
} channel_config_t;

/* 加密配置（兼容B项目的crypto.h接口） */
#define SM4_KEY_HEX_LEN     32        /* SM4密钥十六进制字符串长度 */
#define SM4_KEY_BIN_LEN     16        /* SM4密钥二进制长度 */

typedef struct {
    uint8_t     enabled;              /* 是否启用加密 */
    char        sm4_key[SM4_KEY_HEX_LEN + 1]; /* SM4密钥hex字符串 */
} encryption_config_t;

/* 全局配置 */
typedef struct {
    /* 网卡配置 */
    char        interface[MAX_INTERFACE_NAME];  /* 网卡名称（如 eth0） */
    uint16_t    ethertype;                      /* 自定义 EtherType */
    uint8_t     local_mac[ETH_MAC_ADDR_LEN];    /* 本地 MAC 地址 */
    uint8_t     peer_mac[ETH_MAC_ADDR_LEN];     /* 对端 MAC 地址 */

    /* KCP 配置 */
    int         kcp_mtu;                /* KCP MTU */
    int         kcp_send_window;        /* 发送窗口大小 */
    int         kcp_recv_window;        /* 接收窗口大小 */
    int         kcp_nodelay;            /* nodelay 模式 */
    int         kcp_interval;           /* 内部更新间隔 */
    int         kcp_resend;             /* 快速重传 */
    int         kcp_nc;                 /* 流控关闭 */

    /* 性能调优配置 */
    int         perf_af_packet_sndbuf;          /* AF_PACKET SO_SNDBUF */
    int         perf_af_packet_rcvbuf;          /* AF_PACKET SO_RCVBUF */
    int         perf_af_packet_send_retry_max;  /* AF_PACKET EAGAIN 重试次数 */
    int         perf_af_packet_send_wait_ms;    /* AF_PACKET 每次重试等待时间 */
    int         perf_proxy_tcp_sockbuf;         /* 本地 TCP SO_SNDBUF/SO_RCVBUF */
    int         perf_kcp_read_pause_waitsnd;    /* KCP waitsnd 高水位 */
    int         perf_kcp_read_resume_waitsnd;   /* KCP waitsnd 低水位 */
    int         perf_kcp_immediate_flush;       /* KCP send 后立即 flush */
    int         perf_max_frames_per_cycle;      /* 主循环每轮最多处理 AF_PACKET 帧 */

    /* 代理配置 */
    node_type_t node_type;            /* 节点角色（frontend/backend） */
    int          max_channels;          /* 最大通道数 */
    int          heartbeat_interval;    /* 心跳间隔（秒） */
    int          heartbeat_timeout;     /* 心跳超时（秒） */

    /* 加密配置 */
    encryption_config_t encryption;       /* 加密子配置 */

    /* CRC 配置 */
    uint8_t     crc_enabled;            /* 是否启用 CRC32 */

    /* NIC MTU 配置 */
    uint8_t     auto_set_nic_mtu;       /* 是否自动设置 NIC MTU */
    int         nic_mtu;                /* 目标 NIC MTU */

    /* 多实例配置 */
    char        pid_file[MAX_PID_PATH]; /* PID 文件路径 */
    char        instance_name[MAX_LISTEN_ADDR]; /* 实例名称 */

    /* 通道列表 */
    channel_config_t channels[MAX_CHANNELS]; /* 通道配置列表 */
    int              channel_count;          /* 实际通道数 */

    /* 统计 */
    uint8_t     stats_enabled;          /* 是否启用统计 */
} global_config_t;

/* ============================================================================
 * 运行时结构体
 * ============================================================================ */

/* 通道统计计数器 */
typedef struct {
    uint64_t    tx_frames;              /* 已发送帧数 */
    uint64_t    tx_bytes;               /* 已发送字节数 */
    uint64_t    rx_frames;              /* 已接收帧数 */
    uint64_t    rx_bytes;               /* 已接收字节数 */
    uint64_t    retransmits;            /* 重传次数 */
    uint64_t    tx_errors;              /* 发送错误数 */
    uint64_t    rx_errors;              /* 接收错误数 */
    uint64_t    crc_errors;             /* CRC 校验错误数 */
    uint64_t    crypto_errors;          /* 加密/解密错误数 */
} channel_stats_t;

/* ── 通道结构体 ──────────────────────────────────────────────────
 * channel_t 是整个系统的核心数据结构，代表一条 MyProto 逻辑通道。
 *
 * 生命周期：
 *   1. 静态通道：从 config.channels[] 创建，flags 含 CH_FLAG_STATIC_LISTENER
 *   2. 动态通道：LISTENER accept 新连接或收到 SYN 时动态创建
 *   3. 销毁：通道关闭后从哈希表移除并释放内存
 *
 * 关键字段说明：
 *
 * flags 标志位：
 *   CH_FLAG_STATIC_LISTENER (0x01):
 *     标记该通道为静态 listener，不会被 destroy 销毁。
 *     热重载时通过此标志识别配置文件中定义的持久通道。
 *   CH_FLAG_RELOAD_MARKED (0x02):
 *     热重载过程中的临时标记。reload 流程会：
 *       1) 给所有现有通道打上此标记
 *       2) 遍历新配置，匹配成功的通道清除标记
 *       3) 仍有标记的通道 = 旧配置中存在但新配置中已删除 → 关闭
 *
 * listener_idx:
 *   指向 config.channels[] 中对应静态配置的索引。
 *   动态子通道通过此字段找到其父 listener 的端口/地址配置。
 *   对于非 listener 的动态通道，此字段指向其 parent listener。
 *
 * listen_fd vs local_fd:
 *   listen_fd:  仅 LISTENER 角色使用，是 bind+listen 后的监听套接字。
 *               负责 accept 新客户端连接。
 *   local_fd:   INITIATOR/RESPONDER 角色使用，是 accept 返回的已连接
 *               套接字，或主动 connect 到本地服务的套接字。
 *               数据流向：local_fd ←(read/write)→ KCP → AF_PACKET → 对端
 *
 * raw_sock:
 *   每通道独立的 AF_PACKET 原始套接字，绑定到指定网卡接口。
 *   使用独立的 raw_sock 而非共享全局 raw_sock，是为了：
 *   - 每个通道可绑定不同的 BPF 过滤器（按 channel_id 过滤）
 *   - 避免全局锁竞争，提升多通道并发性能
 */
/* 通道结构体（前向声明 KCP 类型） */
struct IKCPCB;  /* KCP 控制块 */

typedef struct channel_s {
    /* 标识 */
    uint32_t        channel_id;         /* 通道 ID */
    channel_state_t state;              /* 当前状态 */
    channel_role_t  role;               /* 通道角色 */
    uint32_t        flags;              /* 标志位（CH_FLAG_STATIC_LISTENER / CH_FLAG_RELOAD_MARKED / CH_FLAG_KCP_READ_PAUSED） */
    uint16_t        listener_idx;       /* 在 config.channels[] 中的索引 */

    /* KCP 实例 */
    struct IKCPCB  *kcp;                /* KCP 控制块指针 */

    /* 网络层 */
    int             raw_sock;           /* AF_PACKET 原始套接字 */
    int             ifindex;            /* 网卡接口索引 */
    uint8_t         peer_mac[ETH_MAC_ADDR_LEN];   /* 对端 MAC */
    uint8_t         local_mac[ETH_MAC_ADDR_LEN];  /* 本地 MAC */
    uint16_t        ethertype;          /* EtherType */

    /* 本地套接字
     * listen_fd: 监听套接字（仅 LISTENER 角色），用于 accept 新连接
     * local_fd:  已连接套接字（INITIATOR/RESPONDER），用于与本地应用通信
     */
    int             local_fd;           /* 连接到本地应用/服务的套接字 */
    int             listen_fd;          /* 监听套接字（frontend代理模式） */
    uint16_t        listen_port;        /* 监听端口 */
    uint16_t        remote_port;        /* 远端端口 */
    char            listen_addr[MAX_LISTEN_ADDR];  /* 监听地址 */
    char            remote_addr[MAX_REMOTE_ADDR];  /* 远端地址 */
    uint8_t         is_tcp;             /* TCP 标志 */

    /* 时间戳 */
    uint32_t        last_active;        /* 最后活跃时间（Unix 时间戳） */
    uint32_t        last_peer_seen;     /* 最后收到对端数据的时间 */
    uint32_t        created_at;         /* 创建时间 */
    uint32_t        syn_sent_at;        /* SYN 发送时间 */

    /* 缓冲区 */
    uint8_t        *recv_buf;           /* KCP→socket 待发送缓冲（按需分配） */
    int             recv_buf_len;       /* 接收缓冲区有效数据长度 */
    int             recv_buf_cap;       /* 接收缓冲区容量 */

    /* 流控 */
    int             paused;             /* 背压标志：1=暂停接收本地数据 */

    /* 重传标记 */
    uint8_t         syn_retry_count;    /* SYN 重传计数 */
    uint8_t         fin_retry_count;    /* FIN 重传计数 */
    uint8_t         connect_pending;    /* 异步TCP connect进行中：1=等待EPOLLOUT确认 */

    /* 统计 */
    channel_stats_t stats;              /* 通道统计 */

    /* 链表节点（用于哈希表冲突链） */
    struct channel_s *hash_next;
} channel_t;

/* ── 全局上下文 ──────────────────────────────────────────────────
 * global_ctx_t 是单例全局状态，持有所有运行时资源。
 *
 * 动态通道 ID 分配机制：
 *   next_dynamic_channel_id: 全局自增计数器，为每个动态创建的通道
 *     分配唯一 ID。每次分配后原子递增。与 listener_base[]/listener_next[]
 *     配合，支持每个 listener 独立的 ID 池。
 *
 *   listener_base[MAX_CHANNELS]:
 *     每个 listener（按 config.channels[] 索引）的 ID 池起始偏移。
 *     listener_base[i] = i * (MAX_CHANNELS 范围内每 listener 的配额)。
 *     这样不同 listener 的动态子通道 ID 不会冲突。
 *
 *   listener_next[MAX_CHANNELS]:
 *     每个 listener 的下一个可用动态 ID（相对于 listener_base 的偏移）。
 *     分配新 ID 时：id = listener_base[idx] + listener_next[idx]++;
 *     此方案避免了全局锁，每个 listener 独立计数。
 *
 * ctl_requested:
 *   SIGUSR1 信号触发，用于运行时不重启加载通道控制命令。
 *   主循环检测到此标志后，读取控制命令（如动态添加/删除通道），
 *   执行后清除标志。与 reload_requested (SIGHUP) 不同，
 *   ctl_requested 不重新读取配置文件，而是执行增量操作。
 */
/* 全局上下文 */
typedef struct {
    /* AF_PACKET */
    int             raw_sock;           /* AF_PACKET 原始套接字 */
    int             ifindex;            /* 网卡接口索引 */
    uint8_t         local_mac[ETH_MAC_ADDR_LEN];   /* 本地 MAC */
    uint8_t         peer_mac[ETH_MAC_ADDR_LEN];    /* 对端 MAC（广播发现或配置） */
    uint8_t         peer_mac_learned;   /* 1 if peer MAC was auto-learned */
    uint16_t        ethertype;          /* EtherType */

    /* 配置 */
    global_config_t config;             /* 全局配置 */

    /* 通道管理 */
    channel_t     **channel_hash;                /* 通道哈希表（动态分配） */
    uint32_t        channel_hash_size;           /* 哈希表桶数 */
    int             channel_count;               /* 当前活跃通道数 */

    /* epoll */
    int             epoll_fd;           /* epoll 文件描述符 */

    /* 运行状态 */
    volatile sig_atomic_t running;          /* 运行标志 */
    volatile sig_atomic_t reload_requested; /* 配置重载请求（SIGHUP） */
    volatile sig_atomic_t ctl_requested;    /* 通道控制请求（SIGUSR1）：增量通道操作，非重载 */
    char            config_path[MAX_CONFIG_PATH]; /* 配置文件路径（用于热重载） */
    uint32_t        next_dynamic_channel_id; /* 下一个动态分配的 channel_id（全局自增） */
    uint32_t        listener_base[MAX_CHANNELS];  /* 每个 listener 的 ID 池起始偏移 */
    uint32_t        listener_next[MAX_CHANNELS];  /* 每个 listener 的下一个动态 ID（相对偏移） */
    uint32_t        last_global_heartbeat;  /* 上一次全局心跳响应时间 */

    /* 统计 */
    uint32_t        last_stats_time;    /* 上次统计输出时间 */

    /* 速率限制（防 SYN flood）：每秒最多创建 N 个通道 */
    uint32_t        channel_create_timestamp;  /* 当前秒的时间戳 */
    uint32_t        channel_create_count;      /* 当前秒内创建计数 */
    uint32_t        channel_create_max_per_sec; /* 每秒最大创建数，0=不限制 */

} global_ctx_t;

/* ============================================================================
 * 工具宏
 * ============================================================================ */

/* 取最小值 */
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/* 取最大值 */
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* 安全检查：数组元素数 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* 时间戳辅助 — 安全减法，防止系统时钟回拨导致无符号回绕 */
#define time_now()          ((uint32_t)time(NULL))
#define time_elapsed(t)     ({ uint32_t __n = time_now(); (__n < (t)) ? (uint32_t)0 : (__n - (t)); })

/* ── 日志宏 ──────────────────────────────────────────────────────
 * 四级日志系统，全部输出到 stderr（适合 systemd journal 采集）。
 *
 * LOG_DEBUG: 调试信息，仅在 -DDEBUG 编译时生效。
 *            用于开发阶段追踪详细的数据流向和状态变化。
 * LOG_INFO:  正常运行信息（连接建立、关闭、配置加载等）。
 * LOG_WARN:  警告信息（重传超限、接近资源上限、非致命错误）。
 * LOG_ERROR: 错误信息（连接失败、系统调用错误、致命异常）。
 *
 * 设计理由：
 * - 使用 fprintf(stderr) 而非 syslog，简化依赖，方便容器化部署
 * - 日志级别通过编译宏控制，运行时零开销
 * - 格式统一为 "[LEVEL] message"，便于 grep 和日志平台解析
 */
/* 日志宏 */
#ifdef DEBUG
#define LOG_DEBUG(fmt, ...)   fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)   do { } while (0)
#endif

#define LOG_INFO(fmt, ...)    fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)    fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

#endif /* TYPES_H */
