/*
 * types.h - KCP-over-AF_PACKET 公共类型定义
 *
 * 定义整个项目中所有模块共享的数据结构、枚举、常量和配置类型。
 * 所有其他头文件都应包含此文件。
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <sys/types.h>

/* ============================================================================
 * 常量定义
 * ============================================================================ */

/* MyProto 协议常量 */
#define MYPROTO_MAGIC           0x4D50      /* 'MP' - 魔数，用于帧识别 */
#define MYPROTO_VERSION         0x01        /* 协议版本号 */
#define MYPROTO_HDR_SIZE        8           /* 协议头大小（字节） */
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
#define KCP_SEND_WINDOW         1024        /* 发送窗口 */
#define KCP_RECV_WINDOW         1024        /* 接收窗口 */
#define KCP_NODELAY             1           /* 启用 nodelay 模式 */
#define KCP_INTERVAL            10          /* KCP 内部更新间隔（ms） */
#define KCP_RESEND              2           /* 快速重传阈值 */
#define KCP_NC                  1           /* 禁用拥塞控制 */
#define KCP_UPDATE_INTERVAL     10          /* ikcp_update 调用间隔（ms） */

/* Channel 常量 */
#define MAX_CHANNELS            4096        /* 最大通道配置数 */
#define CHANNEL_HASH_SIZE_DEFAULT 1024      /* 默认哈希表大小 */
#define CHANNEL_RECV_BUF_SIZE   8192        /* 通道接收缓冲区大小 */
#define CHANNEL_ID_STATIC_MIN   1           /* 静态通道 ID 最小值 */
#define HEARTBEAT_CH_ID         0xFFFF      /* 全局心跳通道ID */

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
#define CRYPTO_OVERHEAD         (SM4_IV_SIZE + SM3_HMAC_SIZE) /* 加密总开销 */

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

/* 通道状态机 */
typedef enum {
    CHANNEL_CLOSED      = 0,    /* 关闭状态 */
    CHANNEL_SYN_SENT    = 1,    /* 已发送 SYN，等待 ACK */
    CHANNEL_SYN_RCVD    = 2,    /* 已收到 SYN，已发送 ACK，等待确认 */
    CHANNEL_ESTABLISHED = 3,    /* 已建立连接 */
    CHANNEL_FIN_SENT    = 4,    /* 已发送 FIN，等待对端 FIN */
    CHANNEL_FIN_RCVD    = 5,    /* 已收到 FIN，等待本地关闭 */
    CHANNEL_TIME_WAIT   = 6     /* 等待超时后彻底关闭 */
} channel_state_t;

/* 通道角色 */
/* 通道标志位 */
#define CH_FLAG_STATIC_LISTENER 0x01        /* 静态 listener 通道（不被 destroy 销毁） */

/* 通道角色 */
typedef enum {
    CHANNEL_ROLE_INITIATOR = 0, /* 发起方（主动连接） */
    CHANNEL_ROLE_RESPONDER = 1, /* 响应方（被动接受） */
    CHANNEL_ROLE_LISTENER  = 2  /* 监听方（仅 listen，不发 SYN） */
} channel_role_t;

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

/* MyProto 协议头（8 字节，紧凑打包） */
typedef struct __attribute__((packed)) {
    uint16_t magic;         /* 魔数 0x4D50 ('MP') */
    uint8_t  version;       /* 协议版本，当前 0x01 */
    uint8_t  flags;         /* 帧标志位 */
    uint16_t channel_id;    /* 通道标识符 */
    uint16_t data_len;      /* 负载长度（字节） */
} myproto_hdr_t;

/* 确保协议头大小为 8 字节 */
_Static_assert(sizeof(myproto_hdr_t) == 8, "myproto_hdr_t must be 8 bytes");

/* ============================================================================
 * 配置结构体
 * ============================================================================ */

/* 单通道配置 */
typedef struct {
    uint16_t    channel_id;                 /* 通道 ID */
    uint16_t    listen_port;                /* 本地监听端口 */
    uint16_t    remote_port;                /* 远端目标端口 */
    char        listen_addr[MAX_LISTEN_ADDR];  /* 本地监听地址 */
    char        remote_addr[MAX_REMOTE_ADDR];  /* 远端目标地址 */
    uint8_t     is_tcp;                     /* 1=TCP, 0=UDP */
    uint8_t     enabled;                    /* 是否启用此通道 */
    uint16_t    max_sessions;               /* 此端口最大并发数，0=默认1 */
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

/* 通道结构体（前向声明 KCP 类型） */
struct IKCPCB;  /* KCP 控制块 */

typedef struct channel_s {
    /* 标识 */
    uint16_t        channel_id;         /* 通道 ID */
    channel_state_t state;              /* 当前状态 */
    channel_role_t  role;               /* 通道角色 */
    uint32_t        flags;              /* 标志位（CH_FLAG_*） */
    uint8_t         listener_idx;       /* 在 config.channels[] 中的索引 */

    /* KCP 实例 */
    struct IKCPCB  *kcp;                /* KCP 控制块指针 */

    /* 网络层 */
    int             raw_sock;           /* AF_PACKET 原始套接字 */
    int             ifindex;            /* 网卡接口索引 */
    uint8_t         peer_mac[ETH_MAC_ADDR_LEN];   /* 对端 MAC */
    uint8_t         local_mac[ETH_MAC_ADDR_LEN];  /* 本地 MAC */
    uint16_t        ethertype;          /* EtherType */

    /* 本地套接字 */
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
    uint8_t         recv_buf[CHANNEL_RECV_BUF_SIZE]; /* KCP→socket 接收缓冲 */
    int             recv_buf_len;       /* 接收缓冲区有效数据长度 */

    /* 流控 */
    int             paused;             /* 背压标志：1=暂停接收本地数据 */

    /* 重传标记 */
    uint8_t         syn_retry_count;    /* SYN 重传计数 */
    uint8_t         fin_retry_count;    /* FIN 重传计数 */

    /* 统计 */
    channel_stats_t stats;              /* 通道统计 */

    /* 链表节点（用于哈希表冲突链） */
    struct channel_s *hash_next;
} channel_t;

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
    volatile int    running;            /* 运行标志 */
    volatile int    reload_requested;   /* 配置重载请求 */
    char            config_path[MAX_CONFIG_PATH]; /* 配置文件路径（用于热重载） */
    uint16_t        next_dynamic_channel_id; /* 下一个动态分配的 channel_id */
    uint32_t        last_global_heartbeat;  /* 上一次全局心跳响应时间 */

    /* 统计 */
    uint32_t        last_stats_time;    /* 上次统计输出时间 */

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

/* 时间戳辅助 */
#define time_now()          ((uint32_t)time(NULL))
#define time_elapsed(t)     (time_now() - (t))

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
