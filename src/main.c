/*
 * main.c - KCP-over-AF_PACKET 入口点
 *
 * 负责配置加载、验证、信号处理、主事件循环和清理。
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                          启动序列（Startup Sequence）                     ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║   1. 命令行参数解析                                                       ║
 * ║      -v / --version : 打印版本号                                        ║
 * ║      -h / --help    : 打印帮助信息                                      ║
 * ║      <config.json>  : 配置文件路径（必需）                               ║
 * ║                                                                          ║
 * ║   2. 初始化全局上下文 (global_ctx_t)                                       ║
 * ║      memset 清零，raw_sock=-1, epoll_fd=-1, running=1                    ║
 * ║                                                                          ║
 * ║   3. 加载配置文件 (config_load)                                           ║
 * ║      解析 JSON 配置：网卡、EtherType、MAC、KCP参数、加密、通道列表        ║
 * ║                                                                          ║
 * ║   4. 验证配置 (validate_config)                                           ║
 * ║      检查接口名、EtherType范围、KCP参数、通道ID唯一性、加密密钥            ║
 * ║                                                                          ║
 * ║   4b. 初始化加密模块 (crypto_init)                                        ║
 * ║      解析 hex 密钥 → 设置 SM4 加解密上下文 → 派生 SM3-HMAC 子密钥        ║
 * ║                                                                          ║
 * ║   5. 安装信号处理器 (setup_signals)                                       ║
 * ║      SIGINT/SIGTERM → 设置 running=0                                     ║
 * ║      SIGHUP         → 设置 reload_requested=1                           ║
 * ║      SIGPIPE        → 忽略（防止对已关闭socket写导致进程退出）            ║
 * ║                                                                          ║
 * ║   6. 初始化代理子系统 (proxy_init)                                        ║
 * ║      创建 epoll 实例 (epoll_create1 with EPOLL_CLOEXEC)                  ║
 * ║                                                                          ║
 * ║   7. 初始化通道子系统 (channel_init)                                      ║
 * ║      分配哈希表 (max_channels * 2 个桶，限制 [64, 65535])                 ║
 * ║                                                                          ║
 * ║   8. 创建 AF_PACKET 原始套接字 (af_packet_create)                         ║
 * ║      socket(AF_PACKET, SOCK_RAW, ethertype) → bind → 非阻塞 → TPACKET_V2 ║
 * ║                                                                          ║
 * ║   9. 获取本地 MAC 地址 (af_packet_get_mac)                                ║
 * ║      若配置未指定，通过 SIOCGIFHWADDR ioctl 自动获取                     ║
 * ║                                                                          ║
 * ║   10. 确定对端 MAC 地址                                                   ║
 * ║       若配置未指定 → 使用广播地址 FF:FF:FF:FF:FF:FF，启动自动学习         ║
 * ║                                                                          ║
 * ║   11. 自动设置 NIC MTU (可选)                                             ║
 * ║       SIOCSIFMTU ioctl                                                  ║
 * ║                                                                          ║
 * ║   12. 设置 BPF 过滤器 (af_packet_set_bpf)                                 ║
 * ║      仅接收匹配 EtherType 的帧，内核级过滤减少用户态开销                  ║
 * ║                                                                          ║
 * ║   13. 创建通道并启动代理监听                                              ║
 * ║      对于每个配置的通道:                                                   ║
 * ║        - channel_create() 创建通道 + KCP 实例                             ║
 * ║        - proxy_start_listen() 绑定监听端口 + 加入 epoll (frontend)        ║
 * ║                                                                          ║
 * ║   14. 将 AF_PACKET 套接字加入 epoll                                       ║
 * ║                                                                          ║
 * ║   15. 初始化时间基准 (kcp_wrap_clock + time)                               ║
 * ║                                                                          ║
 * ║   16. 主事件循环                                                          ║
 * ║       epoll_wait(10ms) → 处理 AF_PACKET 帧 + 代理 I/O                    ║
 * ║       → 周期任务 (KCP更新 + 心跳 + 超时检查，每10ms)                      ║
 * ║       → 统计输出 (每60秒)                                                 ║
 * ║       → 配置热重载 (SIGHUP 触发)                                         ║
 * ║                                                                          ║
 * ║   17. 清理退出 (cleanup)                                                  ║
 * ║       优雅关闭所有通道 → KCP缓冲区排空 → 释放所有资源                      ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <json-c/json.h>

#include "types.h"
#include "af_packet.h"
#include "myproto.h"
#include "kcp_wrap.h"
#include "channel.h"
#include "proxy.h"
#include "crypto.h"

#define VERSION             "1.0.0"
#define EPOLL_MAX_EVENTS    64
#define EPOLL_TIMEOUT_MS    10
#define PERIODIC_INTERVAL_MS 10
#define MAX_FRAMES_PER_CYCLE 64
#define STATS_INTERVAL_SEC  60

/* ---- 全局上下文指针（信号处理器需要访问） ---- */
static global_ctx_t *g_ctx = NULL;

/* ---- 前向声明 ---- */
static void cleanup(global_ctx_t *ctx);

/* ---- 信号处理器 ---- */
static void signal_handler(int signum)
{
    if (g_ctx == NULL) return;

    switch (signum) {
    case SIGINT:
    case SIGTERM:
        g_ctx->running = 0;
        break;
    case SIGHUP:
        g_ctx->reload_requested = 1;
        break;
    default:
        break;
    }
}

#ifndef TEST_BUILD
static int setup_signals(global_ctx_t *ctx)
{
    struct sigaction sa;

    g_ctx = ctx;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGINT handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGTERM handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGHUP handler: %s", strerror(errno));
        return -1;
    }

    /* SIGPIPE 忽略，防止对已关闭的 socket 写入导致进程退出 */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGPIPE handler: %s", strerror(errno));
        return -1;
    }

    return 0;
}
#endif /* TEST_BUILD */

/* ---- MAC 地址解析 ---- */
static int parse_mac_string(const char *str, uint8_t mac[ETH_MAC_ADDR_LEN])
{
    unsigned int values[ETH_MAC_ADDR_LEN];
    int n;

    if (str == NULL || strlen(str) == 0)
        return -1;

    n = sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]);
    if (n != ETH_MAC_ADDR_LEN)
        return -1;

    for (int i = 0; i < ETH_MAC_ADDR_LEN; i++) {
        if (values[i] > 255)
            return -1;
        mac[i] = (uint8_t)values[i];
    }

    return 0;
}

static int mac_is_zero(const uint8_t mac[ETH_MAC_ADDR_LEN])
{
    for (int i = 0; i < ETH_MAC_ADDR_LEN; i++) {
        if (mac[i] != 0) return 0;
    }
    return 1;
}

/* Return 1 if mac is broadcast (all 0xFF) */
static int mac_is_broadcast(const uint8_t mac[ETH_MAC_ADDR_LEN])
{
    for (int i = 0; i < ETH_MAC_ADDR_LEN; i++)
        if (mac[i] != 0xFF) return 0;
    return 1;
}

/* ---- 配置加载 ---- */
int config_load(const char *path, global_config_t *config)
{
    struct json_object *root = NULL;
    struct json_object *obj = NULL;
    struct json_object *tmp = NULL;
    int ret = -1;

    root = json_object_from_file(path);
    if (root == NULL) {
        LOG_ERROR("Failed to parse config file: %s", path);
        return -1;
    }

    memset(config, 0, sizeof(*config));

    /* ---- interface ---- */
    if (json_object_object_get_ex(root, "interface", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s) {
            /* strncpy with manual NUL termination is intentional */
            strncpy(config->interface, s, MAX_INTERFACE_NAME - 1);
            config->interface[MAX_INTERFACE_NAME - 1] = '\0';
        }
    }

    /* ---- ethertype ---- */
    if (json_object_object_get_ex(root, "ethertype", &tmp)) {
        int raw_ethertype = json_object_get_int(tmp);
        if (raw_ethertype <= 0 || raw_ethertype > 0xFFFF) {
            LOG_ERROR("Ethertype %d out of range [1, 65535]", raw_ethertype);
            goto cleanup;
        }
        config->ethertype = (uint16_t)raw_ethertype;
    } else {
        config->ethertype = 0x88B5;   /* 默认 EtherType */
    }

    /* ---- peer_mac ---- */
    if (json_object_object_get_ex(root, "peer_mac", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s && strlen(s) > 0) {
            if (parse_mac_string(s, config->peer_mac) != 0) {
                LOG_ERROR("Invalid peer_mac format: %s", s);
                goto cleanup;
            }
        }
        /* empty string: leave as zeros (auto-discovery) */
    }

    /* ---- local_mac ---- */
    if (json_object_object_get_ex(root, "local_mac", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s && strlen(s) > 0) {
            if (parse_mac_string(s, config->local_mac) != 0) {
                LOG_ERROR("Invalid local_mac format: %s", s);
                goto cleanup;
            }
        }
    }

    /* ---- kcp object ---- */
    if (json_object_object_get_ex(root, "kcp", &obj)) {
        if (json_object_object_get_ex(obj, "mtu", &tmp))
            config->kcp_mtu = json_object_get_int(tmp);
        else
            config->kcp_mtu = KCP_MTU_CONSERVATIVE;

        if (json_object_object_get_ex(obj, "sndwnd", &tmp))
            config->kcp_send_window = json_object_get_int(tmp);
        else
            config->kcp_send_window = KCP_SEND_WINDOW;

        if (json_object_object_get_ex(obj, "rcvwnd", &tmp))
            config->kcp_recv_window = json_object_get_int(tmp);
        else
            config->kcp_recv_window = KCP_RECV_WINDOW;

        if (json_object_object_get_ex(obj, "nodelay", &tmp))
            config->kcp_nodelay = json_object_get_int(tmp);
        else
            config->kcp_nodelay = KCP_NODELAY;

        if (json_object_object_get_ex(obj, "interval", &tmp))
            config->kcp_interval = json_object_get_int(tmp);
        else
            config->kcp_interval = KCP_INTERVAL;

        if (json_object_object_get_ex(obj, "resend", &tmp))
            config->kcp_resend = json_object_get_int(tmp);
        else
            config->kcp_resend = KCP_RESEND;

        if (json_object_object_get_ex(obj, "nc", &tmp))
            config->kcp_nc = json_object_get_int(tmp);
        else
            config->kcp_nc = KCP_NC;
    } else {
        /* 未指定 kcp 配置，使用默认值 */
        config->kcp_mtu         = KCP_MTU_CONSERVATIVE;
        config->kcp_send_window = KCP_SEND_WINDOW;
        config->kcp_recv_window = KCP_RECV_WINDOW;
        config->kcp_nodelay     = KCP_NODELAY;
        config->kcp_interval    = KCP_INTERVAL;
        config->kcp_resend      = KCP_RESEND;
        config->kcp_nc          = KCP_NC;
    }

    /* ---- node_type ---- */
    if (json_object_object_get_ex(root, "node_type", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s && strcmp(s, "backend") == 0) {
            config->node_type = NODE_TYPE_BACKEND;
        } else {
            config->node_type = NODE_TYPE_FRONTEND;
        }
    } else {
        config->node_type = NODE_TYPE_FRONTEND;
    }

    /* ---- max_channels ---- */
    if (json_object_object_get_ex(root, "max_channels", &tmp)) {
        config->max_channels = json_object_get_int(tmp);
    } else {
        config->max_channels = 65536;
    }

    /* ---- heartbeat_interval ---- */
    if (json_object_object_get_ex(root, "heartbeat_interval", &tmp)) {
        config->heartbeat_interval = json_object_get_int(tmp);
    } else {
        config->heartbeat_interval = HEARTBEAT_INTERVAL;
    }

    /* ---- heartbeat_timeout ---- */
    if (json_object_object_get_ex(root, "heartbeat_timeout", &tmp)) {
        config->heartbeat_timeout = json_object_get_int(tmp);
    } else {
        config->heartbeat_timeout = HEARTBEAT_TIMEOUT;
    }

    /* ---- encryption object ---- */
    if (json_object_object_get_ex(root, "encryption", &obj)) {
        if (json_object_object_get_ex(obj, "enabled", &tmp)) {
            config->encryption.enabled = json_object_get_boolean(tmp) ? 1 : 0;
        }

        if (json_object_object_get_ex(obj, "sm4_key", &tmp)) {
            const char *hex_key = json_object_get_string(tmp);
            if (hex_key && strlen(hex_key) > 0) {
                size_t key_len = strlen(hex_key);
                if (key_len != SM4_KEY_HEX_LEN) {
                    LOG_ERROR("SM4 key must be %d hex characters (%d bytes)",
                              SM4_KEY_HEX_LEN, SM4_KEY_BIN_LEN);
                    goto cleanup;
                }
                /* strncpy with manual NUL termination is intentional */
                strncpy(config->encryption.sm4_key, hex_key, SM4_KEY_HEX_LEN);
                config->encryption.sm4_key[SM4_KEY_HEX_LEN] = '\0';
            }
        }
    }

    /* ---- crc_enabled ---- */
    if (json_object_object_get_ex(root, "crc_enabled", &tmp)) {
        config->crc_enabled = json_object_get_boolean(tmp) ? 1 : 0;
    } else {
        config->crc_enabled = 0;  // Default: disabled (was 1)
    }

    /* ---- auto_set_nic_mtu ---- */
    if (json_object_object_get_ex(root, "auto_set_nic_mtu", &tmp)) {
        config->auto_set_nic_mtu = json_object_get_boolean(tmp) ? 1 : 0;
    }

    /* ---- nic_mtu ---- */
    if (json_object_object_get_ex(root, "nic_mtu", &tmp)) {
        config->nic_mtu = json_object_get_int(tmp);
    } else {
        config->nic_mtu = ETH_MTU;
    }

    /* ---- pid_file ---- */
    if (json_object_object_get_ex(root, "pid_file", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s) {
            /* strncpy with manual NUL termination is intentional */
            strncpy(config->pid_file, s, MAX_PID_PATH - 1);
            config->pid_file[MAX_PID_PATH - 1] = '\0';
        }
    }

    /* ---- instance_name ---- */
    if (json_object_object_get_ex(root, "instance_name", &tmp)) {
        const char *s = json_object_get_string(tmp);
        if (s) {
            /* strncpy with manual NUL termination is intentional */
            strncpy(config->instance_name, s, MAX_LISTEN_ADDR - 1);
            config->instance_name[MAX_LISTEN_ADDR - 1] = '\0';
        } else {
            /* strncpy with manual NUL termination is intentional */
            strncpy(config->instance_name, "default", MAX_LISTEN_ADDR - 1);
        }
    } else {
        /* strncpy with manual NUL termination is intentional */
        strncpy(config->instance_name, "default", MAX_LISTEN_ADDR - 1);
    }

    /* ---- channels array ---- */
    if (json_object_object_get_ex(root, "channels", &obj)) {
        int arr_len = json_object_array_length(obj);
        if (arr_len > MAX_CHANNELS) {
            LOG_ERROR("Too many channels in config (%d), max is %d", arr_len, MAX_CHANNELS);
            goto cleanup;
        }
        config->channel_count = 0;
        for (int i = 0; i < arr_len; i++) {
            struct json_object *ch_obj = json_object_array_get_idx(obj, i);
            channel_config_t *ch_cfg = &config->channels[config->channel_count];

            memset(ch_cfg, 0, sizeof(*ch_cfg));

            if (json_object_object_get_ex(ch_obj, "channel_id", &tmp))
                ch_cfg->channel_id = (uint32_t)json_object_get_int(tmp);

            if (json_object_object_get_ex(ch_obj, "listen_port", &tmp))
                ch_cfg->listen_port = (uint16_t)json_object_get_int(tmp);

            if (json_object_object_get_ex(ch_obj, "remote_port", &tmp))
                ch_cfg->remote_port = (uint16_t)json_object_get_int(tmp);

            if (json_object_object_get_ex(ch_obj, "listen_addr", &tmp)) {
                const char *s = json_object_get_string(tmp);
                if (s) {
                    /* strncpy with manual NUL termination is intentional */
                    strncpy(ch_cfg->listen_addr, s, MAX_LISTEN_ADDR - 1);
                    ch_cfg->listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
                }
            }

            if (json_object_object_get_ex(ch_obj, "remote_addr", &tmp)) {
                const char *s = json_object_get_string(tmp);
                if (s) {
                    /* strncpy with manual NUL termination is intentional */
                    strncpy(ch_cfg->remote_addr, s, MAX_REMOTE_ADDR - 1);
                    ch_cfg->remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
                }
            }

            if (json_object_object_get_ex(ch_obj, "is_tcp", &tmp)) {
                ch_cfg->is_tcp = json_object_get_boolean(tmp) ? 1 : 0;
            }

            ch_cfg->enabled = 1;

            /* max_sessions: 0=默认1，上限256 */
            if (json_object_object_get_ex(ch_obj, "max_sessions", &tmp)) {
                int ms = json_object_get_int(tmp);
                ch_cfg->max_sessions = (ms > 0 && ms <= 256) ? (uint16_t)ms : 1;
            } else {
                ch_cfg->max_sessions = 1;
            }

            config->channel_count++;
        }
    }

    ret = 0;

cleanup:
    json_object_put(root);
    return ret;
}

/* ---- 配置验证 ---- */
int validate_config(const global_config_t *config)
{
    /* interface 不能为空 */
    if (config->interface[0] == '\0') {
        LOG_ERROR("Interface must be specified");
        return -1;
    }

    /* ethertype 校验：避免保留范围 0x0000-0x05FF */
    if (config->ethertype < 0x0600) {
        LOG_ERROR("Ethertype 0x%04X is invalid or in reserved range", config->ethertype);
        return -1;
    }

    /* 如果指定了 peer_mac，校验格式（非全零即视为已指定） */
    if (!mac_is_zero(config->peer_mac)) {
        LOG_INFO("Peer MAC configured: %02x:%02x:%02x:%02x:%02x:%02x",
                 config->peer_mac[0], config->peer_mac[1], config->peer_mac[2],
                 config->peer_mac[3], config->peer_mac[4], config->peer_mac[5]);
    }

    /* KCP 参数合理性校验 */
    if (config->kcp_mtu <= 0) {
        LOG_ERROR("kcp.mtu must be > 0, got %d", config->kcp_mtu);
        return -1;
    }
    if (config->kcp_send_window <= 0) {
        LOG_ERROR("kcp.sndwnd must be > 0, got %d", config->kcp_send_window);
        return -1;
    }
    if (config->kcp_recv_window <= 0) {
        LOG_ERROR("kcp.rcvwnd must be > 0, got %d", config->kcp_recv_window);
        return -1;
    }
    if (config->kcp_interval < 1 || config->kcp_interval > 500) {
        LOG_ERROR("kcp.interval must be in [1, 500], got %d", config->kcp_interval);
        return -1;
    }
    if (config->kcp_nodelay < 0 || config->kcp_nodelay > 1) {
        LOG_ERROR("kcp.nodelay must be 0 or 1, got %d", config->kcp_nodelay);
        return -1;
    }
    if (config->kcp_resend < 0 || config->kcp_resend > 10) {
        LOG_ERROR("kcp.resend must be in [0, 10], got %d", config->kcp_resend);
        return -1;
    }
    if (config->kcp_nc < 0 || config->kcp_nc > 1) {
        LOG_ERROR("kcp.nc must be 0 or 1, got %d", config->kcp_nc);
        return -1;
    }

    /* node_type 校验 */
    if (config->node_type != NODE_TYPE_FRONTEND && config->node_type != NODE_TYPE_BACKEND) {
        LOG_ERROR("Invalid node_type: %d", config->node_type);
        return -1;
    }

    /* max_channels 验证 */
    if (config->max_channels < 1 || config->max_channels > MAX_CHANNELS) {
        LOG_ERROR("max_channels %d out of range [1, %d]", config->max_channels, MAX_CHANNELS);
        return -1;
    }

    /* 至少有一个通道 */
    if (config->channel_count == 0) {
        LOG_ERROR("At least one channel must be configured");
        return -1;
    }

    /* 通道 ID 唯一性和有效性 */
    for (int i = 0; i < config->channel_count; i++) {
        const channel_config_t *ch = &config->channels[i];

        if (ch->channel_id == 0) {
            LOG_ERROR("Channel %d: channel_id must be > 0", i);
            return -1;
        }

        if (ch->listen_port < 1) {
            LOG_ERROR("Channel %d (id=%u): listen_port %u out of range [1, 65535]",
                      i, ch->channel_id, ch->listen_port);
            return -1;
        }

        if (ch->remote_port < 1) {
            LOG_ERROR("Channel %d (id=%u): remote_port %u out of range [1, 65535]",
                      i, ch->channel_id, ch->remote_port);
            return -1;
        }

        /* 检查 ID 唯一性 */
        for (int j = i + 1; j < config->channel_count; j++) {
            if (ch->channel_id == config->channels[j].channel_id) {
                LOG_ERROR("Duplicate channel_id %u at indices %d and %d",
                          ch->channel_id, i, j);
                return -1;
            }
        }
    }

    /* 加密配置校验 */
    if (config->encryption.enabled) {
        if (config->encryption.sm4_key[0] == '\0') {
            LOG_ERROR("Encryption is enabled but no sm4_key provided "
                      "(need %d hex characters)", SM4_KEY_HEX_LEN);
            return -1;
        }
    }

    LOG_INFO("Configuration validated successfully: %s, %d channels, ethertype=0x%04X",
             config->node_type == NODE_TYPE_FRONTEND ? "frontend" : "backend",
             config->channel_count, config->ethertype);

    return 0;
}

/* ---- 命令行使用说明 ---- */
static void print_usage(const char *prog)
{
    printf("Usage: %s <config.json>\n", prog);
    printf("       %s -v | --version    Print version and exit\n", prog);
    printf("       %s -h | --help       Print this help and exit\n", prog);
    printf("\n");
    printf("KCP-over-AF_PACKET tunnel v" VERSION "\n");
    printf("Options:\n");
    printf("  <config.json>  Path to JSON configuration file (required)\n");
    printf("  -v, --version  Print version string\n");
    printf("  -h, --help     Print this help message\n");
}

static void print_version(void)
{
    printf("kcp-afpacket v" VERSION "\n");
}

/* ---- PID 文件 ---- */
static int write_pid_file(const char *path)
{
    if (!path || !path[0]) return 0;

    FILE *f = fopen(path, "w");
    if (!f) {
        LOG_ERROR("Cannot write PID file %s: %s", path, strerror(errno));
        return -1;
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);
    LOG_INFO("PID %d written to %s", getpid(), path);
    return 0;
}

#define DYNAMIC_CHANNEL_BASE 65536U

/* ---- 构建 listener ID 池基址 ---- */
static void build_listener_bases(global_ctx_t *ctx)
{
    uint32_t offset = DYNAMIC_CHANNEL_BASE;
    for (int i = 0; i < ctx->config.channel_count; i++) {
        uint32_t limit = (uint32_t)g_ctx->config.channels[i].max_sessions;
        if (limit == 0) limit = 1;
        ctx->listener_base[i] = offset;
        ctx->listener_next[i] = offset;
        offset += limit;
    }
}

/* ---- 清理 ---- */
static void cleanup(global_ctx_t *ctx)
{
    if (ctx == NULL) return;

    channel_close_all(ctx);
    /* Drain KCP buffers: allow in-flight data to flush during shutdown */
    {
        int drain_attempts;
        for (drain_attempts = 0; drain_attempts < 20; drain_attempts++) {
            channel_kcp_update(ctx);
            usleep(10000);  /* 10ms */
        }
    }
    channel_shutdown(ctx);
    proxy_shutdown(ctx);
    crypto_cleanup();

    if (ctx->raw_sock >= 0) {
        af_packet_close(ctx->raw_sock);
        ctx->raw_sock = -1;
    }

    if (ctx->epoll_fd >= 0) {
        close(ctx->epoll_fd);
        ctx->epoll_fd = -1;
    }

    /* 移除 PID 文件 */
    if (ctx->config.pid_file[0]) {
        unlink(ctx->config.pid_file);
        LOG_INFO("PID file %s removed", ctx->config.pid_file);
    }
}

/* ---- 配置热重载 ---- */
static int config_reload(global_ctx_t *ctx, const char *config_path)
{
    global_config_t *new_cfg = calloc(1, sizeof(global_config_t));
    if (!new_cfg) return -1;

    if (config_load(config_path, new_cfg) != 0) {
        LOG_ERROR("Config reload: failed to load %s", config_path);
        return -1;
    }

    if (validate_config(new_cfg) != 0) {
        LOG_ERROR("Config reload: validation failed");
        return -1;
    }

    /* Only update runtime-tunable params (not interface, MAC, channels) */
    ctx->config.crc_enabled        = new_cfg->crc_enabled;
    ctx->config.heartbeat_interval = new_cfg->heartbeat_interval;
    ctx->config.heartbeat_timeout  = new_cfg->heartbeat_timeout;
    /* Heartbeat params are read from g_ctx->config at check time (not cached per-channel) */
    ctx->config.kcp_nodelay        = new_cfg->kcp_nodelay;
    ctx->config.kcp_interval       = new_cfg->kcp_interval;
    ctx->config.kcp_resend         = new_cfg->kcp_resend;
    ctx->config.kcp_nc             = new_cfg->kcp_nc;
    ctx->config.kcp_send_window    = new_cfg->kcp_send_window;
    ctx->config.kcp_recv_window    = new_cfg->kcp_recv_window;

    /* Update KCP params on all existing channels */
    for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            if (ch->kcp) {
                ikcp_wndsize(ch->kcp, ctx->config.kcp_send_window, ctx->config.kcp_recv_window);
                ikcp_nodelay(ch->kcp, ctx->config.kcp_nodelay, ctx->config.kcp_interval,
                            ctx->config.kcp_resend, ctx->config.kcp_nc);
            }
            ch = ch->hash_next;
        }
    }

    /* Update encryption if encryption config changed */
    if (new_cfg->encryption.enabled != ctx->config.encryption.enabled ||
        strcmp(new_cfg->encryption.sm4_key, ctx->config.encryption.sm4_key) != 0) {
        crypto_cleanup();
        ctx->config.encryption = new_cfg->encryption;
        if (ctx->config.encryption.enabled) {
            if (crypto_init(&ctx->config.encryption) < 0) {
                LOG_ERROR("Config reload: crypto re-init failed, encryption disabled");
                ctx->config.encryption.enabled = 0;
            }
        }
    }

    LOG_INFO("Configuration reloaded successfully");
    free(new_cfg);
    return 0;
}

/* ---- 主入口 ---- */
#ifndef TEST_BUILD
int main(int argc, char *argv[])
{
    global_ctx_t   ctx;
    g_ctx = calloc(1, sizeof(global_ctx_t));
    if (!g_ctx) {
        fprintf(stderr, "FATAL: unable to allocate global context\n");
        return 1;
    }
    const char    *config_path = NULL;
    int            ret;
    uint32_t       last_periodic_ms = 0;
    uint32_t       last_stats_sec = 0;

    /* ================================================================
     * 1. 命令行参数解析
     * ================================================================ */
    {
        int opt;
        static struct option long_opts[] = {
            {"version", no_argument, 0, 'v'},
            {"help",    no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };

        while ((opt = getopt_long(argc, argv, "vh", long_opts, NULL)) != -1) {
            switch (opt) {
            case 'v':
                print_version();
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
            }
        }

        if (optind < argc) {
            config_path = argv[optind];
        } else {
            LOG_ERROR("Config file path is required");
            print_usage(argv[0]);
            return 1;
        }
    }

    /* ================================================================
     * 2. 初始化全局上下文
     * ================================================================ */
    memset(g_ctx, 0, sizeof(ctx));
    ctx.raw_sock = -1;
    ctx.epoll_fd = -1;
    ctx.running  = 1;
    ctx.reload_requested = 0;

    /* ================================================================
     * 3. 加载配置
     * ================================================================ */
    if (config_load(config_path, &ctx.config) != 0) {
        LOG_ERROR("Failed to load config from %s", config_path);
        return 1;
    }

    /* Save config path for hot-reload */
    strncpy(ctx.config_path, config_path, sizeof(ctx.config_path) - 1);
    ctx.config_path[sizeof(ctx.config_path) - 1] = '\0';

    /* ================================================================
     * 4. 验证配置
     * ================================================================ */
    if (validate_config(&ctx.config) != 0) {
        LOG_ERROR("Configuration validation failed");
        return 1;
    }

    /* ================================================================
     * 4b. 初始化加密模块
     * ================================================================ */
    if (ctx.config.encryption.enabled) {
        if (crypto_init(&g_ctx->config.encryption) < 0) {
            LOG_ERROR("Failed to initialize crypto module");
            return 1;
        }
        LOG_INFO("Crypto initialized (SM4-CBC + SM3-HMAC via Nettle)");
    }

    /* ================================================================
     * 5. 安装信号处理器
     * ================================================================ */
    if (setup_signals(&ctx) != 0) {
        LOG_ERROR("Failed to setup signal handlers");
        return 1;
    }

    /* ================================================================
     * 6. 初始化代理子系统
     * ================================================================ */
    if (proxy_init(&ctx) != 0) {
        LOG_ERROR("Failed to initialize proxy subsystem");
        return 1;
    }

    /* ================================================================
     * 7. 初始化通道子系统
     * ================================================================ */
    if (channel_init(g_ctx, ctx.config.max_channels) != 0) {
        LOG_ERROR("Failed to initialize channel subsystem");
        cleanup(g_ctx);
        return 1;
    }

    build_listener_bases(g_ctx);

    /* ================================================================
     * 8. 创建 AF_PACKET 原始套接字
     * ================================================================ */
    {
        uint16_t ethertype_n = htons(ctx.config.ethertype);

        ctx.raw_sock = af_packet_create(ctx.config.interface, ethertype_n, &ctx.ifindex);
        if (ctx.raw_sock < 0) {
            LOG_ERROR("Failed to create AF_PACKET socket on %s", ctx.config.interface);
            cleanup(g_ctx);
            return 1;
        }
        ctx.ethertype = ethertype_n;
        LOG_INFO("AF_PACKET socket created on %s, ifindex=%d", ctx.config.interface, ctx.ifindex);
    }

    /* ================================================================
     * 9. 获取本地 MAC
     * ================================================================ */
    if (mac_is_zero(ctx.config.local_mac)) {
        if (af_packet_get_mac(ctx.raw_sock, ctx.config.interface, ctx.local_mac) == 0) {
            LOG_INFO("Auto-discovered local MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                     ctx.local_mac[0], ctx.local_mac[1], ctx.local_mac[2],
                     ctx.local_mac[3], ctx.local_mac[4], ctx.local_mac[5]);
        } else {
            LOG_ERROR("Failed to auto-discover local MAC on %s", ctx.config.interface);
            cleanup(g_ctx);
            return 1;
        }
    } else {
        memcpy(ctx.local_mac, ctx.config.local_mac, ETH_MAC_ADDR_LEN);
    }

    /* ================================================================
     * 10. 对端 MAC
     * ================================================================ */
    if (mac_is_zero(ctx.config.peer_mac)) {
        LOG_INFO("Peer MAC not configured — using auto-discovery (broadcast initially)");
        memset(ctx.peer_mac, 0xFF, ETH_MAC_ADDR_LEN);
        ctx.peer_mac_learned = 0;
    } else {
        memcpy(ctx.peer_mac, ctx.config.peer_mac, ETH_MAC_ADDR_LEN);
        ctx.peer_mac_learned = 1;
    }

    /* ================================================================
     * 11. 自动设置 NIC MTU
     * ================================================================ */
    if (ctx.config.auto_set_nic_mtu) {
        if (af_packet_set_mtu(ctx.raw_sock, ctx.config.interface, ctx.config.nic_mtu) == 0) {
            LOG_INFO("NIC MTU set to %d on %s", ctx.config.nic_mtu, ctx.config.interface);
        } else {
            LOG_WARN("Failed to set NIC MTU to %d on %s", ctx.config.nic_mtu, ctx.config.interface);
        }
    }

    /* ================================================================
     * 12. 设置 BPF 过滤器
     * ================================================================ */
    if (af_packet_set_bpf(ctx.raw_sock, ctx.ethertype) != 0) {
        LOG_ERROR("Failed to set BPF filter for ethertype 0x%04X", ctx.config.ethertype);
        cleanup(g_ctx);
        return 1;
    }
    LOG_INFO("BPF filter set for ethertype 0x%04X", ctx.config.ethertype);

    /* ================================================================
     * 13. 创建通道并为每个通道启动代理监听
     * ================================================================ */
    for (int i = 0; i < ctx.config.channel_count; i++) {
        channel_config_t *ch_cfg = &g_ctx->config.channels[i];

        /* 统一使用 LISTENER 角色 — 不发 SYN，仅作为配置载体 */
        channel_t *ch = channel_create(g_ctx, ch_cfg->channel_id,
                                        CHANNEL_ROLE_LISTENER,
                                        ch_cfg->listen_port, ch_cfg->remote_port,
                                        ch_cfg->listen_addr, ch_cfg->remote_addr,
                                        ch_cfg->is_tcp);
        if (ch == NULL) {
            LOG_ERROR("Failed to create channel id=%u", ch_cfg->channel_id);
            cleanup(g_ctx);
            return 1;
        }

        /* 复制网络层信息（channel_create 已从 ctx 复制，此处确保一致性） */
        ch->raw_sock = ctx.raw_sock;
        ch->ifindex  = ctx.ifindex;
        memcpy(ch->local_mac, ctx.local_mac, ETH_MAC_ADDR_LEN);
        memcpy(ch->peer_mac,  ctx.peer_mac,  ETH_MAC_ADDR_LEN);
        ch->ethertype = ctx.ethertype;

        /* Listener 通道：设置防护标志，存储 array index（用于 alloc_channel_id） */
        ch->flags        = CH_FLAG_STATIC_LISTENER;
        ch->listener_idx = (uint8_t)i;

        /* 启动代理：frontend 节点监听本地端口 */
        if (ctx.config.node_type == NODE_TYPE_FRONTEND) {
            if (proxy_start_listen(g_ctx, ch) != 0) {
                LOG_ERROR("Failed to start listen for channel id=%u",
                          ch_cfg->channel_id);
                cleanup(g_ctx);
                return 1;
            }
        }

        LOG_INFO("Channel %u created: listen=%s:%u -> remote=%s:%u [%s]",
                 ch_cfg->channel_id,
                 ch_cfg->listen_addr, ch_cfg->listen_port,
                 ch_cfg->remote_addr, ch_cfg->remote_port,
                 ch_cfg->is_tcp ? "TCP" : "UDP");
    }

    /* ================================================================
     * 14. 将 AF_PACKET 套接字加入 epoll
     * ================================================================ */
    ret = proxy_epoll_add(g_ctx, ctx.raw_sock, NULL);
    if (ret != 0) {
        LOG_ERROR("Failed to add raw socket to epoll");
        cleanup(g_ctx);
        return 1;
    }

    /* ================================================================
     * 15. 初始化时间基准
     * ================================================================ */
    last_periodic_ms = kcp_wrap_clock();
    last_stats_sec   = time(NULL);

    LOG_INFO("KCP-over-AF_PACKET v" VERSION " started. "
             "Instance: %s, Mode: %s, interface: %s, ethertype: 0x%04X, channels: %d",
             ctx.config.instance_name,
             ctx.config.node_type == NODE_TYPE_FRONTEND ? "frontend" : "backend",
             ctx.config.interface, ctx.config.ethertype, ctx.config.channel_count);

    /* 写入 PID 文件 */
    write_pid_file(ctx.config.pid_file);

    /* ================================================================
     * 16. 主事件循环
     * ================================================================ */
    {
        struct epoll_event events[EPOLL_MAX_EVENTS];

        while (ctx.running) {
            int nfds = epoll_wait(ctx.epoll_fd, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);

            if (nfds < 0) {
                if (errno == EINTR) {
                    /* 被信号中断，检查是否退出或重载 */
                    if (ctx.reload_requested) {
                        if (config_reload(g_ctx, ctx.config_path) == 0) {
                            LOG_INFO("Configuration reloaded (SIGHUP)");
                        }
                        ctx.reload_requested = 0;
                    }
                    continue;
                }
                LOG_ERROR("epoll_wait failed: %s", strerror(errno));
                break;
            }

            /* ---- 处理 epoll 事件 ---- */
            for (int i = 0; i < nfds; i++) {
                int fd = events[i].data.fd;
                uint32_t ev = events[i].events;

                if (fd == ctx.raw_sock) {
                    /* AF_PACKET 可读：接收所有待处理的帧 */
                    uint8_t  buf[AF_PACKET_FRAME_SIZE];
                    uint8_t  src_mac[ETH_MAC_ADDR_LEN];
                    uint8_t  dst_mac[ETH_MAC_ADDR_LEN];
                    /* BPF ensures only our ethertype arrives, but keep param for defense-in-depth */
                    uint16_t ethtype __attribute__((unused));

                    int frame_count = 0;
                    while (frame_count < MAX_FRAMES_PER_CYCLE) {
                        ssize_t len = af_packet_recv(ctx.raw_sock, buf, sizeof(buf),
                                                     src_mac, dst_mac, &ethtype);
                        if (len < 0) {
                            /* EAGAIN/EWOULDBLOCK 表示无更多帧 */
                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                                break;
                            LOG_ERROR("af_packet_recv failed: %s", strerror(errno));
                            break;
                        }
                        if (len == 0) break;

                        frame_count++;

                        /* 解析协议头 */
                        const uint8_t *payload;
                        size_t         payload_len;
                        myproto_hdr_t  hdr;

                        if (myproto_parse_frame(buf, (size_t)len,
                                                &hdr, &payload, &payload_len) != 0) {
                            LOG_DEBUG("Failed to parse MyProto frame, len=%zd", len);
                            continue;
                        }

                        /* CRC 校验（仅对数据帧；控制帧不带CRC） */
                        if (ctx.config.crc_enabled && !IS_CTRL_FRAME(hdr.flags)) {
                            ssize_t data_len = myproto_verify_crc(buf, (size_t)len);
                            if (data_len < 0) {
                                LOG_DEBUG("CRC verification failed for frame");
                                continue;
                            }
                            /* data_len 为去除 CRC 后数据长度，但 payload_len
                             * 在 parse_frame 时已计算为去除 CRC 的长度，
                             * 此处我们只做校验，不修改 payload_len */
                        }

                        /* MAC auto-learning: if peer_mac is broadcast, learn from first valid frame */
                        if (ctx.peer_mac_learned == 0 && !mac_is_broadcast(src_mac) && !mac_is_zero(src_mac)) {
                            memcpy(ctx.peer_mac, src_mac, ETH_MAC_ADDR_LEN);
                            ctx.peer_mac_learned = 1;
                            LOG_INFO("Auto-learned peer MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                                     src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
                            /* Update all existing channels with learned MAC */
                            for (uint32_t i = 0; i < ctx.channel_hash_size; i++) {
                                channel_t *ch = ctx.channel_hash[i];
                                while (ch) {
                                    memcpy(ch->peer_mac, ctx.peer_mac, ETH_MAC_ADDR_LEN);
                                    ch = ch->hash_next;
                                }
                            }
                        }

                        /* 路由到通道处理 */
                        channel_process_frame(g_ctx, &hdr, payload, payload_len);
                    }
                    if (frame_count >= MAX_FRAMES_PER_CYCLE) {
                        LOG_WARN("Reached max frames per cycle (%d), possible frame flood", MAX_FRAMES_PER_CYCLE);
                    }
                } else {
                    /* 代理事件：本地套接字 I/O */
                    proxy_handle_event(g_ctx, fd, ev);
                }
            }

            /* ---- 周期性任务 (每 10ms 执行, 匹配 KCP_INTERVAL=10) ---- */
            {
                uint32_t now_ms = kcp_wrap_clock();

                if (now_ms - last_periodic_ms >= PERIODIC_INTERVAL_MS
                    || last_periodic_ms > now_ms) { /* 处理时间回绕 */
                    channel_kcp_update(&ctx);
                    channel_heartbeat(&ctx);
                    channel_timeout_check(&ctx);
                    last_periodic_ms = now_ms;
                }
            }

            /* ---- 统计输出（每 60 秒） ---- */
            if (ctx.config.stats_enabled) {
                uint32_t now_sec = time(NULL);
                if (now_sec - last_stats_sec >= STATS_INTERVAL_SEC) {
                    int active = channel_count(&ctx);
                    LOG_INFO("Stats: %d active channels, running=%d",
                             active, ctx.running);
                    last_stats_sec = now_sec;
                }
            }

            /* ---- 配置重载请求 ---- */
            if (ctx.reload_requested) {
                if (config_reload(g_ctx, ctx.config_path) == 0) {
                    LOG_INFO("Configuration reloaded (SIGHUP)");
                }
                ctx.reload_requested = 0;
            }
        }
    }

    /* ================================================================
     * 17. 清理退出
     * ================================================================ */
    LOG_INFO("Shutting down...");
    cleanup(g_ctx);
    LOG_INFO("KCP-over-AF_PACKET stopped.");

    return 0;
}
#endif /* !TEST_BUILD */
