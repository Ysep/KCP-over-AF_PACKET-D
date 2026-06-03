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
#include "acl.h"
#include "proxy.h"
#include "crypto.h"

#define VERSION             "1.0.0"
#define EPOLL_MAX_EVENTS    64
#define EPOLL_TIMEOUT_MS    10
#define PERIODIC_INTERVAL_MS 10
#define MAX_FRAMES_PER_CYCLE 1024
#define STATS_INTERVAL_SEC  60

/* ---- 全局上下文指针（信号处理器需要访问） ---- */
static global_ctx_t *g_ctx = NULL;

/* ---- 前向声明 ---- */
static void cleanup(global_ctx_t *ctx);

/* ──────────────────────────────────────────────────────────────────────────
 * signal_handler — 统一信号处理器
 *
 * 处理四种信号，全部通过设置全局标志位实现异步通知，信号处理器本身 O(1)：
 *
 *   SIGINT  / SIGTERM  → g_ctx->running = 0
 *     优雅退出：主循环检测到 running=0 后跳出，执行 cleanup() 清理资源。
 *
 *   SIGHUP             → g_ctx->reload_requested = 1
 *     配置热重载：主循环或 epoll_wait(EINTR) 路径检测到后调用 config_reload()。
 *
 *   SIGUSR1            → g_ctx->ctl_requested = 1
 *     通道快速增删：检测到后调用 handle_channel_ctl() 解析 control JSON 文件。
 *
 *   SIGPIPE            → SIG_IGN（在 setup_signals 中设置）
 *     忽略，防止向已关闭的 socket 写入导致进程异常退出。
 * ────────────────────────────────────────────────────────────────────────── */
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
    case SIGUSR1:
        g_ctx->ctl_requested = 1;
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
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        LOG_ERROR("Failed to set SIGUSR1 handler: %s", strerror(errno));
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

/* ──────────────────────────────────────────────────────────────────────────
 * config_load — 解析 JSON 配置文件
 *
 * 从 JSON 文件中逐字段解析全局配置，包括：
 *   - interface: 网卡名称（如 eth0）
 *   - ethertype: 自定义 EtherType（默认 0x88B5）
 *   - peer_mac / local_mac: MAC 地址（支持自动学习/自动获取）
 *   - kcp: KCP 参数（mtu, sndwnd, rcvwnd, nodelay, interval, resend, nc）
 *   - node_type: "frontend" 或 "backend"
 *   - max_channels: 最大通道数（默认 65536）
 *   - heartbeat_interval / heartbeat_timeout: 心跳间隔/超时
 *   - encryption: SM4 加密配置（enabled, sm4_key）
 *   - crc_enabled: 是否启用 CRC 校验
 *   - auto_set_nic_mtu / nic_mtu: MTU 自动设置
 *   - pid_file / instance_name: 进程管理
 *   - channels[]: 通道列表，每个通道包含：
 *     channel_id, listen_port, remote_port, listen_addr, remote_addr,
 *     is_tcp, max_sessions (上限256)
 *
 * @param path    JSON 配置文件路径
 * @param config  输出：填充后的全局配置结构体
 * @return        0=成功, -1=解析或分配失败
 * ────────────────────────────────────────────────────────────────────────── */

/* ── ACL 解析辅助 ── */

static uint32_t cidr_prefix_to_mask(int prefix_len)
{
    if (prefix_len <= 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFF;
    return htonl(0xFFFFFFFF << (32 - prefix_len));
}

static void parse_acl(json_object *obj, channel_acl_t *acl)
{
    memset(acl, 0, sizeof(*acl));

    json_object *acl_obj = json_object_object_get(obj, "client_acl");
    if (!acl_obj) return;  /* 未配置 → enabled 保持 0 */

    acl->enabled = 1;

    json_object *arr;

    /* ── IP 白名单 ── */
    if (json_object_object_get_ex(acl_obj, "ips", &arr) &&
        json_object_is_type(arr, json_type_array)) {
        int count = json_object_array_length(arr);
        for (int i = 0; i < count; i++) {
            if (acl->ip_count >= MAX_ACL_IPS) {
                LOG_WARN("parse_acl: ip_count exceeds MAX_ACL_IPS(%d), truncated",
                         MAX_ACL_IPS);
                break;
            }
            const char *str = json_object_get_string(
                json_object_array_get_idx(arr, (size_t)i));
            acl_ip_entry_t *entry = &acl->ips[acl->ip_count];

            /* 判断格式 */
            const char *slash = strchr(str, '/');
            const char *dash  = strchr(str, '-');

            if (slash) {
                /* CIDR: "10.0.1.0/24" */
                entry->type = ACL_IP_CIDR;
                char addr_buf[64];
                size_t len = (size_t)(slash - str);
                if (len < sizeof(addr_buf)) {
                    memcpy(addr_buf, str, len);
                    addr_buf[len] = '\0';
                    entry->addr = inet_addr(addr_buf);
                } else {
                    LOG_WARN("parse_acl: CIDR prefix too long (%zu chars), "
                             "entry skipped", len);
                    continue;
                }
                int prefix = atoi(slash + 1);
                entry->mask_or_end = cidr_prefix_to_mask(prefix);
            } else if (dash) {
                /* RANGE: "192.168.0.10-192.168.0.50" */
                entry->type = ACL_IP_RANGE;
                char start_buf[64];
                size_t len = (size_t)(dash - str);
                if (len < sizeof(start_buf)) {
                    memcpy(start_buf, str, len);
                    start_buf[len] = '\0';
                    entry->addr = inet_addr(start_buf);
                } else {
                    LOG_WARN("parse_acl: IP range start too long (%zu chars), "
                             "entry skipped", len);
                    continue;
                }
                entry->mask_or_end = inet_addr(dash + 1);
            } else {
                /* SINGLE: "10.0.0.5" */
                entry->type = ACL_IP_SINGLE;
                entry->addr = inet_addr(str);
            }

            if (entry->addr == INADDR_NONE && entry->type != ACL_IP_CIDR) {
                LOG_WARN("parse_acl: invalid IP '%s', skipped", str);
                continue;
            }
            acl->ip_count++;
        }
    }

    /* ── 端口白名单 ── */
    if (json_object_object_get_ex(acl_obj, "ports", &arr) &&
        json_object_is_type(arr, json_type_array)) {
        int count = json_object_array_length(arr);
        for (int i = 0; i < count; i++) {
            if (acl->port_count >= MAX_ACL_PORTS) {
                LOG_WARN("parse_acl: port_count exceeds MAX_ACL_PORTS(%d), truncated",
                         MAX_ACL_PORTS);
                break;
            }
            const char *str = json_object_get_string(
                json_object_array_get_idx(arr, (size_t)i));
            acl_port_entry_t *entry = &acl->ports[acl->port_count];

            const char *dash = strchr(str, '-');
            if (dash) {
                /* RANGE: "1024-65535" */
                entry->type = ACL_PORT_RANGE;
                entry->port_start = (uint16_t)atoi(str);
                entry->port_end   = (uint16_t)atoi(dash + 1);
                if (entry->port_start == 0 || entry->port_end == 0) {
                    LOG_WARN("parse_acl: invalid port range, entry skipped");
                    continue;
                }
            } else {
                /* SINGLE: "8080" */
                entry->type = ACL_PORT_SINGLE;
                entry->port_start = (uint16_t)atoi(str);
                if (entry->port_start == 0) {
                    LOG_WARN("parse_acl: invalid port, entry skipped");
                    continue;
                }
                entry->port_end   = entry->port_start;
            }
            acl->port_count++;
        }
    }
}

static int parse_port_range_value(json_object *obj, uint16_t *start, uint16_t *end)
{
    int a;
    int b;

    if (!obj || !start || !end) {
        return -1;
    }

    if (json_object_is_type(obj, json_type_array)) {
        if (json_object_array_length(obj) != 2) {
            return -1;
        }
        a = json_object_get_int(json_object_array_get_idx(obj, 0));
        b = json_object_get_int(json_object_array_get_idx(obj, 1));
    } else {
        const char *s = json_object_get_string(obj);
        char *tail = NULL;

        if (!s || !s[0]) {
            return -1;
        }

        errno = 0;
        long first = strtol(s, &tail, 10);
        if (errno != 0 || tail == s || *tail != '-') {
            return -1;
        }

        errno = 0;
        char *endptr = NULL;
        long second = strtol(tail + 1, &endptr, 10);
        if (errno != 0 || endptr == tail + 1 || *endptr != '\0') {
            return -1;
        }

        a = (int)first;
        b = (int)second;
    }

    if (a < 1 || a > 65535 || b < 1 || b > 65535 || a > b) {
        return -1;
    }

    *start = (uint16_t)a;
    *end = (uint16_t)b;
    return 0;
}

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
        if (raw_ethertype < 0x0600 || raw_ethertype > 0xFFFF) {
            LOG_ERROR("Ethertype 0x%04X out of range [0x0600, 0xFFFF]", raw_ethertype);
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
            channel_config_t base_cfg;
            uint16_t listen_start = 0;
            uint16_t listen_end = 0;
            uint16_t remote_start = 0;
            uint16_t remote_end = 0;
            uint32_t range_len = 1;
            uint8_t has_listen_range = 0;
            uint8_t has_remote_range = 0;

            memset(&base_cfg, 0, sizeof(base_cfg));

            if (json_object_object_get_ex(ch_obj, "channel_id", &tmp)) {
                int raw_id = json_object_get_int(tmp);
                if (raw_id <= 0) {
                    LOG_ERROR("Channel %d: channel_id must be > 0, got %d",
                              config->channel_count, raw_id);
                    goto cleanup;
                }
                base_cfg.channel_id = (uint32_t)raw_id;
            }

            if (json_object_object_get_ex(ch_obj, "listen_port_range", &tmp)) {
                if (parse_port_range_value(tmp, &listen_start, &listen_end) != 0) {
                    LOG_ERROR("Channel %d (id=%u): invalid listen_port_range",
                              config->channel_count, base_cfg.channel_id);
                    goto cleanup;
                }
                has_listen_range = 1;
            } else if (json_object_object_get_ex(ch_obj, "listen_port", &tmp)) {
                listen_start = (uint16_t)json_object_get_int(tmp);
                listen_end = listen_start;
            }

            if (json_object_object_get_ex(ch_obj, "remote_port_range", &tmp)) {
                if (parse_port_range_value(tmp, &remote_start, &remote_end) != 0) {
                    LOG_ERROR("Channel %d (id=%u): invalid remote_port_range",
                              config->channel_count, base_cfg.channel_id);
                    goto cleanup;
                }
                has_remote_range = 1;
            } else if (json_object_object_get_ex(ch_obj, "remote_port", &tmp)) {
                remote_start = (uint16_t)json_object_get_int(tmp);
                if (has_listen_range) {
                    uint32_t listen_len = (uint32_t)listen_end - listen_start + 1;
                    if ((uint32_t)remote_start + listen_len - 1 > 65535) {
                        LOG_ERROR("Channel %d (id=%u): remote_port base %u "
                                  "cannot cover listen_port_range length %u",
                                  config->channel_count, base_cfg.channel_id,
                                  remote_start, listen_len);
                        goto cleanup;
                    }
                    remote_end = (uint16_t)(remote_start + listen_len - 1);
                } else {
                    remote_end = remote_start;
                }
            }

            if (has_listen_range || has_remote_range) {
                if (!has_listen_range) {
                    LOG_ERROR("Channel %d (id=%u): remote_port_range requires "
                              "listen_port_range",
                              config->channel_count, base_cfg.channel_id);
                    goto cleanup;
                }

                uint32_t listen_len = (uint32_t)listen_end - listen_start + 1;
                uint32_t remote_len = (uint32_t)remote_end - remote_start + 1;
                if (listen_len != remote_len) {
                    LOG_ERROR("Channel %d (id=%u): listen_port_range and "
                              "remote_port_range lengths differ (%u vs %u)",
                              config->channel_count, base_cfg.channel_id,
                              listen_len, remote_len);
                    goto cleanup;
                }
                range_len = listen_len;
            }

            if (json_object_object_get_ex(ch_obj, "listen_addr", &tmp)) {
                const char *s = json_object_get_string(tmp);
                if (s) {
                    /* strncpy with manual NUL termination is intentional */
                    strncpy(base_cfg.listen_addr, s, MAX_LISTEN_ADDR - 1);
                    base_cfg.listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
                }
            }

            if (json_object_object_get_ex(ch_obj, "remote_addr", &tmp)) {
                const char *s = json_object_get_string(tmp);
                if (s) {
                    /* strncpy with manual NUL termination is intentional */
                    strncpy(base_cfg.remote_addr, s, MAX_REMOTE_ADDR - 1);
                    base_cfg.remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
                }
            }

            if (json_object_object_get_ex(ch_obj, "is_tcp", &tmp)) {
                base_cfg.is_tcp = json_object_get_boolean(tmp) ? 1 : 0;
            }

            base_cfg.enabled = 1;

            /* max_sessions: 0=默认1，上限65535 */
            if (json_object_object_get_ex(ch_obj, "max_sessions", &tmp)) {
                int ms = json_object_get_int(tmp);
                if (ms > 65535) {
                    LOG_WARN("Channel %d (id=%u): max_sessions %d exceeds 65535, capping",
                             config->channel_count, base_cfg.channel_id, ms);
                    base_cfg.max_sessions = 65535;
                } else {
                    base_cfg.max_sessions = (ms > 0) ? (uint16_t)ms : 1;
                }
            } else {
                base_cfg.max_sessions = 1;
            }

            /* 客户端 IP/端口 ACL */
            parse_acl(ch_obj, &base_cfg.client_acl);

            if ((uint64_t)base_cfg.channel_id + range_len - 1 > UINT32_MAX) {
                LOG_ERROR("Channel %d (id=%u): expanded channel_id range overflows",
                          config->channel_count, base_cfg.channel_id);
                goto cleanup;
            }

            if ((uint32_t)config->channel_count + range_len > MAX_CHANNELS) {
                LOG_ERROR("Too many channels after range expansion (%u), max is %d",
                          (uint32_t)config->channel_count + range_len,
                          MAX_CHANNELS);
                goto cleanup;
            }

            for (uint32_t offset = 0; offset < range_len; offset++) {
                channel_config_t *ch_cfg = &config->channels[config->channel_count];
                *ch_cfg = base_cfg;
                ch_cfg->channel_id = base_cfg.channel_id + offset;
                ch_cfg->listen_port = (uint16_t)(listen_start + offset);
                ch_cfg->remote_port = (uint16_t)(remote_start + offset);
                config->channel_count++;
            }
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

        /* listen_addr 和 remote_addr 进行完整性提示 */
        if (ch->listen_addr[0] == '\0')
            LOG_WARN("Channel %d (id=%u): listen_addr is empty (will default to 0.0.0.0)",
                     i, ch->channel_id);
        if (ch->remote_addr[0] == '\0')
            LOG_WARN("Channel %d (id=%u): remote_addr is empty",
                     i, ch->channel_id);

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
        if (strlen(config->encryption.sm4_key) != SM4_KEY_HEX_LEN) {
            LOG_ERROR("Encryption sm4_key must be exactly %d hex characters, got %zu",
                      SM4_KEY_HEX_LEN, strlen(config->encryption.sm4_key));
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

/* ──────────────────────────────────────────────────────────────────────────
 * build_listener_bases — 构建 listener ID 池基址
 *
 * 为每个 listener 分配一段连续的 channel_id 范围，用于多会话模式下的
 * 动态子通道 ID 分配。
 *
 * 算法：从 DYNAMIC_CHANNEL_BASE (65536) 开始，每个 listener 获得
 *       max_sessions 个 ID 的空间。listener_base[i] 记录起始偏移，
 *       listener_next[i] 记录下一个可分配的 ID（由 alloc_channel_id 消费）。
 *
 * 例如：channel[0].max_sessions=5 → 使用 ID 65536-65540
 *       channel[1].max_sessions=3 → 使用 ID 65541-65543
 *       ...
 *
 * limit=0 时自动提升为 1，确保每个 listener 至少有一个动态 ID 可用。
 * ────────────────────────────────────────────────────────────────────────── */
static void build_listener_bases(global_ctx_t *ctx)
{
    uint32_t offset = DYNAMIC_CHANNEL_BASE;
    for (int i = 0; i < ctx->config.channel_count; i++) {
        uint32_t limit = (uint32_t)ctx->config.channels[i].max_sessions;
        if (limit == 0) limit = 1;
        ctx->listener_base[i] = offset;
        ctx->listener_next[i] = offset;
        offset += limit;
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * cleanup — 优雅关闭，严格的逆序清理
 *
 * 关闭顺序（与初始化顺序相反）：
 *   1. channel_close_all()        — 遍历所有通道，发送 FIN 控制帧
 *   2. KCP 缓冲区排空              — 循环 channel_kcp_update() + usleep(10ms)
 *                                    最多 20 次（200ms），确保在途数据尽力发送
 *   3. channel_shutdown()         — 销毁所有通道 + 释放哈希表
 *   4. proxy_shutdown()           — 关闭 epoll_fd
 *   5. crypto_cleanup()           — 释放 SM4/SM3 上下文
 *   6. af_packet_close()          — 关闭 AF_PACKET 原始套接字
 *   7. close(epoll_fd)            — 关闭 epoll 实例
 *   8. unlink(pid_file)           — 删除 PID 文件
 *
 * 设计考量：先排空 KCP 缓冲区再销毁通道，确保关闭前的数据尽可能送达对端。
 * 每步操作都会检查 fd >= 0 以避免 double-close。
 * ────────────────────────────────────────────────────────────────────────── */
static void cleanup(global_ctx_t *ctx)
{
    if (ctx == NULL) return;

    if (ctx->channel_hash) {
        channel_close_all(ctx);
    }
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

/* ──────────────────────────────────────────────────────────────────────────
 * config_reload_channels — 4 步算法：Mark → Diff → Clean → Update
 *
 * Step 1 — Mark（标记）：
 *   遍历哈希表中所有通道，对 CH_FLAG_STATIC_LISTENER 设置 CH_FLAG_RELOAD_MARKED。
 *
 * Step 2 — Diff（差异对比）：
 *   遍历新配置 channels[]，对比旧通道：
 *     情况 A: channel_id 已存在 + 旧通道是 STATIC_LISTENER
 *       - 清除 RELOAD_MARKED 标志
 *       - enabled=false → 移除 STATIC_LISTENER → channel_destroy()
 *       - 配置有变更 → proxy_port_probe() 预检 → proxy_stop_listen() →
 *         channel_update_config() → proxy_start_listen()
 *       - 无变更 → 仅更新 listener_idx
 *     情况 B: channel_id 不存在 + enabled=true
 *       - proxy_port_conflict() 端口冲突检测
 *       - channel_create() → 复制网络层信息 → proxy_start_listen()
 *
 * Step 3 — Clean（清理）：
 *   再次扫描哈希表，清理仍带 RELOAD_MARKED 的旧 listener
 *   （说明新配置中已不存在，执行 channel_destroy）。
 *
 * Step 4 — Update（更新 channels[] 数组）：
 *   将新配置通道复制到 updated_channels[]；
 *   保留旧配置中已不存在但数组空间仍有的 disabled 条目（保持索引稳定）。
 *   最后 memcpy 到 ctx->config.channels。
 * ────────────────────────────────────────────────────────────────────────── */
static void config_reload_channels(global_ctx_t *ctx,
                                   const global_config_t *new_cfg)
{
    /* Step 1: 标记所有现存的 listener 通道 */
    for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            if (ch->flags & CH_FLAG_STATIC_LISTENER)
                ch->flags |= CH_FLAG_RELOAD_MARKED;
            ch = ch->hash_next;
        }
    }

    /* Step 2: 遍历新配置，匹配 + 增/改 */
    for (int i = 0; i < new_cfg->channel_count; i++) {
        const channel_config_t *new_ch = &new_cfg->channels[i];
        channel_t *old_ch = channel_find(ctx, new_ch->channel_id);

        if (old_ch && (old_ch->flags & CH_FLAG_STATIC_LISTENER)) {
            /* 情况 A: channel_id 已存在 */
            old_ch->flags &= ~CH_FLAG_RELOAD_MARKED;

            if (!new_ch->enabled) {
                /* 禁用：清除 STATIC_LISTENER → channel_destroy */
                old_ch->flags &= ~CH_FLAG_STATIC_LISTENER;
                channel_destroy(ctx, old_ch);
                LOG_INFO("config_reload: channel %u disabled and destroyed",
                         new_ch->channel_id);
                continue;
            }

            /* ACL 变更检测（channel_config_changed 不接收 ctx） */
            int acl_changed = (memcmp(
                &ctx->config.channels[old_ch->listener_idx].client_acl,
                &new_ch->client_acl,
                sizeof(channel_acl_t)) != 0);

            if (channel_config_changed(old_ch, new_ch) || acl_changed) {
                /* 修改通道：预检 → 关闭旧 listener → 更新配置 → 启动新 */
                if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
                    if (proxy_port_probe(new_ch->listen_addr,
                                          new_ch->listen_port,
                                          new_ch->is_tcp) != 0) {
                        LOG_ERROR("config_reload: port %s:%u unavailable for "
                                  "channel %u, keeping old listener unchanged",
                                  new_ch->listen_addr, new_ch->listen_port,
                                  old_ch->channel_id);
                        continue;
                    }
                }

                proxy_stop_listen(ctx, old_ch);
                channel_update_config(old_ch, new_ch);
                old_ch->listener_idx = (uint16_t)i;

                if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
                    if (proxy_start_listen(ctx, old_ch) != 0) {
                        LOG_ERROR("config_reload: new listen failed for "
                                  "channel %u after config change",
                                  old_ch->channel_id);
                    }
                }
                LOG_INFO("config_reload: channel %u updated", old_ch->channel_id);
            } else {
                /* 无变更，仅更新 listener_idx */
                old_ch->listener_idx = (uint16_t)i;
            }

        } else if (new_ch->enabled) {
            /* 情况 B: channel_id 不存在 → 新建 */
            if (ctx->config.node_type == NODE_TYPE_FRONTEND &&
                proxy_port_conflict(ctx, new_ch->listen_addr,
                                     new_ch->listen_port,
                                     new_ch->channel_id)) {
                LOG_ERROR("config_reload: port %s:%u already in use, "
                          "skipping new channel %u",
                          new_ch->listen_addr, new_ch->listen_port,
                          new_ch->channel_id);
                continue;
            }

            channel_t *ch = channel_create(ctx, new_ch->channel_id,
                                           CHANNEL_ROLE_LISTENER,
                                           new_ch->listen_port,
                                           new_ch->remote_port,
                                           new_ch->listen_addr,
                                           new_ch->remote_addr,
                                           new_ch->is_tcp);
            if (!ch) {
                LOG_ERROR("config_reload: failed to create channel %u",
                          new_ch->channel_id);
                continue;
            }

            ch->raw_sock  = ctx->raw_sock;
            ch->ifindex   = ctx->ifindex;
            memcpy(ch->local_mac, ctx->local_mac, ETH_MAC_ADDR_LEN);
            memcpy(ch->peer_mac,  ctx->peer_mac,  ETH_MAC_ADDR_LEN);
            ch->ethertype = ctx->ethertype;
            ch->flags     = CH_FLAG_STATIC_LISTENER;
            ch->listener_idx = (uint16_t)i;

            if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
                if (proxy_start_listen(ctx, ch) != 0) {
                    LOG_ERROR("config_reload: listen failed for new channel %u",
                              new_ch->channel_id);
                    ch->flags &= ~CH_FLAG_STATIC_LISTENER;
                    channel_destroy(ctx, ch);
                    continue;
                }
            }
            LOG_INFO("config_reload: channel %u created", new_ch->channel_id);
        }
    }

    /* Step 3: 清理未匹配的旧 listener（仍带 RELOAD_MARKED） */
    for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            channel_t *next = ch->hash_next;
            if ((ch->flags & CH_FLAG_STATIC_LISTENER) &&
                (ch->flags & CH_FLAG_RELOAD_MARKED)) {
                ch->flags &= ~CH_FLAG_STATIC_LISTENER;
                channel_destroy(ctx, ch);
                LOG_INFO("config_reload: channel %u removed", ch->channel_id);
            } else {
                ch->flags &= ~CH_FLAG_RELOAD_MARKED;
            }
            ch = next;
        }
    }

    /* Step 4: 刷新 channels[] 数组（保留 disabled 条目保持索引稳定） */
    channel_config_t *updated_channels = calloc(MAX_CHANNELS, sizeof(channel_config_t));
    if (!updated_channels) {
        LOG_ERROR("config_reload_channels: failed to allocate updated_channels");
        return;
    }
    int updated_count = 0;

    for (int i = 0; i < new_cfg->channel_count; i++) {
        updated_channels[updated_count++] = new_cfg->channels[i];
    }

    for (int i = 0; i < ctx->config.channel_count; i++) {
        const channel_config_t *old = &ctx->config.channels[i];
        int found = 0;
        for (int j = 0; j < new_cfg->channel_count; j++) {
            if (new_cfg->channels[j].channel_id == old->channel_id) {
                found = 1;
                break;
            }
        }
        if (!found && updated_count < MAX_CHANNELS) {
            updated_channels[updated_count] = *old;
            updated_channels[updated_count].enabled = 0;
            updated_count++;
        }
    }

    ctx->config.channel_count = updated_count;
    memcpy(ctx->config.channels, updated_channels,
           (size_t)updated_count * sizeof(channel_config_t));
    free(updated_channels);
}

/* ──────────────────────────────────────────────────────────────────────────
 * config_reload — SIGHUP 触发的配置热重载
 *
 * 两阶段重载策略：
 *
 *   阶段一：软参数更新（no-restart）
 *     直接应用到运行中的配置，无需重启任何通道：
 *     - crc_enabled, heartbeat_interval, heartbeat_timeout
 *     - KCP 参数（nodelay, interval, resend, nc, send/recv window）
 *       更新到 config 并通过 ikcp_wndsize() + ikcp_nodelay() 应用到所有通道的 kcp 实例
 *
 *   阶段二：通道 diff 更新（通过 config_reload_channels）
 *     对比新旧 channels[] 数组，执行增/改/删操作。
 *     修改现有通道时先 proxy_port_probe() 预检新端口可用性，
 *     再 proxy_stop_listen() → channel_update_config() → proxy_start_listen()。
 *     best-effort 策略：单个通道失败不回滚，继续处理后续通道。
 *
 *   加密配置变更检测：若 encryption.enabled 或 sm4_key 变化，
 *   先 crypto_cleanup() 再 crypto_init() 重新初始化加密模块。
 *
 * @param ctx         全局上下文
 * @param config_path 配置文件路径
 * @return            0=成功, -1=加载或验证失败
 * ────────────────────────────────────────────────────────────────────────── */
static int config_reload(global_ctx_t *ctx, const char *config_path)
{
    global_config_t *new_cfg = calloc(1, sizeof(global_config_t));
    if (!new_cfg) return -1;

    if (config_load(config_path, new_cfg) != 0) {
        LOG_ERROR("Config reload: failed to load %s", config_path);
        free(new_cfg);
        return -1;
    }

    if (validate_config(new_cfg) != 0) {
        LOG_ERROR("Config reload: validation failed");
        free(new_cfg);
        return -1;
    }

    /* ---- 通道 diff 与增删改（best-effort，失败不回滚） ---- */
    config_reload_channels(ctx, new_cfg);

    /* Update runtime-tunable params (not interface, MAC) */
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

/* ──────────────────────────────────────────────────────────────────────────
 * handle_channel_ctl — SIGUSR1 触发的通道快速增删
 *
 * 控制文件命名规则：config.json → config-ctl.json
 *
 * JSON 控制文件格式（单个或数组）：
 *   { "op": "add", "channel_id": 100, "listen_port": 8080, ... }
 *   { "op": "del", "channel_id": 100 }
 *
 * 处理流程：
 *   1. json_object_from_file() 读取控制文件
 *   2. 遍历每个命令，调用 channel_ctl_add() 或 channel_ctl_del()
 *   3. 统计 added/deleted/errors 数量
 *   4. 清空控制文件（fopen("w") + fclose，实现幂等处理）
 *
 * 幂等性保证：控制文件被处理后立即清空，即使重复触发 SIGUSR1
 * 也不会重复执行相同的命令。
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * 解析 JSON 中的单个通道配置。
 */
static int ctl_parse_channel(json_object *ch_obj, channel_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled  = 1;
    cfg->is_tcp   = 1;

    json_object *tmp;
    if (json_object_object_get_ex(ch_obj, "channel_id", &tmp))
        cfg->channel_id = (uint32_t)json_object_get_int64(tmp);
    else { LOG_ERROR("ctl: missing channel_id"); return -1; }

    if (json_object_object_get_ex(ch_obj, "listen_port", &tmp))
        cfg->listen_port = (uint16_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(ch_obj, "remote_port", &tmp))
        cfg->remote_port = (uint16_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(ch_obj, "listen_addr", &tmp)) {
        strncpy(cfg->listen_addr, json_object_get_string(tmp), MAX_LISTEN_ADDR - 1);
        cfg->listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
    }
    if (json_object_object_get_ex(ch_obj, "remote_addr", &tmp)) {
        strncpy(cfg->remote_addr, json_object_get_string(tmp), MAX_REMOTE_ADDR - 1);
        cfg->remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
    }
    if (json_object_object_get_ex(ch_obj, "is_tcp", &tmp))
        cfg->is_tcp = (uint8_t)json_object_get_int(tmp);
    if (json_object_object_get_ex(ch_obj, "max_sessions", &tmp)) {
        int ms = json_object_get_int(tmp);
        cfg->max_sessions = (ms > 0 && ms <= 65535) ? (uint16_t)ms : 1;
    }
    parse_acl(ch_obj, &cfg->client_acl);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * channel_ctl_add — O(1) 添加新 listener 通道
 *
 * 快速添加流程（不经过 config_reload 的完整 diff 算法）：
 *   1. channel_find() 检查 ID 是否已存在（O(1) 哈希查找）
 *   2. proxy_port_conflict() 端口冲突检测（仅 frontend）
 *   3. channel_create() 创建通道
 *   4. 复制网络层信息（raw_sock, ifindex, MAC, ethertype）
 *   5. 设置 CH_FLAG_STATIC_LISTENER + listener_idx
 *   6. proxy_start_listen() 启动监听（仅 frontend）
 *   7. 追加到 ctx->config.channels[] 数组末尾
 *   8. build_listener_bases() 重建 ID 池基址
 *
 * 不触发通道 diff，不重载配置文件，仅操作单个通道。
 * ────────────────────────────────────────────────────────────────────────── */
static int channel_ctl_add(global_ctx_t *ctx, const channel_config_t *cfg)
{
    if (channel_find(ctx, cfg->channel_id)) {
        LOG_ERROR("ctl_add: channel %u already exists", cfg->channel_id);
        return -1;
    }
    if (ctx->config.node_type == NODE_TYPE_FRONTEND &&
        proxy_port_conflict(ctx, cfg->listen_addr, cfg->listen_port, 0)) {
        LOG_ERROR("ctl_add: port %s:%u already in use", cfg->listen_addr, cfg->listen_port);
        return -1;
    }
    channel_t *ch = channel_create(ctx, cfg->channel_id, CHANNEL_ROLE_LISTENER,
                                    cfg->listen_port, cfg->remote_port,
                                    cfg->listen_addr, cfg->remote_addr, cfg->is_tcp);
    if (!ch) { LOG_ERROR("ctl_add: create failed for %u", cfg->channel_id); return -1; }
    ch->raw_sock  = ctx->raw_sock;
    ch->ifindex   = ctx->ifindex;
    memcpy(ch->local_mac, ctx->local_mac, ETH_MAC_ADDR_LEN);
    memcpy(ch->peer_mac,  ctx->peer_mac,  ETH_MAC_ADDR_LEN);
    ch->ethertype = ctx->ethertype;
    ch->flags     = CH_FLAG_STATIC_LISTENER;
    ch->listener_idx = (uint16_t)ctx->config.channel_count;
    if (ctx->config.node_type == NODE_TYPE_FRONTEND) {
        if (proxy_start_listen(ctx, ch) != 0) {
            ch->flags &= ~CH_FLAG_STATIC_LISTENER;
            channel_destroy(ctx, ch);
            return -1;
        }
    }
    if (ctx->config.channel_count < MAX_CHANNELS) {
        ctx->config.channels[ctx->config.channel_count++] = *cfg;
        build_listener_bases(ctx);
    }
    LOG_INFO("ctl: channel %u added (listen=%s:%u)", cfg->channel_id, cfg->listen_addr, cfg->listen_port);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * channel_ctl_del — O(1) 删除 listener 通道
 *
 * 快速删除流程：
 *   1. channel_find() 查找通道（O(1) 哈希查找）
 *   2. 检查是否为 STATIC_LISTENER（非 listener 不可通过 ctl 删除）
 *   3. proxy_stop_listen() 关闭监听套接字（保留动态子通道）
 *   4. 清除 CH_FLAG_STATIC_LISTENER
 *   5. channel_destroy() 销毁通道（释放 KCP、哈希表条目）
 *   6. 在 channels[] 数组中标记 enabled=0
 *
 * 注意：本函数只关闭 listener 自身，不影响其动态子通道。
 *       子通道由 channel_timeout_check() 按超时自动回收。
 * ────────────────────────────────────────────────────────────────────────── */
static int channel_ctl_del(global_ctx_t *ctx, uint32_t channel_id)
{
    channel_t *ch = channel_find(ctx, channel_id);
    if (!ch || !(ch->flags & CH_FLAG_STATIC_LISTENER)) {
        LOG_ERROR("ctl_del: listener %u not found", channel_id);
        return -1;
    }
    proxy_stop_listen(ctx, ch);
    ch->flags &= ~CH_FLAG_STATIC_LISTENER;
    channel_destroy(ctx, ch);
    for (int i = 0; i < ctx->config.channel_count; i++) {
        if (ctx->config.channels[i].channel_id == channel_id) {
            ctx->config.channels[i].enabled = 0;
            break;
        }
    }
    LOG_INFO("ctl: channel %u removed", channel_id);
    return 0;
}

static void handle_channel_ctl(global_ctx_t *ctx)
{
    /* 构造控制文件路径: config.json → config-ctl.json */
    char ctl_path[512];
    size_t len = strnlen(ctx->config_path, sizeof(ctx->config_path) - 1);
    if (len > 5 && strcmp(ctx->config_path + len - 5, ".json") == 0) {
        snprintf(ctl_path, sizeof(ctl_path), "%.*s-ctl.json", (int)(len - 5), ctx->config_path);
    } else {
        snprintf(ctl_path, sizeof(ctl_path), "%s-ctl.json", ctx->config_path);
    }

    json_object *root = json_object_from_file(ctl_path);
    if (!root) return;  /* 文件不存在 → 静默跳过 */

    int added = 0, deleted = 0, errors = 0;
    int is_array = json_object_is_type(root, json_type_array);
    int count     = is_array ? (int)json_object_array_length(root) : 1;

    for (int i = 0; i < count; i++) {
        json_object *cmd = is_array ? json_object_array_get_idx(root, (size_t)i) : root;
        json_object *tmp;
        if (!json_object_object_get_ex(cmd, "op", &tmp)) { errors++; continue; }
        const char *op = json_object_get_string(tmp);

        if (strcmp(op, "add") == 0) {
            channel_config_t cfg;
            if (ctl_parse_channel(cmd, &cfg) == 0 && channel_ctl_add(ctx, &cfg) == 0)
                added++;
            else errors++;
        } else if (strcmp(op, "del") == 0) {
            json_object *id_obj;
            if (json_object_object_get_ex(cmd, "channel_id", &id_obj)) {
                if (channel_ctl_del(ctx, (uint32_t)json_object_get_int64(id_obj)) == 0)
                    deleted++;
                else errors++;
            } else errors++;
        } else {
            LOG_ERROR("ctl: unknown op '%s'", op);
            errors++;
        }
    }
    json_object_put(root);

    /* 清空控制文件（幂等处理） */
    FILE *f = fopen(ctl_path, "w");
    if (f) fclose(f);

    LOG_INFO("ctl: processed %d ops (add=%d del=%d errors=%d)", count, added, deleted, errors);
}

/* ---- 通道热重载 ---- */

/* ──────────────────────────────────────────────────────────────────────────
 * main — 程序入口，13 步启动序列
 *
 *   1. 命令行参数解析 (-v/-h/<config.json>)
 *   2. 初始化全局上下文 (memset, raw_sock=-1, epoll_fd=-1, running=1)
 *   3. config_load() — 解析 JSON 配置文件
 *   4. validate_config() — 配置合法性校验
 *   4b. crypto_init() — SM4/SM3 加密模块初始化（若启用）
 *   5. setup_signals() — 安装 SIGHUP/SIGUSR1/SIGINT/SIGTERM/SIGPIPE
 *   6. proxy_init() — 创建 epoll 实例 (EPOLL_CLOEXEC)
 *   7. channel_init() — 分配哈希表 (max_channels*2 个桶)
 *      build_listener_bases() — 构建动态 ID 池基址
 *   8. af_packet_create() — AF_PACKET 原始套接字 (TPACKET_V2)
 *   9. af_packet_get_mac() — 自动获取本地 MAC（若未配置）
 *   10. 对端 MAC 确定（未配置→广播地址 FF:FF:FF:FF:FF:FF，启动自动学习）
 *   11. af_packet_set_mtu() — 自动设置 NIC MTU（可选）
 *   12. af_packet_set_bpf() — BPF 内核级 EtherType 过滤
 *   13. 遍历 channels[] → channel_create() + proxy_start_listen()
 *
 *   14. proxy_epoll_add(raw_sock) — AF_PACKET 加入 epoll
 *   15. 初始化时间基准 (kcp_wrap_clock, time)
 *   16. 主事件循环
 *   17. cleanup() — 优雅关闭
 * ────────────────────────────────────────────────────────────────────────── */
#ifndef TEST_BUILD
int main(int argc, char *argv[])
{
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
    memset(g_ctx, 0, sizeof(global_ctx_t));
    g_ctx->raw_sock = -1;
    g_ctx->epoll_fd = -1;
    g_ctx->running  = 1;
    g_ctx->reload_requested = 0;
    g_ctx->ctl_requested    = 0;

    /* ================================================================
     * 3. 加载配置
     * ================================================================ */
    if (config_load(config_path, &g_ctx->config) != 0) {
        LOG_ERROR("Failed to load config from %s", config_path);
        return 1;
    }

    /* Save config path for hot-reload */
    strncpy(g_ctx->config_path, config_path, sizeof(g_ctx->config_path) - 1);
    g_ctx->config_path[sizeof(g_ctx->config_path) - 1] = '\0';

    /* ================================================================
     * 4. 验证配置
     * ================================================================ */
    if (validate_config(&g_ctx->config) != 0) {
        LOG_ERROR("Configuration validation failed");
        return 1;
    }

    /* ================================================================
     * 4b. 初始化加密模块
     * ================================================================ */
    if (g_ctx->config.encryption.enabled) {
        if (crypto_init(&g_ctx->config.encryption) < 0) {
            LOG_ERROR("Failed to initialize crypto module");
            return 1;
        }
        LOG_INFO("Crypto initialized (SM4-CBC + SM3-HMAC via Nettle)");
    }

    /* ================================================================
     * 5. 安装信号处理器
     * ================================================================ */
    if (setup_signals(g_ctx) != 0) {
        LOG_ERROR("Failed to setup signal handlers");
        crypto_cleanup();
        return 1;
    }

    /* ================================================================
     * 6. 初始化代理子系统
     * ================================================================ */
    if (proxy_init(g_ctx) != 0) {
        LOG_ERROR("Failed to initialize proxy subsystem");
        return 1;
    }

    /* ================================================================
     * 7. 初始化通道子系统
     * ================================================================ */
    if (channel_init(g_ctx, g_ctx->config.max_channels) != 0) {
        LOG_ERROR("Failed to initialize channel subsystem");
        cleanup(g_ctx);
        return 1;
    }

    build_listener_bases(g_ctx);

    /* ================================================================
     * 8. 创建 AF_PACKET 原始套接字
     * ================================================================ */
    {
        uint16_t ethertype_n = htons(g_ctx->config.ethertype);

        /* 检测 AF_PACKET 冲突（同一接口上已有其他实例使用此 EtherType） */
        if (af_packet_detect_conflict(g_ctx->config.interface,
                                       g_ctx->config.ethertype) != 0) {
            LOG_WARN("AF_PACKET conflict detected on %s (EtherType=0x%04X)",
                     g_ctx->config.interface, g_ctx->config.ethertype);
        }

        g_ctx->raw_sock = af_packet_create(g_ctx->config.interface, ethertype_n, &g_ctx->ifindex);
        if (g_ctx->raw_sock < 0) {
            LOG_ERROR("Failed to create AF_PACKET socket on %s", g_ctx->config.interface);
            cleanup(g_ctx);
            return 1;
        }
        g_ctx->ethertype = ethertype_n;
        LOG_INFO("AF_PACKET socket created on %s, ifindex=%d", g_ctx->config.interface, g_ctx->ifindex);
    }

    /* ================================================================
     * 9. 获取本地 MAC
     * ================================================================ */
    if (mac_is_zero(g_ctx->config.local_mac)) {
        if (af_packet_get_mac(g_ctx->raw_sock, g_ctx->config.interface, g_ctx->local_mac) == 0) {
            LOG_INFO("Auto-discovered local MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                     g_ctx->local_mac[0], g_ctx->local_mac[1], g_ctx->local_mac[2],
                     g_ctx->local_mac[3], g_ctx->local_mac[4], g_ctx->local_mac[5]);
        } else {
            LOG_ERROR("Failed to auto-discover local MAC on %s", g_ctx->config.interface);
            cleanup(g_ctx);
            return 1;
        }
    } else {
        memcpy(g_ctx->local_mac, g_ctx->config.local_mac, ETH_MAC_ADDR_LEN);
    }

    /* ================================================================
     * 10. 对端 MAC
     * ================================================================ */
    if (mac_is_zero(g_ctx->config.peer_mac)) {
        LOG_INFO("Peer MAC not configured — using auto-discovery (broadcast initially)");
        memset(g_ctx->peer_mac, 0xFF, ETH_MAC_ADDR_LEN);
        g_ctx->peer_mac_learned = 0;
    } else {
        memcpy(g_ctx->peer_mac, g_ctx->config.peer_mac, ETH_MAC_ADDR_LEN);
        g_ctx->peer_mac_learned = 1;
    }

    /* ================================================================
     * 11. 自动设置 NIC MTU
     * ================================================================ */
    if (g_ctx->config.auto_set_nic_mtu) {
        if (af_packet_set_mtu(g_ctx->raw_sock, g_ctx->config.interface, g_ctx->config.nic_mtu) == 0) {
            LOG_INFO("NIC MTU set to %d on %s", g_ctx->config.nic_mtu, g_ctx->config.interface);
        } else {
            LOG_WARN("Failed to set NIC MTU to %d on %s", g_ctx->config.nic_mtu, g_ctx->config.interface);
        }
    }

    /* ================================================================
     * 12. 设置 BPF 过滤器
     * ================================================================ */
    if (af_packet_set_bpf(g_ctx->raw_sock, g_ctx->ethertype) != 0) {
        LOG_ERROR("Failed to set BPF filter for ethertype 0x%04X", g_ctx->config.ethertype);
        cleanup(g_ctx);
        return 1;
    }
    LOG_INFO("BPF filter set for ethertype 0x%04X", g_ctx->config.ethertype);

    /* ================================================================
     * 13. 创建通道并为每个通道启动代理监听
     * ================================================================ */
    for (int i = 0; i < g_ctx->config.channel_count; i++) {
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
        ch->raw_sock = g_ctx->raw_sock;
        ch->ifindex  = g_ctx->ifindex;
        memcpy(ch->local_mac, g_ctx->local_mac, ETH_MAC_ADDR_LEN);
        memcpy(ch->peer_mac,  g_ctx->peer_mac,  ETH_MAC_ADDR_LEN);
        ch->ethertype = g_ctx->ethertype;

        /* Listener 通道：设置防护标志，存储 array index（用于 alloc_channel_id） */
        ch->flags        = CH_FLAG_STATIC_LISTENER;
        ch->listener_idx = (uint16_t)i;

        /* 启动代理：frontend 节点监听本地端口 */
        if (g_ctx->config.node_type == NODE_TYPE_FRONTEND) {
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
    ret = proxy_epoll_add(g_ctx, g_ctx->raw_sock, NULL);
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
             g_ctx->config.instance_name,
             g_ctx->config.node_type == NODE_TYPE_FRONTEND ? "frontend" : "backend",
             g_ctx->config.interface, g_ctx->config.ethertype, g_ctx->config.channel_count);

    /* 写入 PID 文件 */
    write_pid_file(g_ctx->config.pid_file);

    /* ──────────────────────────────────────────────────────────────────────
     * 16. 主事件循环 — epoll_wait → proxy_handle_event → flush → periodic
     *
     * 循环体内五阶段流水线：
     *
     *   a) epoll_wait(10ms timeout)
     *      EINTR → 检查 reload_requested/ctl_requested 标志
     *      其他错误 → break 退出
     *
     *   b) 事件分发
     *      raw_sock 就绪 → af_packet_recv() 循环读取帧
     *        → MAC auto-learning（首次收到非广播帧时学习对端 MAC）
     *        → channel_process_frame() 路由帧到对应通道
     *      代理 fd 就绪 → proxy_handle_event() 分发到 accept/read/write
     *
     *   c) 周期性任务（每 10ms，匹配 KCP_INTERVAL=10）
     *      channel_kcp_update()     — 驱动所有通道的 KCP ikcp_update()
     *      channel_heartbeat()      — 发送心跳帧
     *      channel_timeout_check()  — 超时检测，回收死连接
     *
     *   d) 统计输出（每 60 秒）
     *      channel_count() + LOG_INFO
     *
     *   e) 配置重载检查（reload_requested 标志）
     *      config_reload() — 软参数更新 + 通道 diff
     *
     * 性能保护：MAX_FRAMES_PER_CYCLE=64，防止单次循环处理过多帧
     *           导致饿死代理 I/O 事件。
     * ────────────────────────────────────────────────────────────────────── */
    {
        struct epoll_event events[EPOLL_MAX_EVENTS];

        while (g_ctx->running) {
            memset(events, 0, sizeof(events));  /* 清零防止栈残留数据 */
            int nfds = epoll_wait(g_ctx->epoll_fd, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);

            if (nfds < 0) {
                if (errno == EINTR) {
                    /* 被信号中断，检查是否退出或重载 */
                    if (g_ctx->reload_requested) {
                        if (config_reload(g_ctx, g_ctx->config_path) == 0) {
                            LOG_INFO("Configuration reloaded (SIGHUP)");
                        }
                        g_ctx->reload_requested = 0;
                    }
                    if (g_ctx->ctl_requested) {
                        handle_channel_ctl(g_ctx);
                        g_ctx->ctl_requested = 0;
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

                if (fd == g_ctx->raw_sock) {
                    /* AF_PACKET 可读：接收所有待处理的帧 */
                    uint8_t  buf[AF_PACKET_FRAME_SIZE];
                    uint8_t  src_mac[ETH_MAC_ADDR_LEN];
                    uint8_t  dst_mac[ETH_MAC_ADDR_LEN];
                    /* BPF ensures only our ethertype arrives, but keep param for defense-in-depth */
                    uint16_t ethtype __attribute__((unused));

                    int frame_count = 0;
                    while (frame_count < MAX_FRAMES_PER_CYCLE) {
                        ssize_t len = af_packet_recv(g_ctx->raw_sock, buf, sizeof(buf),
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
                        if (g_ctx->config.crc_enabled && !IS_CTRL_FRAME(hdr.flags)) {
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
                        if (g_ctx->peer_mac_learned == 0 && !mac_is_broadcast(src_mac) && !mac_is_zero(src_mac)) {
                            memcpy(g_ctx->peer_mac, src_mac, ETH_MAC_ADDR_LEN);
                            g_ctx->peer_mac_learned = 1;
                            LOG_INFO("Auto-learned peer MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                                     src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
                            /* Update all existing channels with learned MAC */
                            for (uint32_t i = 0; i < g_ctx->channel_hash_size; i++) {
                                channel_t *ch = g_ctx->channel_hash[i];
                                while (ch) {
                                    memcpy(ch->peer_mac, g_ctx->peer_mac, ETH_MAC_ADDR_LEN);
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
                    channel_kcp_update(g_ctx);
                    channel_heartbeat(g_ctx);
                    channel_timeout_check(g_ctx);
                    last_periodic_ms = now_ms;
                }
            }

            /* ---- 统计输出（每 60 秒） ---- */
            if (g_ctx->config.stats_enabled) {
                uint32_t now_sec = time(NULL);
                if (now_sec - last_stats_sec >= STATS_INTERVAL_SEC) {
                    int active = channel_count(g_ctx);
                    LOG_INFO("Stats: %d active channels, running=%d",
                             active, g_ctx->running);
                    last_stats_sec = now_sec;
                }
            }

            /* ---- 配置重载请求 ---- */
            if (g_ctx->reload_requested) {
                if (config_reload(g_ctx, g_ctx->config_path) == 0) {
                    LOG_INFO("Configuration reloaded (SIGHUP)");
                }
                g_ctx->reload_requested = 0;
            }
        }
    }

    /* ================================================================
     * 17. 清理退出
     * ================================================================ */
    LOG_INFO("Shutting down...");
    cleanup(g_ctx);
    free(g_ctx);
    LOG_INFO("KCP-over-AF_PACKET stopped.");

    return 0;
}
#endif /* !TEST_BUILD */
