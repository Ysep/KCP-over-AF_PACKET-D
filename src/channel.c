/*
 * channel.c - 通道管理模块实现
 *
 * 负责通道的完整生命周期管理：创建、销毁、状态机转换、哈希表查找、
 * 帧分发、心跳检测、超时处理和 KCP 更新调度。
 *
 * 这是整个系统的核心模块，所有数据和控制帧通过此模块路由到正确的通道。
 */

#include "channel.h"
#include "kcp_wrap.h"
#include "myproto.h"
#include "af_packet.h"
#include "proxy.h"
#include "crypto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * 模块级静态变量
 * ============================================================================ */

/*
 * 全局上下文指针，在 channel_init() 中设置。
 * 用于 kcp_output_cb 等需要访问全局配置（如加密密钥）的回调函数。
 */
static global_ctx_t *g_ctx = NULL;

/* ============================================================================
 * 内部辅助函数
 * ============================================================================ */

/*
 * 哈希函数：将 channel_id 映射到哈希表槽位
 */
static inline unsigned int channel_hash(uint16_t channel_id)
{
    return channel_id % CHANNEL_HASH_SIZE;
}

/*
 * 在全局配置中查找与 channel_id 匹配的通道配置。
 * 返回匹配的 channel_config_t 指针，未找到返回 NULL。
 */
static const channel_config_t *channel_lookup_config(uint16_t channel_id)
{
    int i;

    if (!g_ctx) {
        return NULL;
    }

    for (i = 0; i < g_ctx->config.channel_count; i++) {
        if (g_ctx->config.channels[i].enabled &&
            g_ctx->config.channels[i].channel_id == channel_id) {
            return &g_ctx->config.channels[i];
        }
    }

    return NULL;
}

/*
 * KCP 输出回调函数（静态）
 *
 * 当 KCP 需要发送数据段时调用此回调。
 * 将 KCP 数据封装为 MyProto 数据帧，通过 AF_PACKET 发送到对端。
 *
 * @param buf   KCP 待发送的数据段
 * @param len   数据段长度
 * @param user  用户数据指针（指向 channel_t）
 * @return      成功返回 0，失败返回 -1
 */
static int kcp_output_cb(const char *buf, int len, struct IKCPCB *kcp, void *user)
{
    channel_t *ch;
    uint8_t    frame_buf[MAX_FRAME_SIZE];
    uint8_t    flags      = 0;
    ssize_t    frame_len;
    ssize_t    sent;

    (void)kcp;  /* KCP 实例指针在回调中可用，当前通过 user 获取通道信息 */

    /* 参数校验 */
    if (!user) {
        LOG_ERROR("kcp_output_cb: null user pointer");
        return -1;
    }
    if (!buf) {
        LOG_ERROR("kcp_output_cb: null buf pointer");
        return -1;
    }
    if (len <= 0) {
        LOG_ERROR("kcp_output_cb: invalid length %d", len);
        return -1;
    }

    ch = (channel_t *)user;

    /* 确定加密设置 */
    if (g_ctx && crypto_is_enabled()) {
        flags = MPF_CRYPTO;
    }

    /* 构建 MyProto 数据帧 */
    frame_len = myproto_build_data_frame(frame_buf, sizeof(frame_buf),
                                         ch->channel_id, flags,
                                         (const uint8_t *)buf, (size_t)len,
                                         g_ctx ? g_ctx->config.crc_enabled : 0);
    if (frame_len < 0) {
        LOG_ERROR("kcp_output_cb: myproto_build_data_frame failed "
                  "(channel=%u, len=%d)", ch->channel_id, len);
        ch->stats.tx_errors++;
        return -1;
    }

    /* 通过 AF_PACKET 发送 */
    sent = af_packet_send(ch->raw_sock, ch->ifindex,
                          ch->peer_mac, ch->local_mac,
                          ch->ethertype,
                          frame_buf, (size_t)frame_len);
    if (sent < 0) {
        LOG_ERROR("kcp_output_cb: af_packet_send failed "
                  "(channel=%u, frame_len=%zd): %s",
                  ch->channel_id, frame_len, strerror(errno));
        ch->stats.tx_errors++;
        return -1;
    }

    /* 更新统计 */
    ch->stats.tx_frames++;
    ch->stats.tx_bytes += (uint64_t)frame_len;

    /* 更新最后活跃时间 */
    ch->last_active = time_now();

    LOG_DEBUG("kcp_output_cb: sent frame (channel=%u, kcp_len=%d, "
              "frame_len=%zd, flags=0x%02x)",
              ch->channel_id, len, frame_len, flags);

    return 0;
}

/*
 * 将通道插入哈希表
 */
static int channel_hash_insert(channel_t *ch)
{
    unsigned int idx;

    if (!g_ctx || !ch) {
        return -1;
    }

    idx = channel_hash(ch->channel_id);

    /* 检查是否已存在同 ID 的通道 */
    {
        channel_t *cur = g_ctx->channel_hash[idx];
        while (cur) {
            if (cur->channel_id == ch->channel_id) {
                LOG_ERROR("channel_hash_insert: channel %u already exists",
                          ch->channel_id);
                return -1;
            }
            cur = cur->hash_next;
        }
    }

    /* 头插法插入链表 */
    ch->hash_next = g_ctx->channel_hash[idx];
    g_ctx->channel_hash[idx] = ch;

    return 0;
}

/*
 * 从哈希表中移除通道
 */
static int channel_hash_remove(channel_t *ch)
{
    unsigned int idx;
    channel_t **pp;

    if (!g_ctx || !ch) {
        return -1;
    }

    idx = channel_hash(ch->channel_id);
    pp  = &g_ctx->channel_hash[idx];

    while (*pp) {
        if (*pp == ch) {
            *pp = ch->hash_next;
            ch->hash_next = NULL;
            return 0;
        }
        pp = &(*pp)->hash_next;
    }

    LOG_ERROR("channel_hash_remove: channel %u not found in hash table",
              ch->channel_id);
    return -1;
}

/*
 * 发送全局心跳控制帧（使用 channel_id=0xFFFF，不依赖 channel_t）
 */
static int channel_send_heartbeat_ctrl(global_ctx_t *ctx, uint8_t flags)
{
    uint8_t frame_buf[MAX_FRAME_SIZE];
    ssize_t frame_len;
    ssize_t sent;

    if (!ctx) {
        return -1;
    }

    frame_len = myproto_build_ctrl_frame(frame_buf, sizeof(frame_buf),
                                         HEARTBEAT_CH_ID, flags, 0);
    if (frame_len < 0) {
        LOG_ERROR("channel_send_heartbeat_ctrl: build failed (flags=0x%02x)",
                  flags);
        return -1;
    }

    sent = af_packet_send(ctx->raw_sock, ctx->ifindex,
                          ctx->peer_mac, ctx->local_mac,
                          ctx->ethertype,
                          frame_buf, (size_t)frame_len);
    if (sent < 0) {
        LOG_ERROR("channel_send_heartbeat_ctrl: send failed (flags=0x%02x): %s",
                  flags, strerror(errno));
        return -1;
    }

    LOG_DEBUG("channel_send_heartbeat_ctrl: sent (flags=0x%02x, len=%zd)",
              flags, frame_len);

    return 0;
}

/* ============================================================================
 * 公共函数实现
 * ============================================================================ */

/*
 * 初始化通道子系统
 */
int channel_init(global_ctx_t *ctx)
{
    int i;

    if (!ctx) {
        LOG_ERROR("channel_init: null ctx pointer");
        return -1;
    }

    /* 保存全局上下文指针 */
    g_ctx = ctx;

    /* 初始化哈希表所有槽位为 NULL */
    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        ctx->channel_hash[i] = NULL;
    }

    /* 重置通道计数 */
    ctx->channel_count = 0;

    LOG_DEBUG("channel_init: subsystem initialized (hash_size=%d)",
              CHANNEL_HASH_SIZE);

    return 0;
}

/*
 * 关闭通道子系统
 */
void channel_shutdown(global_ctx_t *ctx)
{
    int i;

    if (!ctx) {
        LOG_ERROR("channel_shutdown: null ctx pointer");
        return;
    }

    LOG_DEBUG("channel_shutdown: destroying all channels (count=%d)",
              ctx->channel_count);

    /*
     * 遍历哈希表，销毁所有通道。
     * 注意：channel_destroy 会修改链表，因此需要小心遍历。
     * 每次取桶的第一个元素销毁，直到桶为空。
     */
    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        while (ctx->channel_hash[i]) {
            channel_t *ch = ctx->channel_hash[i];
            channel_destroy(ctx, ch);
        }
    }

    /* 确保所有槽位为 NULL */
    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        ctx->channel_hash[i] = NULL;
    }

    ctx->channel_count = 0;

    /* 清除全局上下文指针 */
    g_ctx = NULL;

    LOG_DEBUG("channel_shutdown: all channels destroyed");
}

/*
 * 创建新通道
 */
channel_t *channel_create(global_ctx_t *ctx, uint16_t channel_id,
                          channel_role_t role,
                          uint16_t listen_port, uint16_t remote_port,
                          const char *listen_addr, const char *remote_addr,
                          uint8_t is_tcp)
{
    channel_t *ch;
    uint32_t   now;

    if (!ctx) {
        LOG_ERROR("channel_create: null ctx pointer");
        return NULL;
    }

    /* 检查最大通道数限制 */
    if (ctx->channel_count >= ctx->config.max_channels) {
        LOG_ERROR("channel_create: max channels reached (%d/%d)",
                  ctx->channel_count, ctx->config.max_channels);
        return NULL;
    }

    /* 检查是否已存在同 ID 通道 */
    if (channel_find(ctx, channel_id)) {
        LOG_ERROR("channel_create: channel %u already exists", channel_id);
        return NULL;
    }

    /* 分配通道结构体并清零 */
    ch = (channel_t *)calloc(1, sizeof(channel_t));
    if (!ch) {
        LOG_ERROR("channel_create: calloc failed for channel %u: %s",
                  channel_id, strerror(errno));
        return NULL;
    }

    /* 获取当前时间戳 */
    now = time_now();

    /* ---- 初始化标识字段 ---- */
    ch->channel_id = channel_id;
    ch->state      = CHANNEL_CLOSED;
    ch->role       = role;

    /* ---- 初始化网络层字段（从全局上下文复制） ---- */
    ch->raw_sock  = ctx->raw_sock;
    ch->ifindex   = ctx->ifindex;
    ch->ethertype = ctx->ethertype;
    memcpy(ch->peer_mac,  ctx->peer_mac,  ETH_MAC_ADDR_LEN);
    memcpy(ch->local_mac, ctx->local_mac, ETH_MAC_ADDR_LEN);

    /* ---- 初始化本地套接字字段 ---- */
    ch->local_fd    = -1;
    ch->listen_fd   = -1;
    ch->listen_port = listen_port;
    ch->remote_port = remote_port;
    ch->is_tcp      = is_tcp;

    if (listen_addr) {
        strncpy(ch->listen_addr, listen_addr, MAX_LISTEN_ADDR - 1);
        ch->listen_addr[MAX_LISTEN_ADDR - 1] = '\0';
    } else {
        ch->listen_addr[0] = '\0';
    }

    if (remote_addr) {
        strncpy(ch->remote_addr, remote_addr, MAX_REMOTE_ADDR - 1);
        ch->remote_addr[MAX_REMOTE_ADDR - 1] = '\0';
    } else {
        ch->remote_addr[0] = '\0';
    }

    /* ---- 初始化时间戳 ---- */
    ch->last_active    = now;
    ch->last_peer_seen = now;
    ch->created_at     = now;
    ch->syn_sent_at    = 0;

    /* ---- 初始化缓冲区 ---- */
    ch->recv_buf_len = 0;

    /* ---- 初始化流控 ---- */
    ch->paused = 0;

    /* ---- 初始化重传计数 ---- */
    ch->syn_retry_count = 0;
    ch->fin_retry_count = 0;

    /* ---- 清零统计 ---- */
    memset(&ch->stats, 0, sizeof(ch->stats));

    /* ---- 初始化链表指针 ---- */
    ch->hash_next = NULL;

    /* ---- 创建 KCP 实例 ---- */
    ch->kcp = kcp_wrap_create((IUINT32)channel_id, (void *)ch);
    if (!ch->kcp) {
        LOG_ERROR("channel_create: kcp_wrap_create failed for channel %u",
                  channel_id);
        free(ch);
        return NULL;
    }

    /* ---- 设置 KCP 输出回调 ---- */
    kcp_wrap_set_output(ch->kcp, kcp_output_cb);

    /* ---- 配置 KCP 参数 ---- */
    kcp_wrap_set_params(ch->kcp,
                        ctx->config.kcp_mtu,
                        ctx->config.kcp_send_window,
                        ctx->config.kcp_recv_window,
                        ctx->config.kcp_nodelay,
                        ctx->config.kcp_interval,
                        ctx->config.kcp_resend,
                        ctx->config.kcp_nc);

    /* ---- 插入哈希表 ---- */
    if (channel_hash_insert(ch) != 0) {
        LOG_ERROR("channel_create: hash insert failed for channel %u",
                  channel_id);
        kcp_wrap_destroy(ch->kcp);
        free(ch);
        return NULL;
    }

    ctx->channel_count++;

    LOG_DEBUG("channel_create: channel %u created (role=%d, is_tcp=%d, "
              "listen=%s:%u, remote=%s:%u)",
              channel_id, role, is_tcp,
              ch->listen_addr, ch->listen_port,
              ch->remote_addr, ch->remote_port);

    /*
     * 发起方角色：立即发送 SYN 建立连接。
     * proxy_start_listen 由 main.c 统一调用，不在此处重复。
     */
    if (role == CHANNEL_ROLE_INITIATOR) {
        ch->state       = CHANNEL_SYN_SENT;
        ch->syn_sent_at = time_now();

        LOG_DEBUG("channel_create: sending initial SYN (channel=%u)",
                  channel_id);

        if (channel_send_ctrl(ch, MPF_SYN) != 0) {
            LOG_ERROR("channel_create: failed to send initial SYN "
                      "for channel %u", channel_id);
            /*
             * SYN 发送失败不阻止通道创建——重试机制
             * 会在 channel_timeout_check 中处理。
             */
        }
    }

    return ch;
}

/*
 * 销毁通道
 */
void channel_destroy(global_ctx_t *ctx, channel_t *ch)
{
    if (!ctx) {
        LOG_ERROR("channel_destroy: null ctx pointer");
        return;
    }
    if (!ch) {
        LOG_ERROR("channel_destroy: null ch pointer");
        return;
    }

    LOG_DEBUG("channel_destroy: destroying channel %u (state=%d)",
              ch->channel_id, ch->state);

    /* 从哈希表中移除 */
    channel_hash_remove(ch);

    /* 更新全局计数 */
    if (ctx->channel_count > 0) {
        ctx->channel_count--;
    }

    /* 销毁 KCP 实例 */
    if (ch->kcp) {
        kcp_wrap_destroy(ch->kcp);
        ch->kcp = NULL;
    }

    /*
     * 关闭本地连接套接字。
     * 注意：proxy_close_local() 内部通过 proxy.c 模块自身的
     * static g_ctx 引用全局上下文（用于 epoll 操作），
     * 而非通过参数传入 ctx。这是 proxy 模块的设计约定，
     * 与 channel_destroy 的 ctx 形参最终指向同一 global_ctx_t。
     */
    if (ch->local_fd >= 0) {
        proxy_close_local(ch);
        ch->local_fd = -1;
    }

    /* 关闭监听套接字（TCP/UDP 使用 close()，非 af_packet_close()） */
    if (ch->listen_fd >= 0) {
        proxy_epoll_del(ctx, ch->listen_fd);
        close(ch->listen_fd);
        ch->listen_fd = -1;
    }

    /* 释放通道内存 */
    free(ch);

    LOG_DEBUG("channel_destroy: channel freed (remaining=%d)",
              ctx->channel_count);
}

/*
 * 在哈希表中查找通道
 */
channel_t *channel_find(global_ctx_t *ctx, uint16_t channel_id)
{
    unsigned int idx;
    channel_t   *cur;

    if (!ctx) {
        LOG_ERROR("channel_find: null ctx pointer");
        return NULL;
    }

    idx = channel_hash(channel_id);
    cur = ctx->channel_hash[idx];

    while (cur) {
        if (cur->channel_id == channel_id) {
            return cur;
        }
        cur = cur->hash_next;
    }

    return NULL;
}

/*
 * 处理接收到的帧——核心分发函数
 *
 * 根据帧类型（控制/数据）和标志位，将帧路由到正确的处理逻辑。
 * 这是整个系统数据路径的关键入口。
 */
int channel_process_frame(global_ctx_t *ctx, const myproto_hdr_t *hdr,
                          const uint8_t *payload, size_t payload_len)
{
    channel_t *ch;
    uint32_t   now;

    if (!ctx) {
        LOG_ERROR("channel_process_frame: null ctx pointer");
        return -1;
    }
    if (!hdr) {
        LOG_ERROR("channel_process_frame: null hdr pointer");
        return -1;
    }

    now = time_now();

    /* ========================================================================
     * 全局心跳通道 (channel_id=0xFFFF) 特殊处理
     * ======================================================================== */
    if (hdr->channel_id == HEARTBEAT_CH_ID) {
        if ((hdr->flags & MPF_CTRL_MASK) == MPF_PING) {
            LOG_DEBUG("channel_process_frame: global PING, responding PONG");
            channel_send_heartbeat_ctrl(ctx, MPF_PONG);
            ctx->last_global_heartbeat = now;
            return 0;
        } else if ((hdr->flags & MPF_CTRL_MASK) == MPF_PONG) {
            LOG_DEBUG("channel_process_frame: global PONG received");
            ctx->last_global_heartbeat = now;
            return 0;
        } else {
            LOG_DEBUG("channel_process_frame: unknown frame type 0x%02x "
                      "on heartbeat channel, ignoring", hdr->flags);
            return 0;
        }
    }

    /* ========================================================================
     * 控制帧处理
     * ======================================================================== */
    if (IS_CTRL_FRAME(hdr->flags)) {

        switch (hdr->flags & MPF_CTRL_MASK) {

        /* ---- SYN: 通道建立请求 ---- */
        case MPF_SYN:
            LOG_DEBUG("channel_process_frame: SYN (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                /*
                 * 响应方收到 SYN：查找配置或使用默认参数创建通道。
                 */
                const channel_config_t *cfg;
                uint16_t                lport = 0;
                uint16_t                rport = 0;
                const char             *laddr = "0.0.0.0";
                const char             *raddr = "0.0.0.0";
                uint8_t                 tcp   = 1;

                cfg = channel_lookup_config(hdr->channel_id);
                if (cfg) {
                    lport = cfg->listen_port;
                    rport = cfg->remote_port;
                    laddr = cfg->listen_addr;
                    raddr = cfg->remote_addr;
                    tcp   = cfg->is_tcp;
                }

                ch = channel_create(ctx, hdr->channel_id,
                                    CHANNEL_ROLE_RESPONDER,
                                    lport, rport,
                                    laddr, raddr, tcp);
                if (!ch) {
                    LOG_ERROR("channel_process_frame: "
                              "failed to create responder channel %u",
                              hdr->channel_id);
                    return -1;
                }

                /* Set up local socket for the new responder channel.
                 * Forward proxy: responder connects to remote service.
                 * Reverse proxy: responder listens for local clients. */
                if (g_ctx && g_ctx->config.proxy_mode == PROXY_MODE_FORWARD) {
                    /* Forward: connect to remote_addr:remote_port */
                    if (proxy_connect_remote(ch) < 0) {
                        LOG_ERROR("Failed to connect remote for "
                                  "dynamic channel %u", ch->channel_id);
                        channel_send_ctrl(ch, MPF_RST);
                        ch->state = CHANNEL_CLOSED;
                        channel_destroy(ctx, ch);
                        return -1;
                    }
                } else if (g_ctx) {
                    /* Reverse: start listening for local clients */
                    if (proxy_start_listen(g_ctx, ch) < 0) {
                        LOG_ERROR("Failed to start listen for "
                                  "dynamic channel %u", ch->channel_id);
                        channel_send_ctrl(ch, MPF_RST);
                        ch->state = CHANNEL_CLOSED;
                        channel_destroy(ctx, ch);
                        return -1;
                    }
                }
                /* Channel found — validate state before accepting SYN.
                 * Reject SYN on closing/closed channels to prevent stale revival.
                 * SYN_SENT (peer's retransmission) and ESTABLISHED (race) are OK. */
                if (ch->state == CHANNEL_FIN_SENT ||
                    ch->state == CHANNEL_FIN_RCVD ||
                    ch->state == CHANNEL_TIME_WAIT ||
                    ch->state == CHANNEL_CLOSED) {
                    LOG_WARN("channel_process_frame: "
                             "SYN for channel %u in closing state %d, ignoring",
                             hdr->channel_id, ch->state);
                    return 0;
                }
            }

            /* 发送 ACK，进入 SYN_RCVD（等待对端数据确认连接） */
            if (channel_send_ctrl(ch, MPF_ACK) != 0) {
                LOG_ERROR("channel_process_frame: "
                          "failed to send ACK for channel %u",
                          hdr->channel_id);
            }
            ch->state          = CHANNEL_SYN_RCVD;
            ch->last_peer_seen = now;
            ch->last_active    = now;

            LOG_DEBUG("channel_process_frame: "
                      "channel %u SYN → SYN_RCVD (responder)",
                      hdr->channel_id);
            break;

        /* ---- ACK: 通道建立确认 ---- */
        case MPF_ACK:
            LOG_DEBUG("channel_process_frame: ACK (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_ERROR("channel_process_frame: "
                          "ACK for unknown channel %u, dropping",
                          hdr->channel_id);
                return -1;
            }

            if (ch->state == CHANNEL_SYN_SENT) {
                ch->state = CHANNEL_ESTABLISHED;
                LOG_DEBUG("channel_process_frame: "
                          "channel %u SYN_SENT → ESTABLISHED",
                          hdr->channel_id);

                /* If we're a reverse proxy responder, connect to local service */
                if (g_ctx && g_ctx->config.proxy_mode == PROXY_MODE_REVERSE &&
                    ch->local_fd < 0) {
                    if (proxy_connect_remote(ch) < 0) {
                        LOG_ERROR("Failed to connect to remote service "
                                  "for channel %u", ch->channel_id);
                        channel_send_ctrl(ch, MPF_RST);
                        ch->state = CHANNEL_CLOSED;
                        channel_destroy(ctx, ch);
                        return -1;
                    }
                }
            } else {
                LOG_DEBUG("channel_process_frame: "
                          "ACK for channel %u in state %d (ignored)",
                          hdr->channel_id, ch->state);
            }

            ch->last_peer_seen = now;
            ch->last_active    = now;
            break;

        /* ---- FIN: 通道关闭请求 ---- */
        case MPF_FIN:
            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_DEBUG("FIN for unknown channel %u, ignoring",
                          hdr->channel_id);
                return 0;
            }
            LOG_DEBUG("Received FIN for channel %u (state=%d)",
                      ch->channel_id, ch->state);

            /* Only respond with FIN if in an active state */
            if (ch->state == CHANNEL_ESTABLISHED ||
                ch->state == CHANNEL_SYN_SENT ||
                ch->state == CHANNEL_SYN_RCVD) {
                channel_send_ctrl(ch, MPF_FIN);
                ch->state = CHANNEL_FIN_RCVD;
            } else if (ch->state == CHANNEL_FIN_SENT) {
                /* Both sides sent FIN simultaneously → proceed to TIME_WAIT */
                ch->state = CHANNEL_TIME_WAIT;
                ch->last_active = time_now();
            } else if (ch->state == CHANNEL_FIN_RCVD ||
                       ch->state == CHANNEL_TIME_WAIT) {
                /* Already closing, ignore duplicate FIN */
            } else {
                /* CLOSED or unknown state */
                LOG_DEBUG("FIN for channel %u in unexpected state %d",
                          ch->channel_id, ch->state);
            }
            ch->last_peer_seen = now;
            break;

        /* ---- RST: 强制复位 ---- */
        case MPF_RST:
            LOG_DEBUG("channel_process_frame: RST (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_DEBUG("channel_process_frame: "
                          "RST for unknown channel %u, ignoring",
                          hdr->channel_id);
                return 0;
            }

            LOG_DEBUG("channel_process_frame: "
                      "force closing channel %u due to RST",
                      hdr->channel_id);

            ch->state = CHANNEL_CLOSED;
            channel_destroy(ctx, ch);
            break;

        /* ---- PING: 心跳探测 ---- */
        case MPF_PING:
            LOG_DEBUG("channel_process_frame: PING (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_ERROR("channel_process_frame: "
                          "PING for unknown channel %u, dropping",
                          hdr->channel_id);
                return -1;
            }

            /* 仅对已建立连接的通道回复 PONG */
            if (ch->state == CHANNEL_ESTABLISHED) {
                if (channel_send_ctrl(ch, MPF_PONG) != 0) {
                    LOG_ERROR("channel_process_frame: "
                              "failed to send PONG for channel %u",
                              hdr->channel_id);
                }
            }

            ch->last_peer_seen = now;
            ch->last_active    = now;
            break;

        /* ---- PONG: 心跳响应 ---- */
        case MPF_PONG:
            LOG_DEBUG("channel_process_frame: PONG (channel=%u)",
                      hdr->channel_id);

            ch = channel_find(ctx, hdr->channel_id);
            if (!ch) {
                LOG_ERROR("channel_process_frame: "
                          "PONG for unknown channel %u, dropping",
                          hdr->channel_id);
                return -1;
            }

            ch->last_peer_seen = now;
            break;

        /* ---- 未知/组合控制标志 ---- */
        default:
            LOG_ERROR("channel_process_frame: "
                      "unknown control flags 0x%02x (channel=%u), dropping",
                      hdr->flags, hdr->channel_id);
            return -1;
        }

        return 0;
    }

    /* ========================================================================
     * 数据帧处理
     * ======================================================================== */
    if (IS_DATA_FRAME(hdr->flags)) {

        LOG_DEBUG("channel_process_frame: DATA (channel=%u, len=%zu, "
                  "flags=0x%02x)",
                  hdr->channel_id, payload_len, hdr->flags);

        /* 查找通道 */
        ch = channel_find(ctx, hdr->channel_id);
        if (!ch) {
            LOG_ERROR("channel_process_frame: "
                      "DATA for unknown channel %u, dropping",
                      hdr->channel_id);
            return -1;
        }

        /*
         * 更新对端活跃时间（数据帧也算活跃）
         */
        ch->last_peer_seen = now;

        /*
         * 使用栈缓冲区进行加解密，不使用 recv_buf。
         * recv_buf 仅用于 proxy_write_to_local /
         * proxy_handle_local_write 的待发送数据缓冲区，
         * 与 crypto 解密缓冲区职责分离，避免冲突。
         */
        {
            uint8_t        decrypt_buf[CHANNEL_RECV_BUF_SIZE];
            const uint8_t *kcp_input_data = payload;
            size_t         kcp_input_len  = payload_len;
            int            ret;

            /* 处理加密数据帧 */
            if (IS_CRYPTO_FRAME(hdr->flags)) {
                size_t decrypted_len = payload_len;

                if (payload_len > sizeof(decrypt_buf)) {
                    LOG_ERROR("channel_process_frame: "
                              "payload too large for crypto processing "
                              "(channel=%u, len=%zu, max=%zu)",
                              hdr->channel_id, payload_len,
                              sizeof(decrypt_buf));
                    ch->stats.crypto_errors++;
                    ch->stats.rx_errors++;
                    return -1;
                }

                /*
                 * 复制 payload 到栈上的可写缓冲区，
                 * 并使用可变协议头副本，避免丢弃 const。
                 */
                memcpy(decrypt_buf, payload, payload_len);

                {
                    myproto_hdr_t mutable_hdr = *hdr;

                    ret = myproto_process_data_frame(&mutable_hdr,
                                                     decrypt_buf,
                                                     &decrypted_len);
                }

                if (ret != 0) {
                    LOG_ERROR("channel_process_frame: "
                              "crypto processing failed for channel %u",
                              hdr->channel_id);
                    ch->stats.crypto_errors++;
                    ch->stats.rx_errors++;
                    return -1;
                }

                kcp_input_data = decrypt_buf;
                kcp_input_len  = decrypted_len;
            }

            /* 更新接收统计 */
            ch->stats.rx_frames++;
            ch->stats.rx_bytes += (uint64_t)kcp_input_len;

            /* SYN_RCVD → ESTABLISHED: 收到对端首个数据段，连接确认 */
            if (ch->state == CHANNEL_SYN_RCVD) {
                ch->state = CHANNEL_ESTABLISHED;
                LOG_DEBUG("channel_process_frame: "
                          "channel %u SYN_RCVD → ESTABLISHED (first data)",
                          hdr->channel_id);
            }

            /*
             * 将数据输入 KCP。
             * KCP 负责重组分片、排序和可靠交付。
             */
            ret = kcp_wrap_input(ch->kcp, kcp_input_data,
                                 (int)kcp_input_len);
            if (ret != 0) {
                LOG_ERROR("channel_process_frame: "
                          "kcp_wrap_input failed for channel %u (len=%zu)",
                          hdr->channel_id, kcp_input_len);
                ch->stats.rx_errors++;
                return -1;
            }
        }

        /*
         * 从 KCP 读取重组后的数据并写入本地套接字。
         * KCP 可能通过多次 recv 调用交付多个完整消息。
         */
        {
            uint8_t kcp_buf[CHANNEL_RECV_BUF_SIZE];
            int     kcp_recv_len;

            while ((kcp_recv_len = kcp_wrap_recv(ch->kcp, kcp_buf,
                                                  (int)sizeof(kcp_buf))) > 0) {
                int write_ret;

                write_ret = proxy_write_to_local(ch, kcp_buf, kcp_recv_len);
                if (write_ret < 0) {
                    LOG_ERROR("channel_process_frame: "
                              "proxy_write_to_local failed "
                              "(channel=%u, len=%d) — local connection lost, "
                              "initiating close",
                              hdr->channel_id, kcp_recv_len);

                    /*
                     * 本地连接断开了——关闭本地端，发送 FIN 通知对端，
                     * 然后进入 FIN_SENT 状态等待对端确认关闭。
                     */
                    proxy_close_local(ch);
                    channel_send_ctrl(ch, MPF_FIN);
                    ch->state = CHANNEL_FIN_SENT;
                    return -1;
                }

                LOG_DEBUG("channel_process_frame: "
                          "delivered %d bytes to local (channel=%u)",
                          kcp_recv_len, hdr->channel_id);
            }

            if (kcp_recv_len < 0) {
                LOG_ERROR("channel_process_frame: "
                          "kcp_wrap_recv error for channel %u",
                          hdr->channel_id);
                ch->stats.rx_errors++;
                return -1;
            }
        }

        return 0;
    }

    /*
     * 既不是控制帧也不是数据帧——不应到达此处
     */
    LOG_ERROR("channel_process_frame: unknown frame type "
              "(channel=%u, flags=0x%02x)",
              hdr->channel_id, hdr->flags);
    return -1;
}

/*
 * 发送控制帧
 */
int channel_send_ctrl(channel_t *ch, uint8_t flags)
{
    uint8_t frame_buf[MAX_FRAME_SIZE];
    ssize_t frame_len;
    ssize_t sent;

    if (!ch) {
        LOG_ERROR("channel_send_ctrl: null ch pointer");
        return -1;
    }

    /* 构建 MyProto 控制帧 */
    frame_len = myproto_build_ctrl_frame(frame_buf, sizeof(frame_buf),
                                         ch->channel_id, flags, 0);
    if (frame_len < 0) {
        LOG_ERROR("channel_send_ctrl: myproto_build_ctrl_frame failed "
                  "(channel=%u, flags=0x%02x)", ch->channel_id, flags);
        ch->stats.tx_errors++;
        return -1;
    }

    /* 通过 AF_PACKET 发送 */
    sent = af_packet_send(ch->raw_sock, ch->ifindex,
                          ch->peer_mac, ch->local_mac,
                          ch->ethertype,
                          frame_buf, (size_t)frame_len);
    if (sent < 0) {
        LOG_ERROR("channel_send_ctrl: af_packet_send failed "
                  "(channel=%u, flags=0x%02x): %s",
                  ch->channel_id, flags, strerror(errno));
        ch->stats.tx_errors++;
        return -1;
    }

    /* 更新统计 */
    ch->stats.tx_frames++;
    ch->stats.tx_bytes += (uint64_t)frame_len;

    /* 更新最后活跃时间 */
    ch->last_active = time_now();

    LOG_DEBUG("channel_send_ctrl: sent (channel=%u, flags=0x%02x, "
              "frame_len=%zd)",
              ch->channel_id, flags, frame_len);

    return 0;
}

/*
 * 发送数据帧
 *
 * 注意：此函数将数据送入 KCP 队列，而非直接发送。
 * 实际发送由 KCP 通过 kcp_output_cb 回调触发。
 */
int channel_send_data(channel_t *ch, const uint8_t *data, size_t len)
{
    int ret;

    if (!ch) {
        LOG_ERROR("channel_send_data: null ch pointer");
        return -1;
    }
    if (!data) {
        LOG_ERROR("channel_send_data: null data pointer (channel=%u)",
                  ch->channel_id);
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    /* 检查通道状态 */
    if (ch->state != CHANNEL_ESTABLISHED) {
        LOG_ERROR("channel_send_data: channel %u not ESTABLISHED (state=%d)",
                  ch->channel_id, ch->state);
        return -1;
    }

    /*
     * 数据通过 KCP 发送。
     * KCP 负责分段、排序和可靠交付。
     * 实际帧发送由 kcp_output_cb 处理。
     */
    ret = kcp_wrap_send(ch->kcp, data, (int)len);
    if (ret < 0) {
        LOG_ERROR("channel_send_data: kcp_wrap_send failed "
                  "(channel=%u, len=%zu)", ch->channel_id, len);
        return -1;
    }

    /* 更新最后活跃时间（数据入队即视为活跃） */
    ch->last_active = time_now();

    /*
     * 注意：此处不更新 tx_frames/tx_bytes 统计，
     * 因为这些统计在 kcp_output_cb 中由实际发送时更新。
     */

    LOG_DEBUG("channel_send_data: queued %d bytes into KCP (channel=%u)",
              ret, ch->channel_id);

    return 0;
}

/*
 * 处理通道心跳
 *
 * 对每个 ESTABLISHED 状态的通道，如果距上次发送超过心跳间隔，
 * 发送 PING 帧以保持连接活跃。
 */
void channel_heartbeat(global_ctx_t *ctx)
{
    int        i;
    uint32_t   now;
    int        interval;
    int        global_hb_ok = 0;

    if (!ctx) {
        LOG_ERROR("channel_heartbeat: null ctx pointer");
        return;
    }

    now      = time_now();
    interval = ctx->config.heartbeat_interval;

    (void)now;  /* suppress unused warning when DEBUG is not defined */

    if (interval <= 0) {
        interval = HEARTBEAT_INTERVAL;
    }

    /*
     * 首先尝试全局心跳（channel_id=0xFFFF）。
     * 如果上一次全局心跳响应在 interval 秒内，则跳过发送。
     * 否则发送 PING，如果最近 interval 秒内收到过全局 PONG，
     * 则标记为成功，跳过逐通道心跳。
     */
    if (time_elapsed(ctx->last_global_heartbeat) < (uint32_t)interval) {
        /* 最近 interval 秒内收到过全局 PONG，对端存活确认 */
        global_hb_ok = 1;
    } else {
        /* 发送全局 PING，但不立即设置 global_hb_ok——
         * 等待对端回复 PONG 后由 channel_process_frame
         * 更新 last_global_heartbeat，下次心跳检查时生效。
         * 在此期间逐通道心跳作为后备继续工作。 */
        LOG_DEBUG("channel_heartbeat: sending global PING on channel 0x%04X "
                  "(now=%u, last_global=%u, elapsed=%u)",
                  HEARTBEAT_CH_ID, now, ctx->last_global_heartbeat,
                  time_elapsed(ctx->last_global_heartbeat));
        channel_send_heartbeat_ctrl(ctx, MPF_PING);
    }

    /*
     * 如果全局心跳已确认对端存活，跳过逐通道心跳。
     * 否则对每个 ESTABLISHED 通道单独发送 PING。
     */
    if (global_hb_ok) {
        LOG_DEBUG("channel_heartbeat: global heartbeat OK, skipping per-channel");
        return;
    }

    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            /*
             * 仅对 ESTABLISHED 状态的通道发送心跳。
             * 保存 hash_next，防止 channel_send_ctrl 间接触发销毁。
             */
            channel_t *next = ch->hash_next;

            if (ch->state == CHANNEL_ESTABLISHED) {
                if (time_elapsed(ch->last_active) >= (uint32_t)interval) {
                    LOG_DEBUG("channel_heartbeat: sending PING to channel %u "
                              "(last_active=%u, now=%u, elapsed=%u)",
                              ch->channel_id, ch->last_active, now,
                              time_elapsed(ch->last_active));

                    if (channel_send_ctrl(ch, MPF_PING) != 0) {
                        LOG_ERROR("channel_heartbeat: "
                                  "failed to send PING to channel %u",
                                  ch->channel_id);
                    }
                }
            }

            ch = next;
        }
    }
}

/*
 * 处理通道超时检测
 *
 * 检查三类超时：
 * 1. 心跳超时：对端长时间无响应 → 强制关闭
 * 2. SYN 重传超限：发起方 SYN 无应答 → 强制关闭
 * 3. TIME_WAIT 超时：优雅关闭等待期满 → 销毁通道
 */
void channel_timeout_check(global_ctx_t *ctx)
{
    int        i;
    uint32_t   now;
    int        hb_timeout;

    if (!ctx) {
        LOG_ERROR("channel_timeout_check: null ctx pointer");
        return;
    }

    now        = time_now();
    hb_timeout = ctx->config.heartbeat_timeout;

    if (hb_timeout <= 0) {
        hb_timeout = HEARTBEAT_TIMEOUT;
    }

    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            channel_t *next = ch->hash_next;

            /*
             * 检查 1: 心跳超时
             * 如果距最后一次收到对端数据超过 heartbeat_timeout 秒，
             * 且通道处于 ESTABLISHED 或 FIN_SENT 状态，则强制关闭。
             * 注意：FIN_RCVD 不在此检查——它正通过 FIN_RCVD→TIME_WAIT→CLOSED 路径关闭。
             */
            if (ch->state == CHANNEL_ESTABLISHED ||
                ch->state == CHANNEL_FIN_SENT) {

                if (time_elapsed(ch->last_peer_seen) >= (uint32_t)hb_timeout) {
                    LOG_ERROR("channel_timeout_check: "
                              "heartbeat timeout for channel %u "
                              "(last_peer_seen=%u, now=%u, elapsed=%u, "
                              "timeout=%d)",
                              ch->channel_id, ch->last_peer_seen, now,
                              time_elapsed(ch->last_peer_seen),
                              hb_timeout);

                    /* 发送 RST 通知对端 */
                    channel_send_ctrl(ch, MPF_RST);

                    ch->state = CHANNEL_CLOSED;
                    channel_destroy(ctx, ch);

                    ch = next;
                    continue;
                }
            }

            /*
             * 检查 2: SYN 重传机制
             * 发起方在 SYN_SENT 状态，每 3 秒重传 SYN，
             * 重试次数超过 3 次则放弃。
             */
            if (ch->state == CHANNEL_SYN_SENT) {
                if (time_elapsed(ch->syn_sent_at) >= 3) {
                    ch->syn_retry_count++;

                    if (ch->syn_retry_count > 3) {
                        LOG_ERROR("channel_timeout_check: "
                                  "SYN retry exceeded for channel %u "
                                  "(retries=%u)",
                                  ch->channel_id, ch->syn_retry_count);

                        ch->state = CHANNEL_CLOSED;
                        channel_destroy(ctx, ch);

                        ch = next;
                        continue;
                    }

                    LOG_DEBUG("channel_timeout_check: "
                              "SYN retry %u for channel %u",
                              ch->syn_retry_count, ch->channel_id);

                    ch->syn_sent_at = now;
                    if (channel_send_ctrl(ch, MPF_SYN) != 0) {
                        LOG_ERROR("channel_timeout_check: "
                                  "SYN retry send failed for channel %u",
                                  ch->channel_id);
                    }
                }
            }

            /*
             * 检查 3: FIN_RCVD → TIME_WAIT 转换
             * 收到 FIN 并回显 FIN 后，等待一小段时间再进入 TIME_WAIT。
             * 这里立即转换（下一次超时检查即可），TIME_WAIT 阶段
             * 等待 CHANNEL_GRACEFUL_TIMEOUT 秒后彻底销毁。
             */
            if (ch->state == CHANNEL_FIN_RCVD) {
                LOG_DEBUG("channel_timeout_check: "
                          "channel %u FIN_RCVD → TIME_WAIT",
                          ch->channel_id);

                ch->state       = CHANNEL_TIME_WAIT;
                ch->last_active = now;
            }

            /*
             * 检查 4: TIME_WAIT 超时
             * 优雅关闭后等待 CHANNEL_GRACEFUL_TIMEOUT 秒，然后彻底销毁。
             */
            if (ch->state == CHANNEL_TIME_WAIT) {
                if (time_elapsed(ch->last_active) >=
                    (uint32_t)CHANNEL_GRACEFUL_TIMEOUT) {
                    LOG_DEBUG("channel_timeout_check: "
                              "TIME_WAIT expired for channel %u, destroying",
                              ch->channel_id);

                    ch->state = CHANNEL_CLOSED;
                    channel_destroy(ctx, ch);

                    ch = next;
                    continue;
                }
            }

            ch = next;
        }
    }
}

/*
 * 更新所有通道的 KCP 实例
 *
 * 驱动 KCP 内部定时器，触发重传和确认处理。
 * 由主循环以固定间隔（KCP_UPDATE_INTERVAL ms）调用。
 */
void channel_kcp_update(global_ctx_t *ctx)
{
    int      i;
    IUINT32  current_ms;

    if (!ctx) {
        LOG_ERROR("channel_kcp_update: null ctx pointer");
        return;
    }

    current_ms = kcp_wrap_clock();

    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            channel_t *next = ch->hash_next;

            if (ch->kcp) {
                kcp_wrap_update(ch->kcp, current_ms);
            }

            ch = next;
        }
    }
}

/*
 * 遍历所有通道
 *
 * 对哈希表中每个非 NULL 通道调用回调函数。
 * 回调期间通道可能被销毁，调用方需自行处理。
 */
void channel_foreach(global_ctx_t *ctx, channel_foreach_cb_t callback,
                     void *user_data)
{
    int i;

    if (!ctx) {
        LOG_ERROR("channel_foreach: null ctx pointer");
        return;
    }
    if (!callback) {
        LOG_ERROR("channel_foreach: null callback pointer");
        return;
    }

    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            channel_t *next = ch->hash_next;

            callback(ch, user_data);

            ch = next;
        }
    }
}

/*
 * 获取活跃通道数
 */
int channel_count(global_ctx_t *ctx)
{
    if (!ctx) {
        LOG_ERROR("channel_count: null ctx pointer");
        return 0;
    }

    return ctx->channel_count;
}

/*
 * 关闭所有通道（优雅关闭）
 *
 * 对所有 ESTABLISHED 状态的通道发送 FIN，
 * 通知对端本端正在关闭，然后转换到 FIN_SENT 状态。
 */
void channel_close_all(global_ctx_t *ctx)
{
    int i;

    if (!ctx) {
        LOG_ERROR("channel_close_all: null ctx pointer");
        return;
    }

    LOG_DEBUG("channel_close_all: initiating graceful shutdown "
              "(count=%d)", ctx->channel_count);

    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        channel_t *ch = ctx->channel_hash[i];

        while (ch) {
            channel_t *next = ch->hash_next;

            if (ch->state == CHANNEL_ESTABLISHED) {
                LOG_DEBUG("channel_close_all: sending FIN to channel %u",
                          ch->channel_id);

                if (channel_send_ctrl(ch, MPF_FIN) != 0) {
                    LOG_ERROR("channel_close_all: "
                              "failed to send FIN to channel %u",
                              ch->channel_id);
                }

                ch->state = CHANNEL_FIN_SENT;
            } else if (ch->state == CHANNEL_SYN_SENT) {
                channel_send_ctrl(ch, MPF_RST);  /* No connection established, send RST */
                ch->state = CHANNEL_CLOSED;
            }

            ch = next;
        }
    }

    LOG_DEBUG("channel_close_all: graceful shutdown complete");
}
