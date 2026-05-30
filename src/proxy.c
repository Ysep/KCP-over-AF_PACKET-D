/*
 * proxy.c - 代理模块实现
 *
 * 负责本地 TCP/UDP 端口的监听、连接和数据桥接。
 * 支持正向代理（监听本地→转发到远端）和反向代理（从 AF_PACKET 接收→连接本地服务）。
 *
 * 使用 edge-triggered epoll 进行高性能 I/O 事件处理。
 * 通过 ev.data.ptr 存储通道指针以实现 O(1) 的 fd→channel 查找。
 * TCP_NODELAY 确保低延迟，SO_REUSEADDR 支持快速重启。
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "proxy.h"
#include "channel.h"
#include "ikcp.h"
#include "kcp_wrap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ============================================================================
 * 模块级常量
 * ============================================================================ */

/* 本地套接字读取栈缓冲区大小 */
#define PROXY_READ_BUF_SIZE     (64 * 1024)

/* KCP→本地套接字刷新时的栈缓冲区大小 */
#define PROXY_FLUSH_BUF_SIZE    (64 * 1024)

/* ============================================================================
 * 模块级静态变量
 * ============================================================================ */

/*
 * 全局上下文指针，在 proxy_init() 中设置。
 * 用于 proxy_connect_remote() 等不需要 ctx 参数的函数访问 epoll_fd。
 */
static global_ctx_t *g_ctx = NULL;

/* ============================================================================
 * 内部辅助函数（前向声明）
 * ============================================================================ */

/*
 * 查找 local_fd 或 listen_fd 匹配的通道。
 * 扫描哈希表 - O(n)，但 n ≤ MAX_CHANNELS (256)，实际使用中开销可忽略。
 */
static channel_t *proxy_find_channel_by_fd(global_ctx_t *ctx, int fd)
{
    int i;

    if (!ctx || fd < 0) {
        return NULL;
    }

    for (i = 0; i < CHANNEL_HASH_SIZE; i++) {
        channel_t *ch = ctx->channel_hash[i];
        while (ch) {
            if (ch->local_fd == fd || ch->listen_fd == fd) {
                return ch;
            }
            ch = ch->hash_next;
        }
    }

    return NULL;
}

/*
 * 修改 epoll 注册事件掩码（用于动态切换 EPOLLOUT）。
 * 在 edge-triggered 模式下，当 recv_buf 有待发送数据时，
 * 需要确保 EPOLLOUT 已注册以接收可写通知。
 */
static int proxy_epoll_mod_events(global_ctx_t *ctx, int fd,
                                  void *ptr, uint32_t events)
{
    struct epoll_event ev;

    (void)ptr;  /* 已改用 data.fd 存储 fd，ptr 保留兼容 */
    ev.events   = events;
    ev.data.fd  = fd;

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        LOG_ERROR("proxy_epoll_mod_events: epoll_ctl(EPOLL_CTL_MOD, fd=%d, "
                  "events=0x%x) failed: %s", fd, events, strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * 确保 local_fd 的 epoll 注册包含 EPOLLOUT。
 * 当 recv_buf 中新增了待发送数据时调用。
 */
static int proxy_ensure_epollout(global_ctx_t *ctx, channel_t *ch)
{
    uint32_t events;

    if (!ctx || !ch || ch->local_fd < 0) {
        return -1;
    }

    events = proxy_get_events(ch);
    return proxy_epoll_mod_events(ctx, ch->local_fd, ch, events);
}

/* ============================================================================
 * 公共 API 实现
 * ============================================================================ */

/*
 * 初始化代理子系统
 */
int proxy_init(global_ctx_t *ctx)
{
    if (!ctx) {
        LOG_ERROR("proxy_init: null context");
        return -1;
    }

    /* 保存全局上下文（供 proxy_connect_remote 使用） */
    g_ctx = ctx;

    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd < 0) {
        LOG_ERROR("proxy_init: epoll_create1 failed: %s", strerror(errno));
        return -1;
    }

    LOG_DEBUG("proxy_init: epoll_fd=%d created", ctx->epoll_fd);
    return 0;
}

/*
 * 关闭代理子系统
 */
void proxy_shutdown(global_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->epoll_fd >= 0) {
        LOG_DEBUG("proxy_shutdown: closing epoll_fd=%d", ctx->epoll_fd);
        close(ctx->epoll_fd);
        ctx->epoll_fd = -1;
    }

    g_ctx = NULL;
}

/*
 * 为通道创建监听套接字并注册到 epoll
 */
int proxy_start_listen(global_ctx_t *ctx, channel_t *ch)
{
    int                fd;
    int                optval;
    struct sockaddr_in addr;
    struct epoll_event ev;

    if (!ctx || !ch) {
        LOG_ERROR("proxy_start_listen: null pointer");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(ch->listen_port);

    if (inet_pton(AF_INET, ch->listen_addr, &addr.sin_addr) != 1) {
        LOG_ERROR("proxy_start_listen: invalid listen_addr '%s' (channel=%u)",
                  ch->listen_addr, ch->channel_id);
        return -1;
    }

    if (ch->is_tcp) {
        /* ---- TCP 监听套接字 ---- */
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            LOG_ERROR("proxy_start_listen: socket(TCP) failed: %s",
                      strerror(errno));
            return -1;
        }

        /* SO_REUSEADDR: 允许快速重启时立即绑定端口 */
        optval = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_start_listen: setsockopt(SO_REUSEADDR) failed: %s",
                      strerror(errno));
            close(fd);
            return -1;
        }

        /* 绑定到监听地址和端口 */
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            LOG_ERROR("proxy_start_listen: bind(%s:%u) failed: %s",
                      ch->listen_addr, ch->listen_port, strerror(errno));
            close(fd);
            return -1;
        }

        /* 开始监听 */
        if (listen(fd, SOMAXCONN) < 0) {
            LOG_ERROR("proxy_start_listen: listen() failed: %s",
                      strerror(errno));
            close(fd);
            return -1;
        }

        ch->listen_fd = fd;
        ch->local_fd  = -1;

        /*
         * 监听套接字使用 level-triggered (EPOLLIN)，
         * 确保不会因 edge-triggered 而在高并发下丢失连接。
         */
        ev.events   = EPOLLIN;
        ev.data.fd  = fd;
        if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            LOG_ERROR("proxy_start_listen: epoll_ctl(ADD, listen_fd=%d) "
                      "failed: %s", fd, strerror(errno));
            close(fd);
            ch->listen_fd = -1;
            return -1;
        }

        LOG_INFO("proxy_start_listen: TCP listening on %s:%u "
                 "(fd=%d, channel=%u)",
                 ch->listen_addr, ch->listen_port, fd, ch->channel_id);

    } else {
        /* ---- UDP 套接字 ---- */
        fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            LOG_ERROR("proxy_start_listen: socket(UDP) failed: %s",
                      strerror(errno));
            return -1;
        }

        /* SO_REUSEADDR */
        optval = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_start_listen: setsockopt(SO_REUSEADDR) "
                      "failed: %s", strerror(errno));
            close(fd);
            return -1;
        }

        /* 绑定 */
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            LOG_ERROR("proxy_start_listen: bind(%s:%u) failed: %s",
                      ch->listen_addr, ch->listen_port, strerror(errno));
            close(fd);
            return -1;
        }

        /*
         * UDP 是无连接的：listen_fd 和 local_fd 指向同一个套接字。
         */
        ch->listen_fd = fd;
        ch->local_fd  = fd;

        /* 添加到 epoll（edge-triggered 用于 local I/O） */
        if (proxy_epoll_add(ctx, fd, ch) < 0) {
            close(fd);
            ch->listen_fd = -1;
            ch->local_fd  = -1;
            return -1;
        }

        LOG_INFO("proxy_start_listen: UDP bound to %s:%u "
                 "(fd=%d, channel=%u)",
                 ch->listen_addr, ch->listen_port, fd, ch->channel_id);
    }

    return 0;
}

/*
 * 接受监听套接字上的新 TCP 连接
 */
int proxy_accept(global_ctx_t *ctx, channel_t *ch)
{
    int client_fd;
    int optval;

    if (!ctx || !ch) {
        LOG_ERROR("proxy_accept: null pointer");
        return -1;
    }

    if (!ch->is_tcp) {
        LOG_ERROR("proxy_accept: called on non-TCP channel %u",
                  ch->channel_id);
        return -1;
    }

    if (ch->listen_fd < 0) {
        LOG_ERROR("proxy_accept: invalid listen_fd for channel %u",
                  ch->channel_id);
        return -1;
    }

    /*
     * 在循环中 accept，以兼容 edge-triggered epoll。
     * 一次 epoll 通知可能对应多个待处理连接。
     */
    while (1) {
        client_fd = accept4(ch->listen_fd, NULL, NULL,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* 所有待处理连接均已接受 */
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("proxy_accept: accept4() failed: %s", strerror(errno));
            return -1;
        }

        /*
         * 如果该通道已有活跃连接，关闭多余的新连接。
         * 每个通道同一时间只服务一个客户端。
         */
        if (ch->local_fd >= 0) {
            LOG_WARN("proxy_accept: channel %u busy (local_fd=%d), "
                     "closing extra connection fd=%d",
                     ch->channel_id, ch->local_fd, client_fd);
            close(client_fd);
            continue;
        }

        /* TCP_NODELAY: 禁用 Nagle 算法，确保低延迟 */
        optval = 1;
        if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_accept: setsockopt(TCP_NODELAY) failed: %s",
                      strerror(errno));
            close(client_fd);
            return -1;
        }

        /* SO_KEEPALIVE: 检测死连接 */
        optval = 1;
        if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_accept: setsockopt(SO_KEEPALIVE) failed: %s",
                      strerror(errno));
            close(client_fd);
            return -1;
        }

        ch->local_fd = client_fd;

        /* 添加到 epoll（edge-triggered 用于高性能数据收发） */
        if (proxy_epoll_add(ctx, client_fd, ch) < 0) {
            close(client_fd);
            ch->local_fd = -1;
            return -1;
        }

        LOG_INFO("proxy_accept: accepted connection fd=%d on channel %u "
                 "(listen_fd=%d)", client_fd, ch->channel_id, ch->listen_fd);

        return client_fd;
    }

    /* 无新连接（EAGAIN），返回 -1 表示本次无连接 */
    return -1;
}

/*
 * 连接到远端服务（反向代理模式）
 */
int proxy_connect_remote(channel_t *ch)
{
    int                fd;
    int                optval;
    int                ret;
    struct sockaddr_in addr;
    struct epoll_event ev;
    global_ctx_t      *ctx;

    if (!ch) {
        LOG_ERROR("proxy_connect_remote: null channel");
        return -1;
    }

    ctx = g_ctx;
    if (!ctx || ctx->epoll_fd < 0) {
        LOG_ERROR("proxy_connect_remote: proxy not initialized");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(ch->remote_port);

    if (inet_pton(AF_INET, ch->remote_addr, &addr.sin_addr) != 1) {
        LOG_ERROR("proxy_connect_remote: invalid remote_addr '%s' "
                  "(channel=%u)", ch->remote_addr, ch->channel_id);
        return -1;
    }

    /* 创建非阻塞套接字 */
    if (ch->is_tcp) {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    } else {
        fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    }

    if (fd < 0) {
        LOG_ERROR("proxy_connect_remote: socket() failed: %s",
                  strerror(errno));
        return -1;
    }

    /* TCP_NODELAY */
    if (ch->is_tcp) {
        optval = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                       &optval, sizeof(optval)) < 0) {
            LOG_ERROR("proxy_connect_remote: setsockopt(TCP_NODELAY) "
                      "failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }

    /* 关闭旧的 local_fd（如果存在） */
    if (ch->local_fd >= 0) {
        LOG_WARN("proxy_connect_remote: closing old local_fd=%d "
                 "(channel=%u)", ch->local_fd, ch->channel_id);
        proxy_epoll_del(ctx, ch->local_fd);
        close(ch->local_fd);
    }

    /* 非阻塞 connect */
    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        LOG_ERROR("proxy_connect_remote: connect(%s:%u) failed: %s",
                  ch->remote_addr, ch->remote_port, strerror(errno));
        close(fd);
        return -1;
    }

    ch->local_fd = fd;

    /*
     * 添加到 epoll。
     * 包含 EPOLLOUT：反向连接建立后，通过 EPOLLOUT 事件确认连接就绪。
     * 对于 TCP，connect 返回 EINPROGRESS 时，连接完成表现为套接字可写。
     */
    ev.events   = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd  = fd;
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERROR("proxy_connect_remote: epoll_ctl(ADD, fd=%d) failed: %s",
                  fd, strerror(errno));
        close(fd);
        ch->local_fd = -1;
        return -1;
    }

    if (ret == 0) {
        /* 本地连接立即成功（UDP 或同主机 TCP） */
        LOG_INFO("proxy_connect_remote: connected to %s:%u "
                 "(fd=%d, channel=%u, immediate)",
                 ch->remote_addr, ch->remote_port, fd, ch->channel_id);
    } else {
        LOG_INFO("proxy_connect_remote: connecting to %s:%u "
                 "(fd=%d, channel=%u, in progress)",
                 ch->remote_addr, ch->remote_port, fd, ch->channel_id);
    }

    return fd;
}

/*
 * 处理本地套接字的可读事件（应用→KCP 方向）
 */
int proxy_handle_local_read(global_ctx_t *ctx, channel_t *ch)
{
    uint8_t         buf[PROXY_READ_BUF_SIZE];
    ssize_t         n;
    int             total_read = 0;

    if (!ctx || !ch) {
        LOG_ERROR("proxy_handle_local_read: null pointer");
        return -1;
    }

    if (ch->local_fd < 0) {
        LOG_ERROR("proxy_handle_local_read: invalid local_fd for channel %u",
                  ch->channel_id);
        return -1;
    }

    if (ch->is_tcp) {
        /*
         * TCP edge-triggered 模式：在循环中读取直到 EAGAIN。
         * 这样可以一次 epoll 通知消费所有可用数据。
         */
        while (1) {
            n = read(ch->local_fd, buf, sizeof(buf));
            if (n > 0) {
                total_read += n;

                /* 将数据送入 KCP */
                if (channel_send_data(ch, buf, (size_t)n) < 0) {
                    LOG_ERROR("proxy_handle_local_read: channel_send_data "
                              "failed (channel=%u, len=%zd)",
                              ch->channel_id, n);
                    return -1;
                }
                continue;
            }

            if (n == 0) {
                /* EOF: 对端关闭连接，开始优雅关闭 */
                LOG_INFO("proxy_handle_local_read: EOF on fd=%d "
                         "(channel=%u), starting graceful close",
                         ch->local_fd, ch->channel_id);
                channel_send_ctrl(ch, MPF_FIN);
                return 0;
            }

            /* n < 0 */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* 所有可用数据已读取完毕 */
                break;
            }

            if (errno == EINTR) {
                continue;
            }

            /* 真正的读取错误 */
            LOG_ERROR("proxy_handle_local_read: read(fd=%d) failed: %s "
                      "(channel=%u)",
                      ch->local_fd, strerror(errno), ch->channel_id);
            return -1;
        }
    } else {
        /*
         * UDP: loop to drain all available datagrams (edge-triggered).
         * Under ET epoll, multiple datagrams arriving together would
         * lose all but the first without this loop.
         */
        struct sockaddr_in peer_addr;
        socklen_t          addr_len = sizeof(peer_addr);

        while (1) {
            n = recvfrom(ch->local_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&peer_addr, &addr_len);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                LOG_ERROR("proxy_handle_local_read: recvfrom(fd=%d) failed: %s "
                          "(channel=%u)",
                          ch->local_fd, strerror(errno), ch->channel_id);
                return -1;
            }
            if (n == 0) {
                break;
            }

            total_read += (int)n;

            /* 将数据报送入 KCP */
            if (channel_send_data(ch, buf, (size_t)n) < 0) {
                LOG_ERROR("proxy_handle_local_read: channel_send_data "
                          "failed (channel=%u, len=%zd)",
                          ch->channel_id, n);
                return -1;
            }
        }
    }

    LOG_DEBUG("proxy_handle_local_read: read %d bytes from fd=%d (channel=%u)",
              total_read, ch->local_fd, ch->channel_id);

    return total_read;
}

/*
 * 处理本地套接字的可写事件（KCP→应用方向）
 */
int proxy_handle_local_write(channel_t *ch)
{
    ssize_t nwritten;

    if (!ch) {
        LOG_ERROR("proxy_handle_local_write: null channel");
        return -1;
    }

    if (ch->local_fd < 0) {
        LOG_ERROR("proxy_handle_local_write: invalid local_fd for channel %u",
                  ch->channel_id);
        return -1;
    }

    if (ch->recv_buf_len == 0) {
        /* 没有待发送数据 */
        return 0;
    }

    nwritten = write(ch->local_fd, ch->recv_buf, (size_t)ch->recv_buf_len);
    if (nwritten < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* 写阻塞，等待下次 EPOLLOUT */
            return 0;
        }
        if (errno == EINTR) {
            return 0;
        }
        LOG_ERROR("proxy_handle_local_write: write(fd=%d) failed: %s "
                  "(channel=%u)",
                  ch->local_fd, strerror(errno), ch->channel_id);
        return -1;
    }

    if (nwritten < ch->recv_buf_len) {
        /*
         * 部分写入：将剩余数据移到缓冲区头部。
         * 使用 memmove 以支持重叠内存区域。
         */
        memmove(ch->recv_buf,
                ch->recv_buf + nwritten,
                (size_t)(ch->recv_buf_len - nwritten));
        ch->recv_buf_len -= (int)nwritten;

        /* Re-arm EPOLLOUT for remaining data (edge-triggered won't fire again) */
        proxy_epoll_mod_events(g_ctx, ch->local_fd, ch, proxy_get_events(ch));

        LOG_DEBUG("proxy_handle_local_write: partial write %zd/%d bytes "
                  "on fd=%d (channel=%u)",
                  nwritten, ch->recv_buf_len + (int)nwritten,
                  ch->local_fd, ch->channel_id);
    } else {
        /* 全部写入完成 */
        ch->recv_buf_len = 0;

        LOG_DEBUG("proxy_handle_local_write: wrote %zd bytes on fd=%d "
                  "(channel=%u)",
                  nwritten, ch->local_fd, ch->channel_id);
    }

    return (int)nwritten;
}

/*
 * 从 KCP 接收缓冲区刷新数据到本地套接字
 */
int proxy_flush_to_local(channel_t *ch)
{
    uint8_t buf[PROXY_FLUSH_BUF_SIZE];
    int     n;
    int     total_flushed = 0;

    if (!ch) {
        LOG_ERROR("proxy_flush_to_local: null channel");
        return -1;
    }

    if (!ch->kcp) {
        return 0;
    }

    /*
     * 从 KCP 循环接收数据并写入本地套接字。
     * 如果 recv_buf 已有待发送数据（上次写入未完成），
     * 新的数据会在 proxy_write_to_local 中追加到缓冲区。
     */
    while (1) {
        n = kcp_wrap_recv(ch->kcp, buf, sizeof(buf));
        if (n < 0) {
            LOG_ERROR("proxy_flush_to_local: kcp_wrap_recv failed "
                      "(channel=%u)", ch->channel_id);
            return -1;
        }
        if (n == 0) {
            /* 无更多数据 */
            break;
        }

        total_flushed += n;

        if (proxy_write_to_local(ch, buf, n) < n) {
            /*
             * 部分写入或阻塞：recv_buf 已满或写阻塞，
             * 停止刷新，等待下次 EPOLLOUT 继续。
             */
            LOG_DEBUG("proxy_flush_to_local: write stalled at %d bytes "
                      "(channel=%u), pending in recv_buf=%d",
                      total_flushed, ch->channel_id, ch->recv_buf_len);
            break;
        }
    }

    if (total_flushed > 0) {
        LOG_DEBUG("proxy_flush_to_local: flushed %d bytes to local_fd=%d "
                  "(channel=%u)",
                  total_flushed, ch->local_fd, ch->channel_id);
    }

    return 0;
}

/*
 * 将数据从 KCP 写入本地套接字
 */
int proxy_write_to_local(channel_t *ch, const uint8_t *data, int len)
{
    ssize_t nwritten;
    int     remaining_space;

    if (!ch || !data) {
        LOG_ERROR("proxy_write_to_local: null pointer");
        return -1;
    }

    if (len <= 0) {
        return 0;
    }

    if (ch->local_fd < 0) {
        LOG_ERROR("proxy_write_to_local: invalid local_fd for channel %u",
                  ch->channel_id);
        return -1;
    }

    /*
     * 如果 recv_buf 中已有待发送数据，将新数据追加到缓冲区尾部。
     * 这样可以保证数据顺序，避免新数据在旧数据之前发送。
     */
    if (ch->recv_buf_len > 0) {
        remaining_space = CHANNEL_RECV_BUF_SIZE - ch->recv_buf_len;
        if (len > remaining_space) {
            LOG_ERROR("proxy_write_to_local: recv_buf overflow "
                      "(channel=%u, pending=%d, new=%d, capacity=%d)",
                      ch->channel_id, ch->recv_buf_len, len,
                      CHANNEL_RECV_BUF_SIZE);
            return -1;
        }

        memcpy(ch->recv_buf + ch->recv_buf_len, data, (size_t)len);
        ch->recv_buf_len += len;

        LOG_DEBUG("proxy_write_to_local: buffered %d bytes (total pending=%d, "
                  "channel=%u)", len, ch->recv_buf_len, ch->channel_id);
        return 0; /* 数据已缓冲，实际写入为 0 */
    }

    /* recv_buf 为空，尝试直接写入 */
    if (ch->is_tcp) {
        nwritten = write(ch->local_fd, data, (size_t)len);
    } else {
        /*
         * UDP: 使用 sendto 发送到远端地址。
         * 对于已连接的 UDP 套接字，也可用 send()，
         * 但 sendto 更通用。
         */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(ch->remote_port);
        if (inet_pton(AF_INET, ch->remote_addr, &addr.sin_addr) != 1) {
            LOG_ERROR("proxy_write_to_local: invalid remote_addr '%s' "
                      "(channel=%u)", ch->remote_addr, ch->channel_id);
            return -1;
        }
        nwritten = sendto(ch->local_fd, data, (size_t)len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    }

    if (nwritten < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /*
             * 套接字写缓冲区满：将数据全部缓冲到 recv_buf，
             * 等待 EPOLLOUT 事件触发重试。
             */
            if (len > CHANNEL_RECV_BUF_SIZE) {
                LOG_ERROR("proxy_write_to_local: data too large for recv_buf "
                          "(channel=%u, len=%d, capacity=%d)",
                          ch->channel_id, len, CHANNEL_RECV_BUF_SIZE);
                return -1;
            }
            memcpy(ch->recv_buf, data, (size_t)len);
            ch->recv_buf_len = len;

            /*
             * 确保 epoll 注册包含 EPOLLOUT，以便后续可写通知。
             * 需要 ctx 来操作 epoll，通过 g_ctx 获取。
             */
            if (g_ctx) {
                proxy_ensure_epollout(g_ctx, ch);
            }

            LOG_DEBUG("proxy_write_to_local: write would block, "
                      "buffered %d bytes (channel=%u)",
                      len, ch->channel_id);
            return 0;
        }

        if (errno == EINTR) {
            /* 被信号中断，尝试缓冲 */
            if (len > CHANNEL_RECV_BUF_SIZE) {
                LOG_ERROR("proxy_write_to_local: data too large for recv_buf "
                          "(channel=%u, len=%d)",
                          ch->channel_id, len);
                return -1;
            }
            memcpy(ch->recv_buf, data, (size_t)len);
            ch->recv_buf_len = len;
            return 0;
        }

        LOG_ERROR("proxy_write_to_local: write/sendto(fd=%d) failed: %s "
                  "(channel=%u)",
                  ch->local_fd, strerror(errno), ch->channel_id);
        return -1;
    }

    if (nwritten < len) {
        /*
         * 部分写入：将剩余数据缓冲到 recv_buf。
         * 这在非阻塞 TCP 套接字上可能发生，尽管较少见。
         */
        int remaining = len - (int)nwritten;
        if (remaining > CHANNEL_RECV_BUF_SIZE) {
            LOG_ERROR("proxy_write_to_local: remaining data too large "
                      "(channel=%u, remaining=%d, capacity=%d)",
                      ch->channel_id, remaining, CHANNEL_RECV_BUF_SIZE);
            return -1;
        }
        memcpy(ch->recv_buf, data + nwritten, (size_t)remaining);
        ch->recv_buf_len = remaining;

        /* 确保 EPOLLOUT 已注册 */
        if (g_ctx) {
            proxy_ensure_epollout(g_ctx, ch);
        }

        LOG_DEBUG("proxy_write_to_local: partial write %zd/%d bytes, "
                  "buffered %d (channel=%u)",
                  nwritten, len, remaining, ch->channel_id);
    }

    return (int)nwritten;
}

/*
 * 关闭通道的本地连接
 */
void proxy_close_local(channel_t *ch)
{
    global_ctx_t *ctx;

    if (!ch) {
        return;
    }

    ctx = g_ctx;

    /*
     * 关闭 local_fd。
     * 对于 UDP（listen_fd == local_fd），只关闭一次。
     */
    if (ch->local_fd >= 0) {
        LOG_DEBUG("proxy_close_local: closing local_fd=%d (channel=%u)",
                  ch->local_fd, ch->channel_id);

        if (ctx && ctx->epoll_fd >= 0) {
            proxy_epoll_del(ctx, ch->local_fd);
        }
        close(ch->local_fd);

        /* 如果是 UDP（listen_fd == local_fd），一并清除 listen_fd */
        if (ch->listen_fd == ch->local_fd) {
            ch->listen_fd = -1;
        }
        ch->local_fd = -1;
    }

    /*
     * 关闭 listen_fd（如果与 local_fd 不同，即 TCP 监听套接字）。
     */
    if (ch->listen_fd >= 0 && ch->listen_fd != ch->local_fd) {
        LOG_DEBUG("proxy_close_local: closing listen_fd=%d (channel=%u)",
                  ch->listen_fd, ch->channel_id);

        if (ctx && ctx->epoll_fd >= 0) {
            proxy_epoll_del(ctx, ch->listen_fd);
        }
        close(ch->listen_fd);
        ch->listen_fd = -1;
    }

    /* 清空接收缓冲区 */
    ch->recv_buf_len = 0;
}

/*
 * 获取通道本地套接字的 epoll 事件掩码
 */
uint32_t proxy_get_events(channel_t *ch)
{
    uint32_t events = EPOLLIN | EPOLLET;

    if (!ch) {
        return 0;
    }

    /*
     * 如果 recv_buf 中有待发送数据，注册 EPOLLOUT
     * 以便在套接字可写时收到通知。
     */
    if (ch->recv_buf_len > 0) {
        events |= EPOLLOUT;
    }

    return events;
}

/*
 * 处理 epoll 事件分发到代理
 *
 * 这是主事件分发器，从 epoll 事件中识别 fd 对应的通道和角色，
 * 然后将事件路由到相应的处理函数。
 */
int proxy_handle_event(global_ctx_t *ctx, int fd, uint32_t events)
{
    channel_t *ch;
    int        is_listen_fd;
    int        ret;

    if (!ctx) {
        LOG_ERROR("proxy_handle_event: null context");
        return -1;
    }

    if (fd < 0) {
        LOG_ERROR("proxy_handle_event: invalid fd %d", fd);
        return -1;
    }

    /* 查找 fd 对应的通道 */
    ch = proxy_find_channel_by_fd(ctx, fd);
    if (!ch) {
        LOG_WARN("proxy_handle_event: no channel found for fd=%d", fd);
        return -1;
    }

    /*
     * 判断 fd 角色。
     * 对于 UDP，listen_fd == local_fd，优先按 local_fd 处理。
     */
    is_listen_fd = (fd == ch->listen_fd && fd != ch->local_fd);

    if (is_listen_fd) {
        /* ---- 监听套接字事件 ---- */

        if (events & (EPOLLERR | EPOLLHUP)) {
            LOG_ERROR("proxy_handle_event: error on listen_fd=%d "
                      "(channel=%u, events=0x%x)",
                      fd, ch->channel_id, events);
            proxy_close_local(ch);
            return -1;
        }

        if (events & EPOLLIN) {
            ret = proxy_accept(ctx, ch);
            if (ret < 0) {
                /* accept 返回 -1 可能是 EAGAIN（无连接），不算错误 */
                LOG_DEBUG("proxy_handle_event: proxy_accept returned %d "
                          "(channel=%u)", ret, ch->channel_id);
            }
        }

    } else {
        /* ---- 本地连接套接字事件 ---- */

        if (events & (EPOLLERR | EPOLLHUP)) {
            LOG_ERROR("proxy_handle_event: error/hangup on local_fd=%d "
                      "(channel=%u, events=0x%x)",
                      fd, ch->channel_id, events);
            proxy_close_local(ch);
            channel_send_ctrl(ch, MPF_RST);
            ch->state = CHANNEL_CLOSED;
            return -1;
        }

        if (events & EPOLLIN) {
            ret = proxy_handle_local_read(ctx, ch);
            if (ret < 0) {
                LOG_ERROR("proxy_handle_event: proxy_handle_local_read "
                          "failed (channel=%u, fd=%d)",
                          ch->channel_id, fd);
                proxy_close_local(ch);
                return -1;
            }
        }

        if (events & EPOLLOUT) {
            ret = proxy_handle_local_write(ch);
            if (ret < 0) {
                LOG_ERROR("proxy_handle_event: proxy_handle_local_write "
                          "failed (channel=%u, fd=%d)",
                          ch->channel_id, fd);
                proxy_close_local(ch);
                return -1;
            }

            /*
             * 写操作完成后，如果 recv_buf 已清空，
             * 更新 epoll 注册以移除 EPOLLOUT，减少不必要的事件通知。
             */
            if (ch->recv_buf_len == 0) {
                uint32_t new_events = proxy_get_events(ch);
                proxy_epoll_mod_events(ctx, fd, ch, new_events);
            }
        }
    }

    return 0;
}

/*
 * 添加 fd 到 epoll（edge-triggered，关联通道指针）
 */
int proxy_epoll_add(global_ctx_t *ctx, int fd, void *ptr)
{
    struct epoll_event ev;

    if (!ctx) {
        LOG_ERROR("proxy_epoll_add: null context");
        return -1;
    }

    if (fd < 0) {
        LOG_ERROR("proxy_epoll_add: invalid fd %d", fd);
        return -1;
    }

    if (ctx->epoll_fd < 0) {
        LOG_ERROR("proxy_epoll_add: epoll_fd not initialized");
        return -1;
    }

    /*
     * EPOLLIN:  监听可读事件
     * EPOLLET:  边缘触发模式（高性能，避免重复通知）
     * data.fd = fd:  存储 fd，main.c 通过 data.fd 获取触发源。
     */
    ev.events   = EPOLLIN | EPOLLET;
    ev.data.fd  = fd;

    (void)ptr;  /* 已改用 data.fd 存储 fd，ptr 保留兼容 */

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERROR("proxy_epoll_add: epoll_ctl(EPOLL_CTL_ADD, fd=%d) "
                  "failed: %s", fd, strerror(errno));
        return -1;
    }

    LOG_DEBUG("proxy_epoll_add: added fd=%d to epoll (ptr=%p)", fd, ptr);

    return 0;
}

/*
 * 从 epoll 移除 fd
 */
int proxy_epoll_del(global_ctx_t *ctx, int fd)
{
    if (!ctx) {
        LOG_ERROR("proxy_epoll_del: null context");
        return -1;
    }

    if (fd < 0) {
        return 0; /* 静默忽略无效 fd */
    }

    if (ctx->epoll_fd < 0) {
        return 0;
    }

    /*
     * epoll_ctl(EPOLL_CTL_DEL) 在较新的内核上不需要 event 参数，
     * 内核 2.6.9+ 允许 NULL，会忽略 fd。
     */
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        /*
         * ENOENT 表示 fd 未注册（可能已被移除），不算错误。
         * EBADF  表示 fd 已关闭，也不算错误。
         */
        if (errno == ENOENT || errno == EBADF) {
            LOG_DEBUG("proxy_epoll_del: fd=%d already removed or closed", fd);
            return 0;
        }
        LOG_ERROR("proxy_epoll_del: epoll_ctl(EPOLL_CTL_DEL, fd=%d) "
                  "failed: %s", fd, strerror(errno));
        return -1;
    }

    LOG_DEBUG("proxy_epoll_del: removed fd=%d from epoll", fd);

    return 0;
}
