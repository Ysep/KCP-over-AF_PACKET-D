/*
 * af_packet.c - AF_PACKET 原始套接字实现
 *
 * 在数据链路层直接收发以太网帧，绕过 TCP/IP 协议栈。
 * 支持 BPF 过滤器、MAC 地址发现、NIC MTU 管理以及冲突检测。
 *
 * 所有函数在错误路径上均通过 LOG_ERROR 记录 errno，
 * 并返回适当的错误码。缓冲区操作均包含溢出保护。
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║                   AF_PACKET 原始套接字 API 使用说明                        ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                          ║
 * ║   AF_PACKET 允许用户态程序绕过内核 TCP/IP 协议栈，直接在数据链路层        ║
 * ║   收发以太网帧。关键系统调用和创建步骤：                                   ║
 * ║                                                                          ║
 * ║   1. socket(AF_PACKET, SOCK_RAW, htons(ethertype))                       ║
 * ║      创建指定 EtherType 的原始套接字                                      ║
 * ║      ethertype 参数同时作为绑定过滤条件                                   ║
 * ║                                                                          ║
 * ║   2. setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V2)                  ║
 * ║      升级到 TPACKET_V2 以获得更高的吞吐量                                 ║
 * ║      失败时自动回退到 TPACKET_V1                                          ║
 * ║                                                                          ║
 * ║   3. setsockopt(SOL_SOCKET, SO_SNDBUF / SO_RCVBUF)                       ║
 * ║      扩大套接字缓冲区 (256KB发送 / 512KB接收)                              ║
 * ║                                                                          ║
 * ║   4. bind(sock, &sockaddr_ll, sizeof(sll))                               ║
 * ║      绑定到指定网卡接口 (sll_ifindex = 接口索引)                          ║
 * ║                                                                          ║
 * ║   5. fcntl(sock, F_SETFL, O_NONBLOCK)                                    ║
 * ║      设置为非阻塞模式，配合 epoll 使用                                    ║
 * ║                                                                          ║
 * ║   6. setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog)                 ║
 * ║      安装 BPF 过滤器，内核级过滤仅接收匹配 EtherType 的帧                 ║
 * ║      大幅减少不必要的用户态/内核态切换                                     ║
 * ║                                                                          ║
 * ║   【发送流程】                                                            ║
 * ║   构造以太网帧: [dst_mac(6) | src_mac(6) | ethertype(2) | payload(N)]    ║
 * ║   sendto(sock, frame, len, 0, &sockaddr_ll, sizeof(sll))                 ║
 * ║                                                                          ║
 * ║   【接收流程】                                                            ║
 * ║   recvfrom(sock, buf, size, 0, &sockaddr_ll, &sll_len)                   ║
 * ║   解析: dst_mac = buf[0..5], src_mac = buf[6..11], ethertype = buf[12..13]║
 * ║   负载: buf[14..recvd-1]                                                  ║
 * ║                                                                          ║
 * ║   【BPF 过滤器字节码说明】                                                ║
 * ║   指令0: ldh [12]        — 从偏移12加载16位 (EtherType字段)              ║
 * ║   指令1: jeq #V, 0, 1   — 等于ethertype则继续，否则跳转到reject          ║
 * ║   指令2: ret #0          — 拒绝（返回0字节）                              ║
 * ║   指令3: ret #0xFFFFFFFF — 接受（返回全部）                               ║
 * ║                                                                          ║
 * ║   【辅助功能】                                                            ║
 * ║   - af_packet_get_mac():   SIOCGIFHWADDR ioctl 获取 MAC 地址            ║
 * ║   - af_packet_get_ifindex(): SIOCGIFINDEX ioctl 获取接口索引            ║
 * ║   - af_packet_set_mtu():   SIOCSIFMTU ioctl 设置 MTU                   ║
 * ║   - af_packet_get_mtu():   SIOCGIFMTU ioctl 获取 MTU                   ║
 * ║   - af_packet_detect_conflict(): 解析 /proc/net/packet 检测冲突         ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

#include "af_packet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* ============================================================================
 * 内部常量
 * ============================================================================ */

/* 高性能套接字缓冲区大小 */
#define AF_PKT_SOCK_SNDBUF      (256 * 1024)
#define AF_PKT_SOCK_RCVBUF      (512 * 1024)

/* /proc/net/packet 行最大长度 */
#define PROC_NET_PACKET_LINE_MAX 512

/* 单次发送/接收帧硬上限（以太网头 + 有效载荷 + VLAN + 安全余量） */
#define AF_PKT_MAX_FRAME         (ETH_HDR_SIZE + ETH_MAX_PAYLOAD + 128)

/* ============================================================================
 * 内部辅助函数
 * ============================================================================ */

/*
 * 尝试将套接字缓冲区大小设置为期望值。
 * 失败时仅记录警告，因为内核可能限制缓冲区大小。
 */
static void af_packet_set_sockbuf(int sock, int optname, int desired)
{
    int val = desired;

    if (setsockopt(sock, SOL_SOCKET, optname, &val, sizeof(val)) < 0) {
        LOG_ERROR("af_packet: setsockopt(%s, %d) failed (non-fatal): %s",
                  (optname == SO_SNDBUF) ? "SO_SNDBUF" : "SO_RCVBUF",
                  desired, strerror(errno));
    }
}

/*
 * 安全的字符串截断复制（始终以 NUL 结尾）。
 */
static size_t safe_strncpy(char *dst, const char *src, size_t dstsize)
{
    size_t i;

    if (!dst || dstsize == 0) {
        return 0;
    }

    for (i = 0; i < dstsize - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';

    return i;
}

/* ============================================================================
 * af_packet_create
 * ============================================================================ */

/*
 * 注意: ethertype 参数必须是网络字节序 (big-endian)。
 * 调用方应使用 htons() 转换。socket() 和 bind() 的内核 API
 * 要求网络字节序的协议号。
 */
int af_packet_create(const char *if_name, uint16_t ethertype, int *ifindex)
{
    int              sock = -1;
    int              idx  = -1;
    struct sockaddr_ll sll;
    int              flags;
    int              version;

    /* --- 参数校验 --- */
    if (!if_name || !ifindex) {
        LOG_ERROR("af_packet_create: null argument (if_name=%p ifindex=%p)",
                  (const void *)if_name, (const void *)ifindex);
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_create: interface name too long: \"%s\"", if_name);
        errno = EINVAL;
        return -1;
    }

    /* --- 创建 AF_PACKET 原始套接字 --- */
    sock = socket(AF_PACKET, SOCK_RAW, ethertype);
    if (sock < 0) {
        LOG_ERROR("af_packet_create: socket(AF_PACKET, SOCK_RAW, 0x%04X) "
                  "failed: %s", ethertype, strerror(errno));
        return -1;
    }

    /* --- 设置 TPACKET_V2 以获得更高性能 --- */
    version = TPACKET_V2;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION,
                   &version, sizeof(version)) < 0) {
        /* 非致命：回退至 TPACKET_V1 */
        LOG_ERROR("af_packet_create: PACKET_VERSION(TPACKET_V2) failed "
                  "(non-fatal, falling back to V1): %s", strerror(errno));
    }

    /* --- 扩大套接字缓冲区 --- */
    af_packet_set_sockbuf(sock, SO_SNDBUF, AF_PKT_SOCK_SNDBUF);
    af_packet_set_sockbuf(sock, SO_RCVBUF, AF_PKT_SOCK_RCVBUF);

    /* --- 获取网卡接口索引 --- */
    idx = af_packet_get_ifindex(sock, if_name);
    if (idx < 0) {
        LOG_ERROR("af_packet_create: af_packet_get_ifindex(%s) failed", if_name);
        goto fail;
    }

    /* --- 绑定到网卡接口 --- */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = ethertype;
    sll.sll_ifindex  = idx;

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_ERROR("af_packet_create: bind(%s, ifindex=%d) failed: %s",
                  if_name, idx, strerror(errno));
        goto fail;
    }

    /* --- 设置为非阻塞模式 --- */
    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        LOG_ERROR("af_packet_create: fcntl(F_GETFL) failed: %s",
                  strerror(errno));
        goto fail;
    }

    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERROR("af_packet_create: fcntl(F_SETFL, O_NONBLOCK) failed: %s",
                  strerror(errno));
        goto fail;
    }

    *ifindex = idx;
    return sock;

fail:
    if (sock >= 0) {
        close(sock);
    }
    return -1;
}

/* ============================================================================
 * af_packet_set_bpf
 * ============================================================================ */

int af_packet_set_bpf(int sock, uint16_t ethertype)
{
    /*
     * BPF 过滤器字节码说明：
     *
     *   指令 0: ldh [12]        - 从帧偏移 12 处加载 16 位（EtherType 字段）
     *   指令 1: jeq #V, 0, 1    - 如果 A == ethertype 则继续，否则跳转至 reject
     *   指令 2: ret #0           - reject（返回 0）
     *   指令 3: ret #0xFFFFFFFF  - accept（返回最大值）
     *
     * 注意：ldh [k] 使用 be16_to_cpu 转换，因此比较值必须为主机字节序。
     */
    struct sock_filter bpf_code[] = {
        /* 000 */ BPF_STMT(BPF_LD  | BPF_H   | BPF_ABS, 12),
        /* 001 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                           ntohs(ethertype), 0, 1),
        /* 002 */ BPF_STMT(BPF_RET | BPF_K, 0),
        /* 003 */ BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
    };

    struct sock_fprog bpf_prog;
    socklen_t         opt_len;
    int               ret;
    int               saved_errno;

    if (sock < 0) {
        LOG_ERROR("af_packet_set_bpf: invalid socket fd %d", sock);
        errno = EBADF;
        return -1;
    }

    bpf_prog.len    = sizeof(bpf_code) / sizeof(bpf_code[0]);
    bpf_prog.filter = bpf_code;

    if (bpf_prog.len > BPF_FILTER_MAX) {
        LOG_ERROR("af_packet_set_bpf: BPF program too long (%u instructions)",
                  bpf_prog.len);
        errno = EINVAL;
        return -1;
    }

    ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                     &bpf_prog, sizeof(bpf_prog));
    if (ret < 0) {
        saved_errno = errno;
        LOG_ERROR("af_packet_set_bpf: SO_ATTACH_FILTER failed "
                  "(ethertype=0x%04X): %s", ethertype, strerror(saved_errno));

        /*
         * 如果已存在过滤器，则先尝试分离再重新附加。
         * EEXIST 或已附加状态在不同内核版本中可能表现不同。
         */
        opt_len = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER,
                       NULL, opt_len) == 0) {
            ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                             &bpf_prog, sizeof(bpf_prog));
            if (ret < 0) {
                saved_errno = errno;
                LOG_ERROR("af_packet_set_bpf: SO_ATTACH_FILTER retry "
                          "failed: %s", strerror(saved_errno));
                errno = saved_errno;
                return -1;
            }
            /* 重新附加成功 */
            return 0;
        }

        errno = saved_errno;
        return -1;
    }

    return 0;
}

/* ============================================================================
 * af_packet_send
 *
 * ethertype 为网络字节序 (big-endian)
 * ============================================================================ */

ssize_t af_packet_send(int sock, int ifindex,
                       const uint8_t dst_mac[ETH_MAC_ADDR_LEN],
                       const uint8_t src_mac[ETH_MAC_ADDR_LEN],
                       uint16_t ethertype,
                       const uint8_t *payload, size_t payload_len)
{
    uint8_t            frame_buf[AF_PKT_MAX_FRAME];
    size_t             frame_len;
    struct sockaddr_ll sll;
    ssize_t            sent;
    int                saved_errno;

    /* --- 参数校验 --- */
    if (sock < 0) {
        LOG_ERROR("af_packet_send: invalid socket fd %d", sock);
        errno = EBADF;
        return -1;
    }

    if (!dst_mac || !src_mac) {
        LOG_ERROR("af_packet_send: null MAC address pointer");
        errno = EINVAL;
        return -1;
    }

    if (!payload && payload_len > 0) {
        LOG_ERROR("af_packet_send: null payload with non-zero length %zu",
                  payload_len);
        errno = EINVAL;
        return -1;
    }

    if (payload_len > ETH_MAX_PAYLOAD) {
        LOG_ERROR("af_packet_send: payload length %zu exceeds ETH_MAX_PAYLOAD %d",
                  payload_len, ETH_MAX_PAYLOAD);
        errno = EMSGSIZE;
        return -1;
    }

    if (ifindex <= 0) {
        LOG_ERROR("af_packet_send: invalid ifindex %d", ifindex);
        errno = EINVAL;
        return -1;
    }

    /* --- 构造以太网帧 --- */
    frame_len = ETH_HDR_SIZE + payload_len;

    if (frame_len > sizeof(frame_buf)) {
        LOG_ERROR("af_packet_send: frame too large (%zu > %zu)",
                  frame_len, sizeof(frame_buf));
        errno = EMSGSIZE;
        return -1;
    }

    /* 以太网头部：目标 MAC + 源 MAC + EtherType */
    memcpy(frame_buf, dst_mac, ETH_MAC_ADDR_LEN);
    memcpy(frame_buf + ETH_MAC_ADDR_LEN, src_mac, ETH_MAC_ADDR_LEN);
    /* ethertype 为网络字节序 (big-endian), 转为 host 序后再手动编码 */
    {
        uint16_t host_ethertype = ntohs(ethertype);
        frame_buf[12] = (uint8_t)((host_ethertype >> 8) & 0xFF);
        frame_buf[13] = (uint8_t)(host_ethertype & 0xFF);
    }

    /* 负载 */
    if (payload && payload_len > 0) {
        memcpy(frame_buf + ETH_HDR_SIZE, payload, payload_len);
    }

    /* --- 构造目标地址 --- */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = ethertype;
    sll.sll_ifindex  = ifindex;
    sll.sll_hatype   = 0;
    sll.sll_pkttype  = 0;
    sll.sll_halen    = ETH_ALEN;
    memcpy(sll.sll_addr, dst_mac, ETH_ALEN);
    /* sll_addr 在结构体中为 8 字节，ETH_ALEN 为 6；其余由 memset 归零 */

    /* --- 发送 --- */
    sent = sendto(sock, frame_buf, frame_len, 0,
                  (const struct sockaddr *)&sll, sizeof(sll));
    if (sent < 0) {
        saved_errno = errno;
        LOG_ERROR("af_packet_send: sendto failed (ifindex=%d, len=%zu): %s",
                  ifindex, frame_len, strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }

    if ((size_t)sent != frame_len) {
        LOG_ERROR("af_packet_send: partial send (%zd of %zu bytes)", sent, frame_len);
        /* 部分发送视为错误 */
        errno = EIO;
        return -1;
    }

    return sent;
}

/* ============================================================================
 * af_packet_recv
 * ============================================================================ */

ssize_t af_packet_recv(int sock, uint8_t *buf, size_t buf_size,
                       uint8_t src_mac[ETH_MAC_ADDR_LEN],
                       uint8_t dst_mac[ETH_MAC_ADDR_LEN],
                       uint16_t *ethertype)
{
    uint8_t            recv_buf[AF_PKT_MAX_FRAME];
    struct sockaddr_ll sll;
    socklen_t          sll_len;
    ssize_t            recvd;
    size_t             payload_len;
    int                saved_errno;

    /* --- 参数校验 --- */
    if (sock < 0) {
        LOG_ERROR("af_packet_recv: invalid socket fd %d", sock);
        errno = EBADF;
        return -1;
    }

    if (!buf || buf_size == 0) {
        LOG_ERROR("af_packet_recv: null or zero-size buffer");
        errno = EINVAL;
        return -1;
    }

    if (!src_mac || !dst_mac || !ethertype) {
        LOG_ERROR("af_packet_recv: null output pointer");
        errno = EINVAL;
        return -1;
    }

    /* --- 接收原始帧 --- */
    memset(&sll, 0, sizeof(sll));
    sll_len = sizeof(sll);

    recvd = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                     (struct sockaddr *)&sll, &sll_len);
    if (recvd < 0) {
        saved_errno = errno;
        if (saved_errno != EAGAIN && saved_errno != EWOULDBLOCK) {
            LOG_ERROR("af_packet_recv: recvfrom failed: %s", strerror(saved_errno));
        }
        errno = saved_errno;
        return -1;
    }

    /* --- 验证帧长度 --- */
    if ((size_t)recvd < ETH_HDR_SIZE) {
        LOG_ERROR("af_packet_recv: received frame too short (%zd bytes, "
                  "minimum %d)", recvd, ETH_HDR_SIZE);
        errno = EINVAL;
        return -1;
    }

    if ((size_t)recvd > sizeof(recv_buf)) {
        LOG_ERROR("af_packet_recv: received frame exceeds buffer "
                  "(%zd > %zu)", recvd, sizeof(recv_buf));
        errno = EMSGSIZE;
        return -1;
    }

    /* --- 解析以太网头部 --- */
    memcpy(dst_mac, recv_buf, ETH_MAC_ADDR_LEN);
    memcpy(src_mac, recv_buf + ETH_MAC_ADDR_LEN, ETH_MAC_ADDR_LEN);
    *ethertype = ((uint16_t)recv_buf[12] << 8) | (uint16_t)recv_buf[13];

    payload_len = (size_t)recvd - ETH_HDR_SIZE;

    /* --- 将负载复制到调用者缓冲区 --- */
    if (payload_len > buf_size) {
        LOG_ERROR("af_packet_recv: payload length %zu exceeds caller buffer %zu",
                  payload_len, buf_size);
        errno = EMSGSIZE;
        return -1;
    }

    if (payload_len > 0) {
        memcpy(buf, recv_buf + ETH_HDR_SIZE, payload_len);
    }

    return (ssize_t)payload_len;
}

/* ============================================================================
 * af_packet_get_mac
 * ============================================================================ */

int af_packet_get_mac(int sock, const char *if_name, uint8_t mac[ETH_MAC_ADDR_LEN])
{
    struct ifreq ifr;
    int          ret;

    if (!if_name || !mac) {
        LOG_ERROR("af_packet_get_mac: null argument");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_get_mac: interface name too long: \"%s\"", if_name);
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    safe_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

    if (sock >= 0) {
        ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
    } else {
        /* 调用者未提供有效套接字，则尝试使用临时套接字 */
        int tmp_sock;

        tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_sock < 0) {
            LOG_ERROR("af_packet_get_mac: cannot create temp socket: %s",
                      strerror(errno));
            return -1;
        }
        ret = ioctl(tmp_sock, SIOCGIFHWADDR, &ifr);
        close(tmp_sock);
    }

    if (ret < 0) {
        LOG_ERROR("af_packet_get_mac: SIOCGIFHWADDR(%s) failed: %s",
                  if_name, strerror(errno));
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_MAC_ADDR_LEN);
    return 0;
}

/* ============================================================================
 * af_packet_get_ifindex
 * ============================================================================ */

int af_packet_get_ifindex(int sock, const char *if_name)
{
    struct ifreq ifr;
    int          ret;

    if (!if_name) {
        LOG_ERROR("af_packet_get_ifindex: null if_name");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_get_ifindex: interface name too long: \"%s\"",
                  if_name);
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    safe_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

    if (sock >= 0) {
        ret = ioctl(sock, SIOCGIFINDEX, &ifr);
    } else {
        int tmp_sock;

        tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_sock < 0) {
            LOG_ERROR("af_packet_get_ifindex: cannot create temp socket: %s",
                      strerror(errno));
            return -1;
        }
        ret = ioctl(tmp_sock, SIOCGIFINDEX, &ifr);
        close(tmp_sock);
    }

    if (ret < 0) {
        LOG_ERROR("af_packet_get_ifindex: SIOCGIFINDEX(%s) failed: %s",
                  if_name, strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

/* ============================================================================
 * af_packet_set_mtu
 * ============================================================================ */

int af_packet_set_mtu(int sock, const char *if_name, int mtu)
{
    struct ifreq ifr;
    int          ret;

    if (!if_name) {
        LOG_ERROR("af_packet_set_mtu: null if_name");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_set_mtu: interface name too long: \"%s\"", if_name);
        errno = EINVAL;
        return -1;
    }

    if (mtu <= 0) {
        LOG_ERROR("af_packet_set_mtu: invalid MTU value %d", mtu);
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    safe_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
    ifr.ifr_mtu = mtu;

    if (sock >= 0) {
        ret = ioctl(sock, SIOCSIFMTU, &ifr);
    } else {
        int tmp_sock;

        tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_sock < 0) {
            LOG_ERROR("af_packet_set_mtu: cannot create temp socket: %s",
                      strerror(errno));
            return -1;
        }
        ret = ioctl(tmp_sock, SIOCSIFMTU, &ifr);
        close(tmp_sock);
    }

    if (ret < 0) {
        LOG_ERROR("af_packet_set_mtu: SIOCSIFMTU(%s, %d) failed: %s",
                  if_name, mtu, strerror(errno));
        return -1;
    }

    return 0;
}

/* ============================================================================
 * af_packet_get_mtu
 * ============================================================================ */

int af_packet_get_mtu(int sock, const char *if_name)
{
    struct ifreq ifr;
    int          ret;

    if (!if_name) {
        LOG_ERROR("af_packet_get_mtu: null if_name");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_get_mtu: interface name too long: \"%s\"", if_name);
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    safe_strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

    if (sock >= 0) {
        ret = ioctl(sock, SIOCGIFMTU, &ifr);
    } else {
        int tmp_sock;

        tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp_sock < 0) {
            LOG_ERROR("af_packet_get_mtu: cannot create temp socket: %s",
                      strerror(errno));
            return -1;
        }
        ret = ioctl(tmp_sock, SIOCGIFMTU, &ifr);
        close(tmp_sock);
    }

    if (ret < 0) {
        LOG_ERROR("af_packet_get_mtu: SIOCGIFMTU(%s) failed: %s",
                  if_name, strerror(errno));
        return -1;
    }

    return ifr.ifr_mtu;
}

/* ============================================================================
 * af_packet_detect_conflict
 *
 * TODO: Call in main.c before af_packet_create
 * ============================================================================ */

int af_packet_detect_conflict(const char *if_name, uint16_t ethertype)
{
    FILE *fp;
    char  line[PROC_NET_PACKET_LINE_MAX];
    int   found_conflict = 0;

    if (!if_name) {
        LOG_ERROR("af_packet_detect_conflict: null if_name");
        errno = EINVAL;
        return -1;
    }

    if (strnlen(if_name, IFNAMSIZ + 1) > IFNAMSIZ) {
        LOG_ERROR("af_packet_detect_conflict: interface name too long: \"%s\"",
                  if_name);
        errno = EINVAL;
        return -1;
    }

    fp = fopen("/proc/net/packet", "r");
    if (!fp) {
        LOG_ERROR("af_packet_detect_conflict: cannot open "
                  "/proc/net/packet: %s", strerror(errno));
        return -1;
    }

    /*
     * /proc/net/packet 格式（Linux 4.x+ 典型输出）：
     *
     *   sk       RefCnt Type Proto  Iface R Rmem   User   Inode
     *   ffff...  2      1    88b5   eth0  1 0      0      0     0
     *
     * 字段说明（空格/制表符分隔）：
     *   - Proto: 十六进制 EtherType（主机字节序？实际上是网络字节序的十六进制表示）
     *
     * 解析策略：
     *   1. 跳过标题行（以 "sk" 开头）
     *   2. 对每一行，提取 Proto（第 4 列）和 Iface（第 5 列）
     *   3. 比较 Iface 和 Proto
     */

    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        char          *token;
        char          *saveptr;
        int            col;
        int            match_iface;
        unsigned long  proto_val;

        /* 跳过标题行 */
        if (line[0] == 's' && line[1] == 'k') {
            continue;
        }

        /*
         * 使用 strtok_r 安全解析列。
         * 列索引（0-based）：
         *   0:sk  1:RefCnt  2:Type  3:Proto  4:Iface  5:R 6:Rmem ...
         */
        col = 0;
        match_iface = 0;
        proto_val   = 0;

        token = strtok_r(line, " \t\n", &saveptr);
        while (token != NULL) {
            if (col == 3) {
                /* Proto 字段 - 十六进制 */
                char *endptr;
                proto_val = strtoul(token, &endptr, 16);
                if (*endptr != '\0' && *endptr != ' ' && *endptr != '\t') {
                    /* 解析失败，跳过此行 */
                    proto_val = 0;
                    break;
                }
            } else if (col == 4) {
                /* Iface 字段 */
                if (strcmp(token, if_name) == 0) {
                    match_iface = 1;
                }
            }

            token = strtok_r(NULL, " \t\n", &saveptr);
            col++;
        }

        /*
         * 检查冲突：同一网卡接口上存在匹配的 EtherType 的套接字。
         *
         * 注意：/proc/net/packet 中的 Proto 字段为十六进制网络字节序。
         * 直接比较十六进制值即可。
         */
        if (match_iface && proto_val == ethertype) {
            found_conflict = 1;
            break;
        }
    }

    fclose(fp);

    if (found_conflict) {
        LOG_ERROR("af_packet_detect_conflict: conflict detected on %s "
                  "(ethertype=0x%04X)", if_name, ethertype);
        return 1;
    }

    return 0;
}

/* ============================================================================
 * af_packet_close
 * ============================================================================ */

void af_packet_close(int sock)
{
    if (sock >= 0) {
        /*
         * 在关闭之前分离 BPF 过滤器（尽力而为）。
         * 虽然 close 会自动清理，但显式分离可以避免残留状态。
         */
        setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER, NULL, 0);

        if (close(sock) < 0) {
            LOG_ERROR("af_packet_close: close(%d) failed: %s",
                      sock, strerror(errno));
        }
    }
}
