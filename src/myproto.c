/*
 * myproto.c - MyProto 私有链路层协议模块实现
 *
 * 实现协议头的封装/解析、帧验证、CRC32 校验以及 SM4/SM3 加密存根。
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "types.h"
#include "myproto.h"
#include "crypto.h"

/* ============================================================================
 * 内部常量
 * ============================================================================ */

/* 帧最小长度：MyProto 协议头（以太网头由 af_packet 层处理） */
#define MYPROTO_MIN_FRAME_SIZE  (MYPROTO_HDR_SIZE)

/* ============================================================================
 * CRC32 实现
 * ============================================================================ */

/*
 * 生成 CRC32 查找表（标准多项式 0xEDB88320，即反射的 0x04C11DB7）。
 * 线程安全：使用静态标志 + 一次性初始化。
 */
static void crc32_generate_table(uint32_t table[256])
{
    int i, j;

    for (i = 0; i < 256; i++) {
        uint32_t crc = (uint32_t)i;
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
}

/*
 * 获取 CRC32 查找表（惰性初始化，线程安全）。
 */
static const uint32_t *crc32_get_table(void)
{
    static uint32_t table[256];
    static volatile int initialized = 0;

    /*
     * 双重检查锁定模式的简化版：使用 volatile 标志。
     * 最坏情况：多个线程同时初始化，但 table 的内容是幂等的
     * （相同输入总是产生相同输出），因此不会导致数据竞争问题。
     */
    if (!initialized) {
        crc32_generate_table(table);
        initialized = 1;
    }
    return table;
}

/*
 * myproto_crc32 - 计算数据的 CRC32 校验值。
 *
 * 使用标准 CRC-32/ISO-HDLC 多项式 (0xEDB88320 反射形式)。
 * 初始值 0xFFFFFFFF，最终异或 0xFFFFFFFF。
 */
uint32_t myproto_crc32(const uint8_t *data, size_t len)
{
    const uint32_t *table = crc32_get_table();
    uint32_t crc = 0xFFFFFFFF;
    size_t i;

    for (i = 0; i < len; i++) {
        crc = (crc >> 8) ^ table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/* ============================================================================
 * 公开 API 实现
 * ============================================================================ */

/*
 * myproto_validate_hdr - 验证 MyProto 帧头合法性。
 *
 * 检查项：
 *   - 魔数必须为 MYPROTO_MAGIC (0x4D50)
 *   - 版本号必须为 MYPROTO_VERSION (0x01)
 *   - channel_id 必须在 [0, MAX_CHANNELS) 范围内
 *   - data_len 不得超过 ETH_MAX_PAYLOAD
 */
int myproto_validate_hdr(const myproto_hdr_t *hdr)
{
    if (!hdr) {
        LOG_ERROR("myproto_validate_hdr: null header pointer");
        return -1;
    }

    if (hdr->magic != MYPROTO_MAGIC) {
        LOG_ERROR("myproto_validate_hdr: invalid magic 0x%04X (expected 0x%04X)",
                  hdr->magic, MYPROTO_MAGIC);
        return -1;
    }

    if (hdr->version != MYPROTO_VERSION) {
        LOG_ERROR("myproto_validate_hdr: unsupported version %u (expected %u)",
                  hdr->version, MYPROTO_VERSION);
        return -1;
    }

    if (hdr->channel_id >= MAX_CHANNELS && hdr->channel_id != HEARTBEAT_CH_ID) {
        LOG_ERROR("myproto_validate_hdr: channel_id %u exceeds MAX_CHANNELS (%u)",
                  hdr->channel_id, MAX_CHANNELS);
        return -1;
    }

    if (hdr->data_len > ETH_MAX_PAYLOAD) {
        LOG_ERROR("myproto_validate_hdr: data_len %u exceeds ETH_MAX_PAYLOAD (%u)",
                  hdr->data_len, ETH_MAX_PAYLOAD);
        return -1;
    }

    return 0;
}

/*
 * myproto_build_frame - 构造完整的 MyProto 帧。
 *
 * 缓冲区布局（MyProto 层视角，不含以太网头）：
 *   [0..MYPROTO_HDR_SIZE-1]        MyProto 协议头
 *   [MYPROTO_HDR_SIZE..]          负载数据
 *   [如果 crc_enabled]            CRC32（4 字节小端序）
 *
 * 所有多字节字段以网络字节序写入。
 * 成功返回实际帧长度（含 CRC），失败返回 -1。
 */
ssize_t myproto_build_frame(uint8_t *buf, size_t buf_size,
                            const myproto_hdr_t *hdr,
                            const uint8_t *payload, size_t payload_len,
                            int crc_enabled)
{
    size_t total_len;
    uint8_t *hdr_pos;

    if (!buf) {
        LOG_ERROR("myproto_build_frame: null buffer");
        return -1;
    }
    if (!hdr) {
        LOG_ERROR("myproto_build_frame: null header pointer");
        return -1;
    }
    if (payload_len > 0 && !payload) {
        LOG_ERROR("myproto_build_frame: null payload with non-zero length %zu",
                  payload_len);
        return -1;
    }

    if (payload_len > buf_size - MYPROTO_HDR_SIZE) {
        LOG_ERROR("myproto_build_frame: buffer too small "
                  "(need %zu, have %zu)", MYPROTO_HDR_SIZE + payload_len, buf_size);
        return -1;
    }

    total_len = MYPROTO_HDR_SIZE + payload_len;

    /* 写入 MyProto 协议头（网络字节序） */
    {
        uint16_t net_magic     = htons(hdr->magic);
        uint16_t net_channel   = htons(hdr->channel_id);
        uint16_t net_data_len  = htons(hdr->data_len);

        hdr_pos = buf;
        memcpy(hdr_pos,     &net_magic,    2);
        hdr_pos[2] = hdr->version;
        hdr_pos[3] = hdr->flags;
        memcpy(hdr_pos + 4, &net_channel,  2);
        memcpy(hdr_pos + 6, &net_data_len, 2);
    }

    /* 复制负载数据（若 payload 已位于 buf+MYPROTO_HDR_SIZE 则跳过，
     * 避免自重叠 memcpy — 加密路径下数据已由 crypto 模块原地写入） */
    if (payload_len > 0 && payload != buf + MYPROTO_HDR_SIZE) {
        memcpy(buf + MYPROTO_HDR_SIZE, payload, payload_len);
    }

    /* 如果启用 CRC，附加 CRC32 到帧末尾 */
    if (crc_enabled) {
        ssize_t ret = myproto_append_crc(buf, total_len, buf_size);
        if (ret < 0) {
            return -1;
        }
        return ret;
    }

    return (ssize_t)total_len;
}

/*
 * myproto_parse_frame - 解析 MyProto 帧。
 *
 * 从原始数据中读取协议头、验证合法性，并输出负载指针与长度。
 * 输入数据从 MyProto 协议头开始（以太网头已由 af_packet 层剥离）。
 * 成功返回 0，失败返回 -1。
 */
int myproto_parse_frame(const uint8_t *data, size_t data_len,
                        myproto_hdr_t *hdr,
                        const uint8_t **payload, size_t *payload_len)
{
    const uint8_t *hdr_pos;

    if (!data) {
        LOG_ERROR("myproto_parse_frame: null data pointer");
        return -1;
    }
    if (!hdr) {
        LOG_ERROR("myproto_parse_frame: null header output pointer");
        return -1;
    }
    if (!payload) {
        LOG_ERROR("myproto_parse_frame: null payload output pointer");
        return -1;
    }
    if (!payload_len) {
        LOG_ERROR("myproto_parse_frame: null payload_len output pointer");
        return -1;
    }

    if (data_len < MYPROTO_MIN_FRAME_SIZE) {
        LOG_ERROR("myproto_parse_frame: data too short "
                  "(%zu bytes, minimum %u)", data_len, MYPROTO_MIN_FRAME_SIZE);
        return -1;
    }

    /* 从以太网头之后读取 MyProto 协议头（网络字节序） */
    {
        uint16_t net_magic, net_channel, net_data_len;

        hdr_pos = data;
        memcpy(&net_magic,    hdr_pos,     2);
        hdr->version    = hdr_pos[2];
        hdr->flags      = hdr_pos[3];
        memcpy(&net_channel,  hdr_pos + 4, 2);
        memcpy(&net_data_len, hdr_pos + 6, 2);

        hdr->magic      = ntohs(net_magic);
        hdr->channel_id = ntohs(net_channel);
        hdr->data_len   = ntohs(net_data_len);
    }

    /* 验证协议头 */
    if (myproto_validate_hdr(hdr) != 0) {
        return -1;
    }

    /* 检查 data_len 是否在可用数据范围内 */
    {
        size_t available = data_len - MYPROTO_MIN_FRAME_SIZE;
        if (hdr->data_len > available) {
            LOG_ERROR("myproto_parse_frame: declared data_len %u exceeds "
                      "available bytes %zu", hdr->data_len, available);
            return -1;
        }
    }

    /* 设置输出指针 */
    *payload = data + MYPROTO_HDR_SIZE;
    *payload_len = hdr->data_len;

    return 0;
}

/*
 * myproto_build_ctrl_frame - 构造控制帧。
 *
 * 控制帧没有负载数据（data_len=0），仅包含协议头。
 * 控制帧不附加 CRC（crc_enabled 参数仅用于接口一致性，内部恒传 0）。
 */
ssize_t myproto_build_ctrl_frame(uint8_t *buf, size_t buf_size,
                                 uint16_t channel_id, uint8_t flags,
                                 int crc_enabled)
{
    myproto_hdr_t hdr;

    if (!buf) {
        LOG_ERROR("myproto_build_ctrl_frame: null buffer");
        return -1;
    }

    if (buf_size < MYPROTO_MIN_FRAME_SIZE) {
        LOG_ERROR("myproto_build_ctrl_frame: buffer too small "
                  "(need %u, have %zu)", MYPROTO_MIN_FRAME_SIZE, buf_size);
        return -1;
    }

    if (channel_id >= MAX_CHANNELS && channel_id != HEARTBEAT_CH_ID) {
        LOG_ERROR("myproto_build_ctrl_frame: invalid channel_id %u "
                  "(max %u)", channel_id, MAX_CHANNELS);
        return -1;
    }

    (void)crc_enabled; /* 控制帧不使用 CRC，保留参数以供接口统一 */

    /* 验证 flags 中至少包含一个控制标志 */
    if ((flags & MPF_CTRL_MASK) == 0) {
        LOG_ERROR("myproto_build_ctrl_frame: no control flag set in flags=0x%02X",
                  flags);
        return -1;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.flags      = flags;
    hdr.channel_id = channel_id;
    hdr.data_len   = 0;

    return myproto_build_frame(buf, buf_size, &hdr, NULL, 0, 0);
}

/*
 * myproto_build_data_frame - 构造数据帧（可能加密）。
 *
 * 非加密路径：myproto_hdr | payload
 * 加密路径：  myproto_hdr | IV(16) | ciphertext | HMAC-tag(32)
 *
 * 加密由 crypto 模块 (SM4-CBC + SM3-HMAC via Nettle) 处理。
 */
ssize_t myproto_build_data_frame(uint8_t *buf, size_t buf_size,
                                 uint16_t channel_id, uint8_t flags,
                                 const uint8_t *data, size_t data_len,
                                 int crc_enabled)
{
    myproto_hdr_t hdr;
    size_t wire_payload_len;
    size_t total_len;

    if (!buf) {
        LOG_ERROR("myproto_build_data_frame: null buffer");
        return -1;
    }
    if (data_len > 0 && !data) {
        LOG_ERROR("myproto_build_data_frame: null data with non-zero length %zu",
                  data_len);
        return -1;
    }

    if (channel_id >= MAX_CHANNELS && channel_id != HEARTBEAT_CH_ID) {
        LOG_ERROR("myproto_build_data_frame: invalid channel_id %u "
                  "(max %u)", channel_id, MAX_CHANNELS);
        return -1;
    }

    /* 加密路径：先将加密输出写入 buf+MYPROTO_HDR_SIZE，再构建帧头 */
    if (flags & MPF_CRYPTO) {
        /* Pre-check buffer capacity: crypto may add up to CRYPTO_OVERHEAD bytes */
        int max_crypto_len;
        /* KCP data_len is bounded by KCP MTU (~1400), safe to cast to int */
        max_crypto_len = (int)data_len + CRYPTO_OVERHEAD;
        if (MYPROTO_HDR_SIZE + (size_t)max_crypto_len > buf_size) {
            LOG_ERROR("myproto_build_data_frame: buffer too small for crypto "
                      "(need at least %zu, have %zu)",
                      MYPROTO_HDR_SIZE + (size_t)max_crypto_len, buf_size);
            return -1;
        }
        /* Now safe to write */
        int crypto_len = crypto_encrypt_frame(data, (int)data_len,
                                               buf + MYPROTO_HDR_SIZE,
                                               (int)(buf_size - MYPROTO_HDR_SIZE));
        if (crypto_len < 0) {
            LOG_ERROR("crypto_encrypt_frame failed");
            return -1;
        }
        wire_payload_len = (size_t)crypto_len;
    } else {
        wire_payload_len = data_len;
    }

    total_len = MYPROTO_HDR_SIZE + wire_payload_len;
    if (total_len > buf_size) {
        LOG_ERROR("myproto_build_data_frame: buffer too small "
                  "(need %zu, have %zu)", total_len, buf_size);
        return -1;
    }

    if (wire_payload_len > ETH_MAX_PAYLOAD) {
        LOG_ERROR("myproto_build_data_frame: wire payload %zu exceeds "
                  "ETH_MAX_PAYLOAD %u", wire_payload_len, ETH_MAX_PAYLOAD);
        return -1;
    }

    /* 构建协议头 */
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.flags      = flags;
    hdr.channel_id = channel_id;
    hdr.data_len   = (uint16_t)wire_payload_len;

    /*
     * 加密路径下，加密数据已由 crypto_encrypt_frame 写入 buf+MYPROTO_HDR_SIZE；
     * 非加密路径下，原始数据还在 data 中。
     * 使用 myproto_build_frame 统一写入头 + 负载。
     */
    if (flags & MPF_CRYPTO) {
        return myproto_build_frame(buf, buf_size, &hdr,
                                    buf + MYPROTO_HDR_SIZE, wire_payload_len,
                                    crc_enabled);
    } else {
        return myproto_build_frame(buf, buf_size, &hdr, data, data_len,
                                    crc_enabled);
    }
}

/*
 * myproto_process_data_frame - 处理接收到的数据帧。
 *
 * 如果帧启用了加密（MPF_CRYPTO），则调用 crypto 模块进行
 * SM4-CBC 解密 + SM3-HMAC 验证。解密后的明文替换 payload。
 *
 * 加密由 crypto 模块 (SM4-CBC + SM3-HMAC via Nettle) 处理。
 */
int myproto_process_data_frame(myproto_hdr_t *hdr,
                               uint8_t *payload, size_t *payload_len)
{
    size_t decrypted_len;
    uint8_t decrypted_buf[MAX_FRAME_SIZE];
    int ret;

    if (!hdr) {
        LOG_ERROR("myproto_process_data_frame: null header pointer");
        return -1;
    }
    if (!payload) {
        LOG_ERROR("myproto_process_data_frame: null payload pointer");
        return -1;
    }
    if (!payload_len) {
        LOG_ERROR("myproto_process_data_frame: null payload_len pointer");
        return -1;
    }

    /* 非加密帧：无需处理，直接返回成功 */
    if (!(hdr->flags & MPF_CRYPTO)) {
        return 0;
    }

    /* 加密帧处理：调用 crypto 模块解密 */
    ret = crypto_decrypt_frame(payload, (int)*payload_len,
                                decrypted_buf, sizeof(decrypted_buf));
    if (ret < 0) {
        LOG_ERROR("crypto_decrypt_frame failed (HMAC/auth error)");
        return -1;
    }
    decrypted_len = (size_t)ret;

    /* 将解密后的明文移回 payload 区域 */
    memmove(payload, decrypted_buf, decrypted_len);
    *payload_len = decrypted_len;

    return 0;
}

/*
 * myproto_append_crc - 附加 CRC32 到帧末尾。
 *
 * 计算 buf[0..frame_len-1] 的 CRC32，以 4 字节小端序附加到 frame_len 处。
 * 返回附加 CRC 后的帧总长度，失败返回 -1。
 */
ssize_t myproto_append_crc(uint8_t *buf, size_t frame_len, size_t buf_size)
{
    uint32_t crc;

    if (!buf) {
        LOG_ERROR("myproto_append_crc: null buffer");
        return -1;
    }

    if (frame_len > buf_size - CRC32_SIZE) {
        LOG_ERROR("myproto_append_crc: buffer overflow "
                  "(frame_len=%zu + CRC=%u > buf_size=%zu)",
                  frame_len, CRC32_SIZE, buf_size);
        return -1;
    }

    if (frame_len == 0) {
        LOG_ERROR("myproto_append_crc: zero frame length");
        return -1;
    }

    crc = myproto_crc32(buf, frame_len);

    /* 以小端序写入 CRC32 */
    buf[frame_len]     = (uint8_t)(crc & 0xFF);
    buf[frame_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
    buf[frame_len + 2] = (uint8_t)((crc >> 16) & 0xFF);
    buf[frame_len + 3] = (uint8_t)((crc >> 24) & 0xFF);

    return (ssize_t)(frame_len + CRC32_SIZE);
}

/*
 * myproto_verify_crc - 验证帧末尾的 CRC32。
 *
 * 计算 buf[0..frame_len-CRC32_SIZE-1] 的 CRC32，
 * 与 buf[frame_len-CRC32_SIZE..frame_len-1] 中存储的 CRC 比较。
 * 校验通过返回数据长度（不含 CRC），失败返回 -1。
 */
ssize_t myproto_verify_crc(const uint8_t *buf, size_t frame_len)
{
    uint32_t computed_crc;
    uint32_t stored_crc;
    size_t data_len;

    if (!buf) {
        LOG_ERROR("myproto_verify_crc: null buffer");
        return -1;
    }

    if (frame_len < CRC32_SIZE) {
        LOG_ERROR("myproto_verify_crc: frame too short for CRC "
                  "(%zu bytes, minimum %u)", frame_len, CRC32_SIZE);
        return -1;
    }

    data_len = frame_len - CRC32_SIZE;

    /* 计算数据部分的 CRC32 */
    computed_crc = myproto_crc32(buf, data_len);

    /* 读取存储的 CRC32（小端序） */
    stored_crc = (uint32_t)buf[data_len]
               | ((uint32_t)buf[data_len + 1] << 8)
               | ((uint32_t)buf[data_len + 2] << 16)
               | ((uint32_t)buf[data_len + 3] << 24);

    if (computed_crc != stored_crc) {
        LOG_ERROR("myproto_verify_crc: CRC mismatch "
                  "(computed=0x%08X, stored=0x%08X)",
                  computed_crc, stored_crc);
        return -1;
    }

    return (ssize_t)data_len;
}
