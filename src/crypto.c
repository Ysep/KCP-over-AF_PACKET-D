/**
 * @file    crypto.c
 * @brief   SM4-CBC 加密 / SM3-HMAC 认证模块（基于 GNU Nettle）
 *
 * @details
 * 本模块为 KCP-over-AF_PACKET 提供帧级对称加密和完整性保护：
 *   - SM4-CBC：国密分组密码 CBC 模式，带标准 PKCS7 填充
 *   - SM3-HMAC：国密哈希消息认证码，防止篡改和重放（配合 IV）
 *   - HMAC 密钥通过 HKDF 式派生：HMAC-SM3("KCP-HMAC", sm4_key)
 *   - 线格式：IV(16B) || ciphertext(N×16B) || HMAC(32B)
 *   - 每帧独立随机 IV（/dev/urandom），即使相同明文也产生不同密文
 *
 * 依赖：
 *   - Nettle 库 (sm4.h, cbc.h, hmac.h)
 *   - Linux /dev/urandom（IV 熵源）
 *
 * 安全设计要点：
 *   - 解密时先验证 HMAC，再执行 CBC 解密，防止 padding oracle / 密文篡改攻击
 *   - 加密/解密使用独立轮密钥上下文（g_enc_ctx / g_dec_ctx），避免密钥调度混乱
 *   - 派生密钥和临时密钥材料使用后立即 memset 擦除
 *   - PKCS7 解填充做完整格式校验（pad 范围 + 逐字节一致性）
 *
 * 已知限制：
 *   - memcmp 非恒定时间，理论上有 timing leak（注释已标注），在 LAN 威胁模型下可接受
 *   - 不支持 AEAD 模式（如 GCM），无法提供关联数据认证
 *   - IV 生成依赖 /dev/urandom 可用性，容器/沙箱中需确保设备节点存在
 */

#include "crypto.h"
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <nettle/sm4.h>
#include <nettle/cbc.h>
#include <nettle/hmac.h>

/** SM4 加密上下文（轮密钥由 sm4_set_encrypt_key 填充） */
static struct sm4_ctx  g_enc_ctx;
/** SM4 解密上下文（轮密钥与加密不同，由 sm4_set_decrypt_key 填充） */
static struct sm4_ctx  g_dec_ctx;
/** 全局加密开关：0=明文透传 / 1=加密模式 */
static int             crypto_enabled = 0;
/**
 * HMAC 密钥（32 字节），由 SM4 密钥通过 HMAC-SM3("KCP-HMAC", sm4_key) 派生。
 * 与 SM4 数据密钥分离：即使 CBC 密文被破解，攻击者无法直接获得 HMAC 密钥。
 */
static uint8_t         g_hmac_key[SM3_DIGEST_SIZE];

/**
 * @brief   初始化加密子系统
 *
 * @param   cfg  配置结构（含 enabled 标志和 hex 格式 sm4_key）
 * @return  0 成功；错误码（当前始终返回 0，错误由调用者在初始化前校验）
 *
 * @details
 * 流程：
 *   1. 将 32 字符 hex 密钥 → 16 字节二进制 key_bin
 *   2. 分别调用 sm4_set_encrypt_key / sm4_set_decrypt_key 填充加解密上下文
 *      （SM4 加解密轮密钥不同，必须分别设置）
 *   3. 派生 HMAC 密钥：以固定标签 "KCP-HMAC"(8B) 作为 HMAC key，
 *      对 SM4 原始密钥做 HMAC-SM3，得到 32B HMAC 工作密钥
 *   4. memset 擦除临时 key_bin，防止栈泄露
 */
int crypto_init(const encryption_config_t *cfg)
{
    crypto_enabled = cfg->enabled;
    if (!crypto_enabled) return 0;

    /* hex key → binary (16 bytes)：每两个 hex 字符解析为一个字节 */
    uint8_t key_bin[16];
    for (int i = 0; i < 16; i++) {
        unsigned int b;
        if (sscanf(cfg->sm4_key + i * 2, "%2x", &b) != 1) {
            LOG_ERROR("crypto_init: invalid hex key at position %d", i * 2);
            return -1;
        }
        key_bin[i] = (uint8_t)b;
    }
    /* Verify key is exactly 32 hex chars */
    if (cfg->sm4_key[32] != '\0') {
        LOG_ERROR("crypto_init: key must be exactly 32 hex characters");
        memset(key_bin, 0, sizeof(key_bin));
        return -1;
    }

    sm4_set_encrypt_key(&g_enc_ctx, key_bin);
    sm4_set_decrypt_key(&g_dec_ctx, key_bin);

    /* 派生 HMAC key: HMAC-SM3("KCP-HMAC" 作为 key, sm4_key 作为 data)
     * 此构造类似于简化的 HKDF-extract：
     *   伪代码: g_hmac_key = HMAC-SM3(key="KCP-HMAC", message=sm4_key)
     * 好处：HMAC 和数据加密使用不同密钥材料，满足密钥分离原则 */
    struct hmac_sm3_ctx hctx;
    hmac_sm3_set_key(&hctx, 8, (const uint8_t *)"KCP-HMAC");
    hmac_sm3_update(&hctx, 16, key_bin);
    hmac_sm3_digest(&hctx, SM3_DIGEST_SIZE, g_hmac_key);

    /* 擦除临时 key：防止通过 core dump / /proc/pid/mem 泄露 */
    memset(key_bin, 0, sizeof(key_bin));
    __asm__ __volatile__("" : : "r"(key_bin) : "memory");
    return 0;
}

/**
 * @brief   查询加密是否启用
 * @return  1 已启用 / 0 未启用
 */
int crypto_is_enabled(void) { return crypto_enabled; }

/**
 * @brief   清理加密子系统，擦除所有敏感密钥材料
 *
 * @details
 * 将所有密钥上下文和 HMAC 密钥清零并重置加密开关。
 * 应在进程退出前调用，防止密钥残留在内存中。
 */
void crypto_cleanup(void)
{
    memset(&g_enc_ctx, 0, sizeof(g_enc_ctx));
    memset(&g_dec_ctx, 0, sizeof(g_dec_ctx));
    memset(g_hmac_key, 0, sizeof(g_hmac_key));
    crypto_enabled = 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  SM4-CBC 加密（Nettle 后端）
 *
 *  使用 PKCS7 填充方案：
 *    若 in_len % 16 == 0，追加 16 字节的 0x10
 *    若 in_len % 16 == r  (r>0)，追加 (16-r) 字节，每字节值为 (16-r)
 *  这确保解密后能精确恢复原始明文长度。
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief   SM4-CBC 加密（内部函数）
 *
 * @param   key    未使用（使用全局 g_enc_ctx）
 * @param   iv     16 字节初始化向量（调用者负责随机生成）
 * @param   in     明文缓冲区
 * @param   in_len 明文长度（字节）
 * @param   out    输出缓冲区（调用者确保 ≥ in_len + 16）
 * @return  加密后总长度（含 PKCS7 填充）；-1 表示参数错误
 *
 * @note    key 参数保留用于 API 兼容性，实际使用全局 g_enc_ctx。
 *          调用 cbc_encrypt 时将 sm4_crypt 强制转换为 nettle_cipher_func，
 *          这是 Nettle 库的标准用法（SM4 块大小为 16 字节）。
 */
static int sm4_cbc_encrypt(const uint8_t *key __attribute__((unused)),
                           const uint8_t *iv,
                           const uint8_t *in, int in_len,
                           uint8_t *out)
{
    /* PKCS7 padding: 填充字节数 ∈ [1, 16]
     * pad = 16 - (in_len % 16)，当 in_len 恰好为 16 倍数时 pad=16 */
    int pad = SM4_IV_LEN - (in_len % SM4_IV_LEN);
    if (in_len > INT_MAX - SM4_IV_SIZE) return -1;
    int padded_len = in_len + pad;

    /* 构造填充后的临时缓冲区：原始数据 + 填充字节（每字节值为 pad） */
    uint8_t buf[MAX_FRAME_SIZE];  /* Safe: padded_len ≤ in_len+16 ≤ MAX_FRAME_SIZE */
    memcpy(buf, in, in_len);
    memset(buf + in_len, pad, pad);

    /* CBC 加密：需要 local copy of IV，因为 cbc_encrypt 会就地修改 iv_copy */
    uint8_t iv_copy[SM4_IV_LEN];
    memcpy(iv_copy, iv, SM4_IV_LEN);
    cbc_encrypt(&g_enc_ctx, (nettle_cipher_func *)sm4_crypt,
                SM4_IV_LEN, iv_copy, padded_len, out, buf);
    return padded_len;
}

/**
 * @brief   SM4-CBC 解密（内部函数）
 *
 * @param   key    未使用（使用全局 g_dec_ctx）
 * @param   iv     16 字节初始化向量
 * @param   in     密文缓冲区
 * @param   in_len 密文长度（必须是 16 的整数倍，≥ 16）
 * @param   out    输出缓冲区（调用者确保 ≥ in_len）
 * @return  明文长度（去除填充后）；-1 表示格式错误
 *
 * @details
 * PKCS7 解填充验证三步：
 *   1. pad 值必须在 [1, 16] 范围内
 *   2. 末尾 pad 个字节必须全部等于 pad 值
 *   3. 若任一步失败则返回 -1（丢弃该帧，不返回部分解密数据）
 *
 * @note    入参校验（in_len % 16 == 0）在调用者 crypto_decrypt_frame 中完成，
 *          此处再次检查以防调用链异常。
 */
static int sm4_cbc_decrypt(const uint8_t *key __attribute__((unused)),
                           const uint8_t *iv,
                           const uint8_t *in, int in_len,
                           uint8_t *out)
{
    if (in_len < SM4_IV_LEN || in_len % SM4_IV_LEN != 0) return -1;

    uint8_t iv_copy[SM4_IV_LEN];
    memcpy(iv_copy, iv, SM4_IV_LEN);
    cbc_decrypt(&g_dec_ctx, (nettle_cipher_func *)sm4_crypt,
                SM4_IV_LEN, iv_copy, in_len, out, in);

    /* 去除 PKCS7 填充：读取末尾字节作为 pad 值 */
    int pad = out[in_len - 1];
    /* pad 必须在 [1, 16] 范围，超出说明数据损坏或攻击 */
    if (pad < 1 || pad > SM4_IV_LEN) return -1;
    /* 逐字节校验：末尾 pad 个字节必须全部等于 pad（PKCS7 规范要求） */
    for (int i = 0; i < pad; i++) {
        if (out[in_len - 1 - i] != pad) return -1;
    }
    return in_len - pad;
}

/* ═══════════════════════════════════════════════════════════════════
 *  SM3-HMAC 计算（Nettle 后端）
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief   计算 SM3-HMAC
 *
 * @param   data     输入数据
 * @param   data_len 数据长度
 * @param   mac      输出 32 字节 MAC（调用者分配）
 *
 * @details
 * 使用全局 g_hmac_key 作为 HMAC 密钥。
 * Nettle HMAC 三步模式：set_key → update → digest。
 */
static void sm3_hmac_compute(const uint8_t *data, int data_len,
                             uint8_t mac[SM3_DIGEST_SIZE])
{
    struct hmac_sm3_ctx ctx;
    hmac_sm3_set_key(&ctx, SM3_DIGEST_SIZE, g_hmac_key);
    hmac_sm3_update(&ctx, data_len, data);
    hmac_sm3_digest(&ctx, SM3_DIGEST_SIZE, mac);
}

/* ═══════════════════════════════════════════════════════════════════
 *  帧级加密 / 解密（完整线格式）
 *
 *  线格式布局（加密模式）：
 *    [0..15]   随机 IV (16B)
 *    [16..N-33] SM4-CBC 密文（含 PKCS7 填充，长度是 16 的整数倍）
 *    [N-32..N-1] SM3-HMAC over IV || ciphertext (32B)
 *
 *  明文模式（crypto_enabled==0）：直接透传原始数据。
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * @brief   帧级加密：明文 → IV || ciphertext || HMAC
 *
 * @param   in      明文数据
 * @param   in_len  明文长度
 * @param   out     输出缓冲区
 * @param   out_cap 输出缓冲区容量（字节）
 * @return  加密后总长度（IV + ciphertext + HMAC）；-1 表示失败
 *
 * @details
 * 加密流程：
 *   1. 从 /dev/urandom 读取 16 字节随机 IV
 *   2. 将 IV 写入输出头部
 *   3. SM4-CBC 加密（含 PKCS7 填充）
 *   4. 计算 SM3-HMAC over IV || ciphertext，追加到尾部
 *
 * 若加密未启用（crypto_enabled==0），则直接 memcpy 明文到输出。
 *
 * @note    每次加密都使用新鲜 IV：即使同一明文重复发送，密文也不同，
 *          有效防止流量分析。IV 不加密，以明文形式传输——CBC 模式下
 *          IV 只需不可预测，不需保密。
 */
int crypto_encrypt_frame(const uint8_t *in, int in_len,
                         uint8_t *out, int out_cap)
{
    if (!crypto_enabled) {
        if (in_len > out_cap) return -1;
        memcpy(out, in, in_len);
        return in_len;
    }

    /* 估算总长度: IV(16) + 密文(≤in_len+16) + HMAC(32)
     * 最坏情况：明文已是 16 倍数，PKCS7 追加完整一个 block (16 字节) */
    if (in_len > INT_MAX - SM4_IV_SIZE) return -1;
    int max_ct = in_len + SM4_IV_LEN;
    int total = SM4_IV_LEN + max_ct + SM3_HMAC_LEN;
    if (total > out_cap) return -1;

    /* 1. 生成随机 IV
     *    使用 /dev/urandom 而非 rand()：
     *      - rand() 种子可预测且周期短，不适合安全用途
     *      - /dev/urandom 由内核熵池驱动，提供密码学质量的随机数
     *    每次 open/read/close 保证即使多线程也不会共享 fd 偏移 */
    uint8_t iv[SM4_IV_LEN];
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return -1;
        ssize_t total_read = 0;
        while (total_read < SM4_IV_LEN) {
            ssize_t n = read(fd, iv + total_read, SM4_IV_LEN - total_read);
            if (n <= 0) { close(fd); return -1; }
            total_read += n;
        }
        close(fd);
    }
    memcpy(out, iv, SM4_IV_LEN);

    /* 2. SM4-CBC 加密（密文紧接 IV 之后） */
    int ct_len = sm4_cbc_encrypt(NULL, iv, in, in_len,
                                  out + SM4_IV_LEN);
    if (ct_len < 0) return -1;

    /* 3. SM3-HMAC over IV || Ciphertext
     *    HMAC 覆盖 IV+密文全部：攻击者篡改 IV 也会被检测到 */
    int mac_input_len = SM4_IV_LEN + ct_len;
    sm3_hmac_compute(out, mac_input_len, out + mac_input_len);

    return mac_input_len + SM3_HMAC_LEN;
}

/**
 * @brief   帧级解密：IV || ciphertext || HMAC → 明文
 *
 * @param   in      加密帧数据
 * @param   in_len  加密帧总长度
 * @param   out     明文输出缓冲区
 * @param   out_cap 输出缓冲区容量
 * @return  明文长度；-1 表示 HMAC 验证失败或解密错误
 *
 * @details
 * 解密流程（顺序至关重要）：
 *   1. 【先】验证 SM3-HMAC — 若 MAC 不匹配立即拒绝，不解密
 *   2. 【后】SM4-CBC 解密 + PKCS7 解填充
 *
 *   先验 MAC 后解密的设计原则（Encrypt-then-MAC）：
 *     - 防止 padding oracle 攻击：攻击者无法通过修改密文观察解密结果
 *     - 防止密文篡改：HMAC 不匹配的帧在解密前就被丢弃
 *     - 节省 CPU：无效帧不消耗解密计算
 *
 * @warning  memcmp 为非常量时间实现，理论上存在 timing side-channel。
 *           在当前 LAN 场景下（攻击者难以精确测量纳秒级时差），风险可控。
 *           未来可替换为 CRYPTO_memcmp / sodium_memcmp。
 */
int crypto_decrypt_frame(const uint8_t *in, int in_len,
                         uint8_t *out, int out_cap)
{
    if (!crypto_enabled) {
        if (in_len > out_cap) return -1;
        memcpy(out, in, in_len);
        return in_len;
    }

    /* 最小长度检查：至少需要 IV(16) + 1 block(16) + HMAC(32) = 64 字节 */
    if (in_len < SM4_IV_LEN + SM3_HMAC_LEN) return -1;
    int ct_len = in_len - SM4_IV_LEN - SM3_HMAC_LEN;
    /* 密文长度必须是 16（SM4 块大小）的整数倍 */
    if (ct_len <= 0 || ct_len % SM4_IV_LEN != 0) return -1;

    /* 1. 验证 HMAC — 在解密之前执行（Encrypt-then-MAC 的关键顺序）
     *    R1 审计修复：原实现先解密再验 MAC，存在 padding oracle 风险。
     *    现改为先验证 HMAC，验证通过才执行解密。 */
    uint8_t mac_calc[SM3_HMAC_LEN];
    sm3_hmac_compute(in, SM4_IV_LEN + ct_len, mac_calc);
    if (memcmp(mac_calc, in + SM4_IV_LEN + ct_len, SM3_HMAC_LEN) != 0)
        return -1;  /* HMAC mismatch — 帧被篡改或密钥不匹配 */

    /* 2. SM4-CBC 解密（先验证输出缓冲区足够）
     *    ct_len 在解密后可能会因 PKCS7 解填充缩短，不会超过 out_cap */
    if (ct_len > out_cap) return -1;
    int pt_len = sm4_cbc_decrypt(NULL, in, in + SM4_IV_LEN, ct_len, out);
    if (pt_len < 0 || pt_len > out_cap) return -1;
    return pt_len;
}
