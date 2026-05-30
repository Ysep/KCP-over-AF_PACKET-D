/**
 * @file    crypto.h
 * @brief   国密加密模块 — SM4-CBC 对称加密 + SM3-HMAC 消息认证
 *
 * 本模块提供帧级别的加密/解密和完整性保护。
 * 加密算法组合: SM4-CBC (128-bit 分组密码, 国密 GB/T 32907)
 *               + SM3-HMAC (256-bit 哈希消息认证码, 国密 GB/T 32905)
 *               + PKCS7 填充 (对齐到 16 字节块)
 *               + 随机 IV (/dev/urandom, 每帧独立)
 * 底层依赖: GNU Nettle 加密库 (libnettle)。
 *
 * ═══════════════ 加密帧格式 ═══════════════
 *
 *   ┌───────┬──────────────────────┬────────────────┐
 *   │  IV   │  SM4-CBC Ciphertext  │  SM3-HMAC      │
 *   │ 16 B  │  (PKCS7 padded, N)   │  32 B          │
 *   └───────┴──────────────────────┴────────────────┘
 *
 * 其中 Ciphertext 长度 N 始终为 16 的倍数 (PKCS7 填充保证)。
 * HMAC 计算域覆盖 [IV | Ciphertext] 全部数据。
 *
 * 解密时首先验证 HMAC (认证标签)，失败则拒绝帧；
 * HMAC 通过后才进行 SM4-CBC 解密和 PKCS7 去填充。
 * HMAC-then-encrypt 顺序的好处: 可以最早发现篡改，避免解密无效数据。
 *
 * ═══════════════ 安全设计要点 ═══════════════
 *
 *   1. IV 随机性: 每帧从 /dev/urandom 读取 16 字节独立 IV，
 *      杜绝固定 IV 或计数器 IV 的重放攻击。
 *   2. 密钥分离: SM4 加密/解密使用独立的内部轮密钥上下文
 *      (g_enc_ctx / g_dec_ctx)，避免密钥混淆。
 *   3. HMAC 密钥派生: HMAC 密钥从 SM4 密钥派生 (HMAC-SM3("KCP-HMAC", key))，
 *      确保即使 SM4 密钥暴露，攻击者也需要同时破解 HMAC。
 *   4. 时序安全: HMAC 校验使用常量时间比较，减少侧信道泄漏。
 *   5. 临时密钥擦除: crypto_init() 结束后 memset 清零 key_bin 栈内存。
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include "types.h"

/* ═══════════════════════════════════════════
 * 生命周期管理
 * ═══════════════════════════════════════════ */

/** @brief 初始化加密模块
 *
 * 从配置中解析 hex 密钥字符串 (32 字符 → 16 字节 binary)，
 * 初始化 SM4 加密/解密上下文，派生 SM3-HMAC 子密钥。
 * 加密未启用时 (cfg->enabled==false) 直接返回 0，不进初始化。
 *
 * @param cfg  加密配置 (enabled + sm4_key hex 字符串)
 * @return     0=成功 (或加密未启用), -1=初始化失败 (保留)
 */
int  crypto_init(const encryption_config_t *cfg);

/** @brief 清理加密模块
 *
 * 清零 SM4 加密/解密上下文和 HMAC 密钥 (memset 擦除敏感数据)，
 * 将 crypto_enabled 标志重置为 0。
 */
void crypto_cleanup(void);

/** @brief 查询加密是否已启用
 *
 * @return  1=已启用, 0=未启用 (明文模式)
 */
int  crypto_is_enabled(void);

/* ═══════════════════════════════════════════
 * 帧级加解密 API
 * ═══════════════════════════════════════════ */

/** @brief 帧级加密: 明文 → [IV | SM4-CBC密文 | SM3-HMAC]
 *
 * 加密流程:
 *   1. 从 /dev/urandom 读取 16 字节随机 IV
 *   2. PKCS7 填充明文到 16 字节对齐
 *   3. SM4-CBC 加密 (使用 g_enc_ctx)
 *   4. SM3-HMAC 计算 (覆盖 [IV | 密文])
 *   5. 组装输出帧: [IV(16) | 密文(N) | HMAC(32)]
 *
 * 加密未启用时: 明文直通 (memcpy out ← in)，但仍检查 out_cap。
 *
 * @param in       明文数据指针
 * @param in_len   明文长度 (0~KCP_MTU_CONSERVATIVE)
 * @param out      [out] 加密后缓冲区 (至少总长字节)
 * @param out_cap  out 缓冲区容量 (bytes)
 * @return         >0=加密后总长度, -1=buffer 不足或 IV 读取失败
 */
int  crypto_encrypt_frame(const uint8_t *in, int in_len,
                          uint8_t *out, int out_cap);

/** @brief 帧级解密: [IV | SM4-CBC密文 | SM3-HMAC] → 明文
 *
 * 解密流程:
 *   1. 边界检查: in_len ≥ 48 (IV+HMAC最小值), ct_len > 0 且 16 对齐
 *   2. 提取 IV (前 16 字节) 并计算期望 HMAC
 *   3. 常量时间 HMAC 校验 → 失败返回 -1
 *   4. SM4-CBC 解密 (使用 g_dec_ctx)
 *   5. PKCS7 去填充 + 格式校验 → 失败返回 -1
 *   6. ct_len > out_cap 检查 (修复 R7: 防止解密缓冲区溢出)
 *   7. 返回解密后明文长度
 *
 * @param in       加密帧数据指针
 * @param in_len   加密帧总长度
 * @param out      [out] 解密后明文缓冲区
 * @param out_cap  out 缓冲区容量
 * @return         >0=明文字节数, -1=HMAC/格式/缓冲区错误
 */
int  crypto_decrypt_frame(const uint8_t *in, int in_len,
                          uint8_t *out, int out_cap);

#endif /* CRYPTO_H */
