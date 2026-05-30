# 安全文档 — KCP-over-AF_PACKET

本文档描述 KCP-over-AF_PACKET 的安全架构，包括加密方案、密钥管理、威胁模型、DoS 防护机制、审计历史和已知限制。

---

## 目录

1. [加密方案](#1-加密方案)
2. [密钥管理最佳实践](#2-密钥管理最佳实践)
3. [威胁模型](#3-威胁模型)
4. [DoS 防护机制](#4-dos-防护机制)
5. [审计历史摘要](#5-审计历史摘要)
6. [已知限制](#6-已知限制)
7. [安全配置清单](#7-安全配置清单)

---

## 1. 加密方案

### 1.1 算法组合

KCP-over-AF_PACKET 使用**国密算法组合**提供帧级加密和完整性保护：

| 组件 | 算法 | 标准编号 | 参数 |
|------|------|---------|------|
| 对称加密 | SM4-CBC | GB/T 32907-2016 | 128-bit 密钥，128-bit 分组，CBC 模式 |
| 消息认证 | SM3-HMAC | GB/T 32905-2016 | 256-bit 输出，用于完整性校验 |
| 填充方案 | PKCS#7 | RFC 2315 | 对齐到 16 字节块 |
| 初始化向量 | /dev/urandom | Linux 内核 CSPRNG | 每帧独立 16 字节随机 IV |
| 底层库 | GNU Nettle | libnettle | SM4、CBC、HMAC 实现 |

### 1.2 加密帧线格式

```
┌───────┬──────────────────────────┬────────────────┐
│  IV   │  SM4-CBC Ciphertext      │  SM3-HMAC      │
│ 16 B  │  (PKCS7 padded, N×16 B)  │  32 B          │
└───────┴──────────────────────────┴────────────────┘
  │                                  │
  └────── HMAC 计算域 ──────────────┘
  (HMAC 覆盖 [IV | Ciphertext] 全部数据)
```

加密总开销：`CRYPTO_OVERHEAD = 16 + 32 = 48` 字节

### 1.3 加密流程

```
发送方：                             接收方：
                                     │
plaintext                            │
  │                                  │
  ├─ 1. /dev/urandom → IV(16B)       │
  ├─ 2. PKCS7 填充明文               │
  ├─ 3. SM4-CBC 加密 (g_enc_ctx)     │
  ├─ 4. SM3-HMAC(IV || 密文)         │
  └─ 5. 组装：[IV|密文|HMAC]  ───►   │
                                     │
                                     ├─ 1. 提取 IV(前16B)
                                     ├─ 2. 计算期望 HMAC
                                     ├─ 3. 比较 HMAC ─── 不一致 → 丢弃帧
                                     ├─ 4. SM4-CBC 解密 (g_dec_ctx)
                                     ├─ 5. PKCS7 去填充+校验 ─ 失败 → 丢弃帧
                                     └─ 6. 返回明文
```

### 1.4 密钥派生

HMAC 密钥不直接使用 SM4 密钥，而是通过简化的 HKDF 派生：

```
g_hmac_key = HMAC-SM3(
    key   = "KCP-HMAC",     // 8 字节固定标签
    message = sm4_key       // 16 字节 SM4 密钥
)
```

**密钥分离原则**：即使攻击者破解 SM4-CBC 密文获得 SM4 密钥，也无法直接获得 HMAC 密钥进行消息伪造。

### 1.5 安全设计要点

1. **Encrypt-then-MAC 顺序**：先加密，后计算 HMAC。解密时先验证 HMAC，验证失败直接丢弃帧，不执行解密操作。这防止了：
   - 密文篡改攻击（篡改密文 → HMAC 不匹配 → 拒绝）
   - Padding Oracle 攻击（攻击者无法通过解密结果推断填充信息）

2. **每帧独立随机 IV**：从 `/dev/urandom` 读取 16 字节独立 IV，确保：
   - 相同明文在不同帧产生不同密文
   - 防止重放攻击（攻击者重放旧帧 → IV 不变但上下文已不同 → 上层拒绝）
   - 防止 CBC 模式下固定 IV 的已知明文攻击

3. **密钥材料擦除**：
   - `crypto_init()` 结束后 `memset` 清零栈上临时密钥
   - `crypto_cleanup()` 擦除所有全局密钥上下文（`g_enc_ctx`、`g_dec_ctx`、`g_hmac_key`）
   - 使用 `__asm__ __volatile__` 内存屏障防止编译器优化掉擦除操作

4. **独立加解密上下文**：`g_enc_ctx` 和 `g_dec_ctx` 分别调用 `sm4_set_encrypt_key` 和 `sm4_set_decrypt_key` 初始化（SM4 加密和解密轮密钥不同）

---

## 2. 密钥管理最佳实践

### 2.1 密钥生成

```bash
# 使用 OpenSSL 生成随机 128-bit SM4 密钥（32 字符十六进制）
openssl rand -hex 16
# 输出示例: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

### 2.2 密钥存储

**不推荐**：将密钥直接写在 JSON 配置文件中。

**推荐**：使用文件权限控制 + 外部密钥注入。

```bash
# 方案 A: 文件权限控制
sudo chmod 600 /etc/kcp-afpacket/config.json
sudo chown root:root /etc/kcp-afpacket/config.json

# 方案 B: 使用配置文件预处理脚本
cat > gen_config.sh << 'EOF'
#!/bin/bash
SM4_KEY=$(cat /etc/kcp-afpacket/key.hex)  # 单独存储的密钥文件
sed "s/__SM4_KEY__/$SM4_KEY/g" config.template.json > config.json
EOF

chmod 700 gen_config.sh
chmod 600 /etc/kcp-afpacket/key.hex
```

### 2.3 密钥轮换

```
1. 在对端生成新密钥
2. 更新两端配置文件（确保完全一致）
3. 发送 SIGHUP 触发热重载（如果支持）
   或按顺序重启: 先重启对端 → 等待连接恢复 → 重启本端
4. 安全删除旧密钥文件
```

### 2.4 密钥传输

- 使用 SSH/SCP 安全传输密钥文件
- 禁止通过明文协议（HTTP、FTP）传输密钥
- 传输后验证文件完整性（`sha256sum`）

### 2.5 检查清单

- [ ] 密钥长度：32 字符十六进制（128-bit）
- [ ] 密钥来源：`/dev/urandom` 或等效 CSPRNG
- [ ] 配置文件权限：`0600`（仅 root 可读写）
- [ ] 两端密钥完全一致
- [ ] 密钥未硬编码在源码中
- [ ] 密钥未提交到版本控制系统

---

## 3. 威胁模型

### 3.1 LAN 威胁模型（主要场景）

**假设**：攻击者在同一局域网内，可以嗅探、注入或篡改以太网帧。

| 威胁 | 影响（无加密） | 影响（加密+HMAC） | 缓解措施 |
|------|-------------|------------------|---------|
| 被动嗅探 | 🔴 高：明文数据完全可见 | 🟢 无：SM4-CBC 加密，数据不可读 | 启用加密 |
| 帧注入（伪造 SYN） | 🔴 高：可建立恶意通道 | 🟡 中：可注入控制帧（无法伪造数据） | rate limiting + 通道配额 |
| 帧篡改 | 🔴 高：数据可被修改 | 🟢 无：HMAC 验证失败，帧被丢弃 | 启用 HMAC |
| 重放攻击 | 🔴 高：旧数据可被重放 | 🟡 低：IV 随机化 + KCP 序列号检测 | 加密 + KCP SEQ |
| DoS（帧洪泛） | 🔴 高：CPU/带宽耗尽 | 🟡 中：处理量受限 | rate limiting |
| MAC 欺骗 | 🟡 中：可伪装对端 | 🟡 中：可伪装对端 | 固定 MAC 配置 + 交换机端口安全 |

### 3.2 WAN 威胁模型

**假设**：两台主机通过不可信广域网连接（如 Internet），AF_PACKET 帧封装在 VPN/隧道中传输。

| 威胁 | 影响 | 缓解措施 |
|------|------|---------|
| 中间人攻击 | 🔴 高：可截获/修改所有流量 | 加密 + HMAC + 底层 VPN 加密 |
| 流量分析 | 🟡 中：元数据可见（帧大小/频率） | 固定帧大小填充（当前未实现） |
| 侧信道攻击 | 🟢 低：LAN 场景下 timing leak 风险可控 | 当前 `memcmp` 非常量时间（见已知限制） |

### 3.3 边界与假设

- 加密保护的是**数据链路层 MyProto 帧负载**，不包括以太网头部（MAC 地址和 EtherType 可见）
- 控制帧（SYN/ACK/FIN/RST/PING/PONG）**不经过加密**——控制帧标志 `MPF_CRYPTO` 不置位
- 系统的安全性依赖于 SM4 密钥的保密性——密钥泄露意味着所有保护失效
- 假设物理链路或底层隧道是安全的——AF_PACKET 本身不提供传输层安全（如 TLS）

---

## 4. DoS 防护机制

### 4.1 内置防护

| 机制 | 实现 | 效果 |
|------|------|------|
| BPF 内核过滤 | `af_packet_set_bpf()` 设置 BPF 字节码，仅接收匹配 EtherType 的帧 | 防止内核向用户态转发无关帧，减少上下文切换开销 |
| 最大通道数限制 | `max_channels` 配置（默认 256） | 限制并发连接数，防止连接耗尽 |
| 帧处理速率限制 | `MAX_FRAMES_PER_CYCLE = 64` | 每事件循环周期最多处理 64 帧，防止帧洪泛 |
| SYN 重试上限 | `syn_retry_count` 最多重试 3 次 | 防止无效 SYN 重试消耗资源 |
| 心跳超时 | `heartbeat_timeout`（默认 60s） | 自动清理死连接，释放资源 |
| 通道空闲超时 | `CHANNEL_IDLE_TIMEOUT`（300s） | 回收长时间不活动的通道 |
| TIME_WAIT 超时 | `CHANNEL_GRACEFUL_TIMEOUT`（30s） | 确保僵尸通道不会无限占用资源 |
| 缓冲区大小限制 | `CHANNEL_RECV_BUF_SIZE = 8192` | 限制单通道接收缓冲区 |

### 4.2 系统级加固

```bash
# iptables 限制同 EtherType 帧速率（若系统支持 eb 表）
# 通过交换机端口限速
# 使用 VLAN 隔离管理流量

# 限制进程资源
sudo systemctl set-property kcp-afpacket.service \
    MemoryMax=256M \
    CPUQuota=50% \
    TasksMax=128
```

### 4.3 推荐配置

```json
{
    "max_channels": 64,           // 降低最大通道数
    "heartbeat_interval": 30,     // 减少心跳频率
    "heartbeat_timeout": 120,     // 宽松超时防止误判
    "crc_enabled": true,          // 启用 CRC 检测比特错误
    "encryption": {
        "enabled": true,          // 启用加密
        "sm4_key": "<random>"     // 使用强随机密钥
    }
}
```

---

## 5. 审计历史摘要

### 代码审查记录

| 日期 | 类型 | 范围 | 发现 |
|------|------|------|------|
| 初始提交 | 全量审查 | 全部 8 个模块 | 架构合理，无严重安全问题 |
| R1 | 加密模块 | `crypto.c/h` | PKCS7 填充实现正确 |
| R2 | 协议模块 | `myproto.c/h` | 缓冲区边界检查完善 |
| R3 | 通道管理 | `channel.c` | 状态机逻辑完整，RST 处理正确 |
| R7 | 加密模块 | `crypto.c` | 添加 `ct_len > out_cap` 检查，修复潜在的缓冲区溢出 |

### 安全相关修复

| 编号 | 描述 | 严重程度 | 状态 |
|------|------|---------|------|
| R1 | 加密帧长度边界检查 | 中 | ✅ 已修复 |
| R7 | 解密输出缓冲区溢出检查 | 高 | ✅ 已修复 |
| - | `memset` 密钥擦除优化 | 低 | ✅ 已实现 |
| - | PKCS7 填充完整性验证 | 中 | ✅ 已实现 |

---

## 6. 已知限制

### 6.1 加密相关

| 限制 | 影响 | 缓解 |
|------|------|------|
| `memcmp` 非常量时间 | 理论 timing side-channel，可推测 HMAC 值 | LAN 场景风险可控；未来可替换为 `CRYPTO_memcmp` |
| 不支持 AEAD（GCM/CCM） | 不提供关联数据认证（如协议头保护） | 当前设计将协议头视为可信元数据 |
| IV 依赖 `/dev/urandom` | 容器/沙箱可能缺少设备节点 | 部署前确认 `/dev/urandom` 可用 |
| 控制帧不加密 | SYN/ACK/FIN/RST 的 channel_id 和标志位可见 | 控制帧不含敏感数据；若需要可扩展 |
| 无前向安全性（PFS） | 密钥泄露后历史数据可解密 | 当前为对称密钥架构，未来可考虑添加工单密钥协商 |

### 6.2 协议相关

| 限制 | 影响 | 缓解 |
|------|------|------|
| 无对端身份认证 | 攻击者可伪造 SYN 建立通道 | rate limiting + 静态通道配置 |
| MAC 自动发现未完成 | 依赖手动配置 `peer_mac` | 强烈建议显式配置 peer_mac |
| 无数据压缩 | 加密后数据不可压缩 | 在 KCP 层面或应用层自行压缩 |
| 帧大小不固定/无填充 | 流量分析可推断数据特征 | 未来可考虑固定大小填充 |

### 6.3 部署相关

| 限制 | 影响 | 缓解 |
|------|------|------|
| 需要 root/CAP_NET_RAW | 增加攻击面 | 使用 systemd 能力限制 + `NoNewPrivileges=yes` |
| AF_PACKET 绕过内核防火墙 | iptables/nftables 规则不生效 | 在应用层实现访问控制 |
| 无内置密钥协商 | 密钥需手动分发 | 通过 SSH 安全传输配置文件 |

---

## 7. 安全配置清单

### 部署前安全检查

- [ ] 使用强随机 SM4 密钥（`openssl rand -hex 16` 生成）
- [ ] 配置文件权限设置为 `0600`
- [ ] 显式配置 `peer_mac`（不使用广播）
- [ ] 启用加密（`encryption.enabled: true`）
- [ ] 启用 CRC32（`crc_enabled: true`，检测传输错误）
- [ ] 限制 `max_channels` 为实际需要的值
- [ ] 配置合理的 `heartbeat_timeout`
- [ ] 使用专用非 root 用户运行（通过 systemd `User=`）
- [ ] 限制进程 capabilities（仅 `CAP_NET_RAW` + 可选 `CAP_NET_ADMIN`）
- [ ] 配置文件不包含在版本控制中（`.gitignore`）
- [ ] 防火墙规则限制管理端口的访问来源
- [ ] 定期轮换加密密钥
- [ ] 监控 `crypto_errors` 和 `crc_errors` 统计指标
- [ ] 异常高的错误率 → 可能遭受攻击 → 立即调查

### systemd 安全加固

```ini
[Service]
# 能力限制
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

# 禁止提权
NoNewPrivileges=yes

# 文件系统保护
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/run
PrivateTmp=yes
PrivateDevices=no          # 需要 /dev/urandom

# 网络命名空间（如不需要访问外网）
# PrivateNetwork=yes       # 注意：这会阻止 AF_PACKET

# 资源限制
MemoryMax=256M
CPUQuota=50%
TasksMax=64
LimitNOFILE=4096
```
