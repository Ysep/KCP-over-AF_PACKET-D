# 测试环境 vs 生产环境 — KCP-over-AF_PACKET

本文档详细说明 KCP-over-AF_PACKET 在测试环境（stub 模式）与生产环境（真实网络）之间的关键差异，帮助开发和运维团队理解哪些功能已被测试验证，哪些需要在真实部署中进行集成验证。

---

## 目录

1. [测试环境概览](#1-测试环境概览)
2. [生产环境概览](#2-生产环境概览)
3. [关键差异详解](#3-关键差异详解)
4. [测试覆盖矩阵](#4-测试覆盖矩阵)
5. [测试覆盖率保障 vs 实际部署需求](#5-测试覆盖率保障-vs-实际部署需求)
6. [生产验证建议](#6-生产验证建议)

---

## 1. 测试环境概览

KCP-over-AF_PACKET 的测试套件（80+ 项测试）在**纯软件层面**运行，无需任何真实网络硬件。

### 1.1 测试架构

```
┌────────────────────────────────────────────┐
│            测试二进制 (test_*.c)            │
│                     │                        │
│     ┌───────────────┼───────────────┐       │
│     │               │               │       │
│  myproto.c      channel.c       kcp_wrap.c  │
│  crypto.c       (状态机+路由)    ikcp.c     │
│     │               │               │       │
│     └───────┬───────┴───────┬───────┘       │
│             │               │               │
│      ┌──────▼──────┐  ┌─────▼──────┐        │
│      │ af_packet   │  │   proxy    │        │
│      │  (stub)     │  │  (stub)    │        │
│      └─────────────┘  └────────────┘        │
│                                             │
│  ❌ 无真实 AF_PACKET socket                  │
│  ❌ 无真实 TCP/UDP 网络连接                   │
│  ❌ 无真实网卡交互                            │
└────────────────────────────────────────────┘
```

### 1.2 Stub 函数列表

| Stub 函数 | 所在模块 | Stub 行为 | 测试含义 |
|-----------|---------|-----------|---------|
| `af_packet_send()` | af_packet.c | 返回 0，不实际发送帧 | 验证帧构造逻辑正确，但不验证实际发送 |
| `af_packet_create()` | af_packet.c | 返回虚拟 fd，不创建真实 socket | 验证 socket 创建参数正确性 |
| `proxy_connect_remote()` | proxy.c | 返回 0，不建立 TCP/UDP 连接 | 验证连接参数传递正确 |
| `proxy_start_listen()` | proxy.c | 返回 0，不绑定真实端口 | 验证监听参数合法性 |
| `af_packet_set_bpf()` | af_packet.c | 返回 0，不安装内核 BPF | 验证 BPF 字节码生成正确 |
| `af_packet_get_mac()` | af_packet.c | 返回固定 MAC 地址 | 验证 MAC 地址解析流程 |

### 1.3 测试环境特征

- **编译标志**：`-DTEST_BUILD` 条件编译，启用 stub 实现
- **编译优化**：`-O0 -g`，无优化 + 调试符号
- **运行时**：直接在命令行执行，无需 root 权限
- **网络依赖**：零 — 可在 CI Runner / 开发容器中运行

---

## 2. 生产环境概览

```
┌─────────────────────────────────────────────────────┐
│                kcp-afpacket (生产)                    │
│                                                       │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐       │
│  │  proxy   │◄──►│ channel  │◄──►│ af_packet │       │
│  │ (真实fd) │    │ (KCP+HS) │    │ (真实sock)│       │
│  └────┬─────┘    └──────────┘    └────┬─────┘       │
│       │                               │              │
│  TCP/UDP socket               AF_PACKET socket       │
│       │                               │              │
│  ┌────▼─────┐                  ┌──────▼──────┐       │
│  │ 内核协议栈│                  │  网卡驱动    │       │
│  └──────────┘                  └──────┬──────┘       │
│                                       │              │
│                                以太网物理链路          │
└─────────────────────────────────────────────────────┘

✅ 真实 AF_PACKET 原始套接字 (socket + bind + TPACKET_V2)
✅ 真实 TCP/UDP 监听和连接
✅ 真实 BPF 内核过滤器
✅ 真实 MAC 地址发现 (SIOCGIFHWADDR)
✅ 真实 NIC MTU 管理 (SIOCGIFMTU / SIOCSIFMTU)
✅ 真实 epoll 边缘触发 I/O
✅ 真实信号处理 (SIGHUP reload, SIGUSR1 通道控制, SIGTERM 优雅退出)
```

---

## 3. 关键差异详解

### 3.1 Stub 函数返回 0 但不执行真实 I/O

| 方面 | 测试环境 | 生产环境 |
|------|---------|---------|
| `af_packet_send()` | 返回 0（模拟成功） | 执行 `sendto()` 系统调用，可能因网卡满、MTU 超限、权限不足等失败 |
| `af_packet_create()` | 返回虚拟 fd | 执行 `socket(AF_PACKET, SOCK_RAW, ...)`，需要 `CAP_NET_RAW` |
| `proxy_connect_remote()` | 返回 0 | 执行 `connect()`，可能超时、拒绝连接、DNS 解析失败 |
| `proxy_start_listen()` | 返回 0 | 执行 `bind()` + `listen()`，端口可能被占用 |

**后果**：测试验证了**数据路径的软件逻辑正确性**，但无法验证**系统调用层的错误路径**。生产环境中大量错误场景（网卡 down、MTU 不匹配、端口冲突、内核缓冲区满）未被测试覆盖。

### 3.2 无真实数据包校验

| 方面 | 测试环境 | 生产环境 |
|------|---------|---------|
| AF_PACKET 帧接收 | 直接调用 `channel_process_frame()` 注入构造好的帧 | 通过 `recvfrom()` 从内核接收真实以太网帧 |
| 以太网帧头处理 | 测试手动构造 14 字节头部 | 内核剥离头部后交付，或完整帧交给用户态 |
| BPF 过滤 | stub 不执行过滤 | 内核 BPF 过滤器丢弃不匹配的帧 |
| TPACKET_V2 | 不使用 | 使用 TPACKET_V2 高性能环形缓冲区 |
| 帧丢失 / 乱序 | 不模拟 | 真实物理链路帧可能丢失、乱序、重复 |

**后果**：测试无法验证：
- 内核 BPF 过滤器是否按预期过滤
- TPACKET_V2 模式下缓冲区溢出行为
- 真实网络丢包率下的 KCP 重传效果
- 物理层错误（CRC 错误帧、巨帧、VLAN 标记帧）

### 3.3 内存分配差异

| 方面 | 测试环境 | 生产环境 |
|------|---------|---------|
| 帧缓冲区 | 栈上分配（小缓冲区，测试用） | 堆上分配（`AF_PACKET_FRAME_SIZE = 1600` 字节） |
| 通道哈希表 | 小规模（max_channels ≤ 256） | 可配置到 65536 个槽位 |
| KCP 实例内存 | 测试结束后立即释放 | 长期运行，需关注内存碎片和泄漏 |
| SM4 加解密上下文 | 临时密钥，测试后丢弃 | 持久化密钥，需安全擦除 |

**后果**：
- 测试中的栈分配意味着 50000+ 监听器场景下的内存需求（~70MB）未在测试中真实模拟
- 长时间运行的内存碎片化行为未被测试

### 3.4 测试无法验证真实 TCP/AF_PACKET 转发

```mermaid
测试环境：
  [测试代码] → stub_send() → "成功" (无数据移动)

生产环境：
  [客户端 TCP] → proxy → KCP → MyProto → AF_PACKET → 网卡
    ↕
  [服务端 TCP] ← proxy ← KCP ← MyProto ← AF_PACKET ← 网卡
```

| 转发环节 | 测试验证状态 | 生产验证需求 |
|---------|------------|------------|
| 客户端 → local_fd (accept) | ✅ 状态机验证 | ❌ 需真实 TCP 连接测试 |
| local_fd → KCP (数据分段) | ✅ 集成测试覆盖 | ❌ 需验证背压和流控 |
| KCP → MyProto (帧封装) | ✅ 单元 + 集成测试 | ❌ 需验证加密+HMAC |
| MyProto → AF_PACKET (发送) | ❌ stub 不发送 | ❌ 需真实网络测试 |
| AF_PACKET → MyProto (接收) | ❌ stub 模拟接收 | ❌ 需真实网络测试 |
| MyProto → KCP (重组) | ✅ 集成测试覆盖 | ❌ 需验证丢包重传 |
| KCP → remote_fd (转发) | ✅ 部分覆盖 | ❌ 需验证连接建立 |

---

## 4. 测试覆盖矩阵

### 4.1 功能覆盖矩阵

| 功能模块 | 功能点 | 单元测试 | 集成测试 I | 集成测试 II | 集成测试 III | 集成测试 IV | 需要真实部署验证 |
|---------|--------|:--:|:--:|:--:|:--:|:--:|:--:|
| **myproto** | 协议头编码/解码往返 | ✅ | ✅ | ✅ | — | — | — |
| | CRC32 已知向量校验 | ✅ | ✅ | ✅ | — | — | — |
| | CRC32 附加与验证 | ✅ | ✅ | ✅ | — | — | — |
| | 多尺寸负载 (0~1400B) | ✅ | — | ✅ | — | — | — |
| | 控制帧全部 6 种类型 | ✅ | ✅ | ✅ | — | — | — |
| | 帧验证（魔数/版本/长度） | ✅ | ✅ | ✅ | — | — | — |
| | 缓冲区溢出保护 | ✅ | — | ✅ | — | — | — |
| **crypto** | SM4-CBC 加密/解密往返 | ✅ | ✅ | ✅ | — | — | — |
| | SM3-HMAC 校验 | ✅ | ✅ | ✅ | — | — | — |
| | Encrypt-then-MAC | ✅ | — | ✅ | — | — | — |
| | 密钥擦除 | ✅ | — | — | — | — | — |
| | 每帧独立 IV | ✅ | — | ✅ | — | — | — |
| | 真实密钥轮换 | — | — | — | — | — | ❌ |
| **kcp_wrap** | 创建/销毁实例 | — | ✅ | ✅ | ✅ | ✅ | — |
| | 参数配置 | — | ✅ | ✅ | — | — | — |
| | 单段/多段收发 | — | ✅ | ✅ | ✅ | ✅ | — |
| | 窗口满处理 | — | ✅ | — | ✅ | — | — |
| | 真实丢包重传 | — | — | — | — | — | ❌ |
| | 真实带宽/延迟测试 | — | — | — | — | — | ❌ |
| **channel** | 状态机转换 (7 状态) | — | ✅ | ✅ | ✅ | ✅ | — |
| | SYN→ESTABLISHED 建立 | — | ✅ | ✅ | ✅ | ✅ | — |
| | FIN→TIME_WAIT→CLOSED | — | ✅ | ✅ | ✅ | — | — |
| | 心跳 PING/PONG | — | ✅ | ✅ | ✅ | — | — |
| | 超时检测与清理 | — | ✅ | — | ✅ | — | — |
| | 哈希表插入/查找/删除 | — | ✅ | ✅ | ✅ | ✅ | — |
| | 多会话 (multi-session) | — | — | — | ✅ | — | ❌ |
| | 真实心跳超时恢复 | — | — | — | — | — | ❌ |
| | 50000+ 监听器并发 | — | — | — | — | — | ❌ |
| | 通道热重载 (SIGHUP) | — | — | — | — | ✅ | ❌ |
| | 通道控制 (SIGUSR1) | — | — | — | — | — | ❌ |
| **proxy** | TCP 监听/连接参数 | — | ✅ | — | — | — | — |
| | IPv6 双栈支持 | — | — | ✅ | — | — | — |
| | 背压流控 | — | — | — | — | — | ❌ |
| | 真实 TCP 转发吞吐 | — | — | — | — | — | ❌ |
| **af_packet** | socket() 参数 | — | stub | — | — | — | — |
| | BPF 字节码生成 | — | stub | — | — | — | — |
| | MAC 地址解析流程 | — | ✅ | — | — | — | — |
| | 真实 AF_PACKET 收发 | — | — | — | — | — | ❌ |
| | TPACKET_V2 环形缓冲 | — | — | — | — | — | ❌ |
| | NIC MTU 自动设置 | — | — | — | — | — | ❌ |
| | 冲突检测 (/proc/net/packet) | — | — | — | — | — | ❌ |
| **main** | 配置加载/验证 | — | ✅ | ✅ | — | — | — |
| | 信号处理 (SIGINT/SIGTERM/SIGHUP/SIGUSR1) | — | ✅ | — | — | — | — |
| | PID 文件管理 | — | ✅ | — | — | — | — |
| | 优雅退出清理 | — | ✅ | — | — | — | — |
| | 真实 epoll 事件循环 | — | — | — | — | — | ❌ |

### 4.2 测试套件统计

| 套件 | 测试项数 | 涉及模块 | stub 依赖 | 网络需求 |
|------|---------|---------|----------|---------|
| `test_myproto` (unit) | ~29 | myproto, crypto | 无 | 无 |
| `test_integration` | ~26 | main, channel, kcp_wrap | af_packet, proxy | 无 |
| `test_integration_v2` | ~20 | myproto, channel, kcp_wrap | af_packet, proxy | 无 |
| `test_integration_v3` | ~20 | channel (multi-session) | af_packet, proxy | 无 |
| `test_integration_v4` | ~20 | channel (reload, uint32 ID) | af_packet, proxy | 无 |
| **合计已验证** | **~115** | — | — | — |
| **需生产验证** | — | af_packet, proxy, end-to-end | 无 | ✅ 需要 |

---

## 5. 测试覆盖率保障 vs 实际部署需求

### 5.1 测试套件能保障的内容

| ✅ 保障项 | 详细说明 |
|-----------|---------|
| 协议正确性 | MyProto 帧格式、CRC32、控制帧类型、魔数和版本号 — 完全验证 |
| 加密管线正确性 | SM4-CBC + SM3-HMAC 加解密往返、Encrypt-then-MAC 顺序、IV 随机性 |
| 状态机逻辑 | 7 状态转换、SYN→ESTABLISHED、FIN→CLOSED、RST 异常路径 |
| KCP 参数传递 | MTU、窗口大小、nodelay、interval、resend、nc 参数配置正确性 |
| 配置解析 | JSON 解析、字段验证、边界条件（interface 长度、ethertype 范围、重复 channel_id） |
| 哈希表操作 | 插入/查找/删除、冲突链处理 |
| 信号处理逻辑 | SIGHUP 触发 reload 标志、SIGUSR1 触发 ctl 标志、SIGTERM 触发退出 |
| 构建系统 | make / make debug / make clean / make test 所有目标 |
| 内存安全（基本） | 缓冲区溢出保护、空指针检查 |

### 5.2 测试套件不能保障的内容

| ❌ 未保障项 | 风险等级 | 说明 |
|------------|:--:|------|
| AF_PACKET 真实收发 | 🔴 高 | socket 创建可能因权限、内核版本、网卡支持度失败 |
| BPF 内核过滤器行为 | 🔴 高 | BPF 字节码正确性不影响其在真实内核中的执行结果 |
| TPACKET_V2 环形缓冲 | 🟡 中 | 高吞吐场景下的缓冲区溢出/丢帧行为 |
| 真实 TCP/UDP 连接 | 🔴 高 | accept/connect 可能因网络配置、防火墙、SELinux 失败 |
| 端到端数据转发 | 🔴 高 | 完整路径（客户端→proxy→KCP→AF_PACKET→...→服务端） |
| KCP 在真实丢包下的行为 | 🟡 中 | 测试未模拟丢包/乱序/重复场景 |
| 长期运行稳定性 | 🟡 中 | 内存泄漏、文件描述符泄漏、碎片化 |
| 高并发压力（50000+ 监听器） | 🟡 中 | ~70MB 内存需求、哈希表性能、epoll 扩展性 |
| 加密密钥轮换 | 🟡 中 | 测试使用临时密钥，未测试密钥轮换场景 |
| NIC MTU 自动设置 | 🟢 低 | `SIOCSIFMTU` 由内核提供，但可能被网卡驱动拒绝 |
| 冲突检测 | 🟢 低 | `/proc/net/packet` 解析在不同内核版本中可能不同 |
| SELinux / AppArmor 兼容性 | 🟢 低 | MAC 策略可能阻止 AF_PACKET 创建 |

---

## 6. 生产验证建议

### 6.1 最小验证清单（部署前必做）

```bash
# 1. 验证 AF_PACKET socket 创建
sudo ./kcp-afpacket config.json 2>&1 | head -20
# 预期：看到 "AF_PACKET socket created" 无错误

# 2. 验证 BPF 过滤器
sudo tcpdump -i eth0 ether proto 0x88B5 -c 5
# 预期：能看到系统发送的自定义 EtherType 帧

# 3. 验证对端连通性
# 在一端启动后，检查另一端是否收到 SYN 帧
sudo tcpdump -i eth0 ether proto 0x88B5 -v

# 4. 验证 TCP 代理转发
# Frontend: 监听 127.0.0.1:8080
curl http://127.0.0.1:8080/test
# 预期：返回 Backend 节点上服务的响应

# 5. 验证加密
# 启用 encryption.enabled=true，确认 HMAC 校验无误
# 查看日志中 "crypto init" 无报错

# 6. 验证信号处理
sudo systemctl reload kcp-afpacket     # SIGHUP 热重载
sudo kill -USR1 $(cat /var/run/kcp-afpacket.pid)  # SIGUSR1 通道控制
```

### 6.2 性能验证清单

| 验证项 | 方法 | 通过标准 |
|--------|------|---------|
| 吞吐量 | `iperf3` 通过隧道 | 达到链路带宽 80%+ |
| 延迟 | `ping` 通过隧道（UDP 通道） | RTT < 链路延迟 + 5ms |
| 并发连接 | 100+ 并发 TCP 连接 | 无超时、无 RST |
| 长时间运行 | 运行 72 小时 | 无内存泄漏 (RSS 稳定) |
| 内存占用 (50000 listeners) | `smem -P kcp-afpacket` | RSS ≈ 70 MB (±10%) |

### 6.3 错误场景验证

| 场景 | 操作方法 | 预期行为 |
|------|---------|---------|
| 网卡 down | `ip link set eth0 down` | 日志报错，服务不崩溃 |
| 对端离线 | 停止对端服务 | 心跳超时后通道进入 CLOSED |
| 端口占用 | 启动两个实例监听同端口 | 第二个实例报错退出 |
| 配置文件语法错误 | 写入非法 JSON | SIGHUP reload 报错，旧配置保持 |
| 内核缓冲区满 | 高速发包 + 不接收 | KCP 自动重传，不丢数据 |
| 密钥不匹配 | 两端使用不同 SM4 密钥 | HMAC 校验失败，帧被丢弃 |

### 6.4 安全验证

```bash
# 验证配置文件权限
stat /etc/kcp/config.json
# 预期：0600 或 0640，owner=root:root

# 验证二进制权限
stat /usr/local/bin/kcp-afpacket
# 预期：0755

# 验证密钥文件权限
stat /etc/kcp/sm4_key.hex
# 预期：0600，owner=root:root

# 验证 kcp 用户权限
sudo -u kcp /usr/local/bin/kcp-afpacket /etc/kcp/config.json
# 预期：因 CAP_NET_RAW 不足而失败（需要 root 或 setcap）
```

### 6.5 已知测试-生产差异导致的常见问题

1. **`EPERM` on `socket(AF_PACKET)`**：测试环境不需要权限，生产环境需要 `CAP_NET_RAW`。解决方案：`sudo` 或 `setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/kcp-afpacket`

2. **`ENODEV` on bind**：测试不调用真实 bind。生产环境中 interface 名称拼写错误或网卡未加载会导致此错误。

3. **MAC 地址广播回退**：测试中手动指定 MAC。生产环境中若 `peer_mac` 留空且自动发现未完整实现，帧会被发送到广播地址 `ff:ff:ff:ff:ff:ff`，可能被交换机过滤。

4. **BPF 过滤器静默丢弃**：测试不执行 BPF。生产内核 BPF 可能因 EtherType 配置错误而丢弃所有帧。

5. **TPACKET_V2 回退**：测试不执行 TPACKET_V2 逻辑。若内核不支持，系统自动回退到 TPACKET_V1，性能降低但功能正常。

---

## 参考文档

- [docs/TESTING.md](TESTING.md) — 测试套件详细说明
- [docs/ARCHITECTURE.md](ARCHITECTURE.md) — 系统架构与数据流
- [docs/DEPLOYMENT.md](DEPLOYMENT.md) — 部署指南
- [docs/SECURITY.md](SECURITY.md) — 安全与加密
