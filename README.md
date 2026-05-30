# KCP-over-AF_PACKET

## 项目简介

KCP-over-AF_PACKET 是一个 Linux 用户空间代理隧道系统，通过 **AF_PACKET 原始套接字**直接在数据链路层（OSI 第 2 层）进行通信，完全绕过 Linux 内核 TCP/IP 协议栈。系统集成 **KCP 协议**（一种基于 UDP 的可靠传输协议）提供 ARQ 可靠传输能力，支持**透明 TCP/UDP 代理**和**多流复用**（多通道），适用于需要低延迟、高吞吐、完全旁路内核网络的特殊场景。

**版本：** 1.0.0 | **许可证：** 参见源码头部声明

---

## 核心特性

- 🔌 **纯链路层通信**：基于 AF_PACKET + 自定义 EtherType，无需 IP 地址配置，无需路由表，两台主机通过以太网帧直接通信
- 🔄 **透明 TCP/UDP 代理**：Frontend 代理（本地监听 → 远端转发）和 Backend 代理（远端请求 → 本地服务）两种模式，对应用层完全透明
- 📦 **KCP 可靠 ARQ 传输**：集成 KCP (ikcp) 协议，提供可配置的自动重传（ARQ）、流量控制和拥塞控制
- 🔀 **多流复用**：最多支持 256 个并发通道，每个通道独立维护 KCP 实例和 7 状态状态机，通过 channel_id 实现帧级多路复用
- 🔐 **国密加密与校验**：支持 SM4-CBC 加密 + SM3-HMAC 完整性校验（基于 GNU Nettle），以及可选的 CRC32 帧校验
- 🚀 **高性能设计**：epoll 边缘触发 I/O（EPOLLET）、TPACKET_V2 高性能数据路径、非阻塞套接字、零拷贝友好架构
- 📡 **多实例部署**：通过 PID 文件管理，支持同一网卡上部署多个实例（需配置不同 EtherType）
- 🔍 **BPF 内核过滤**：使用 Berkeley Packet Filter 在内核层面过滤帧，仅接收目标 EtherType 的帧，减少用户态开销
- 🛡️ **频道加密**：每帧独立随机 IV，密钥分离（SM4 与 HMAC 独立派生），Encrypt-then-MAC 安全设计

---

## 快速开始

### 系统要求

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| Linux Kernel | ≥ 2.6.31 | 需要 AF_PACKET 和 TPACKET_V2 支持 |
| GCC | ≥ 7.0 | C11/GNU11 标准，`_Static_assert` 支持 |
| libjson-c | ≥ 0.13 | JSON 配置文件解析 |
| libnettle | ≥ 3.4 | 国密加密库（SM4 + SM3） |
| glibc | ≥ 2.17 | `epoll_create1`, `clock_gettime` |

### 安装依赖

```bash
# Debian/Ubuntu
sudo apt-get install -y build-essential gcc make libjson-c-dev nettle-dev

# RHEL/CentOS/Fedora
sudo dnf install -y gcc make json-c-devel nettle-devel
```

### 编译

```bash
# Release 构建（-O2 优化，生产环境推荐）
make

# Debug 构建（-g -O0 -DDEBUG，包含调试日志）
make debug

# 查看所有构建目标
make help

# 安装到系统
sudo make install
```

### 运行

```bash
# 使用配置文件启动
sudo ./kcp-afpacket config.json

# 配置文件示例见 config.example.json 和 config-node-b.json / config-node-c.json
```

### 拓扑示例

```
客户端 ──TCP──► Frontend节点 ──AF_PACKET──► Backend节点 ──TCP──► 服务端
```

---

## 测试状态

| 测试套件 | 计数 | 命令 | 状态 |
|---------|------|------|------|
| 单元测试 (MyProto) | ~29 项 | `make test-unit` | ✅ Passing |
| 集成测试 I | ~26 项 | `make test-integ` | ✅ Passing |
| 集成测试 II | ~20 项 | `make test-integ2` | ✅ Passing |
| 对比测试 | ~18 项 | `make test-compare` | ✅ Passing |
| **合计** | **~80+ 项** | `make test` | ✅ All Passing |

```bash
# 运行全部测试
make test

# 按需运行
make test-unit      # 协议模块单元测试
make test-integ     # 配置加载/KCP/通道集成测试
make test-integ2    # 状态机/边界/IPv6/MTU 扩展测试
```

---

## 文档

| 文档 | 内容 |
|------|------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 系统架构、数据流、状态机、协议帧格式、加密管线、关键常量 |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | 部署指南、配置文件详解、拓扑示例、systemd 服务、性能调优 |
| [docs/SECURITY.md](docs/SECURITY.md) | SM4-CBC+SM3-HMAC 加密、密钥管理、威胁模型、DoS 防护 |
| [docs/TESTING.md](docs/TESTING.md) | 测试套件（80+测试）、运行方法、添加新测试、CI 建议 |
| [docs/CONFIG.md](docs/CONFIG.md) | 配置文件完整参考（所有字段的类型、默认值、范围） |

---

## 模块结构

| 模块 | 文件 | 职责 |
|------|------|------|
| **main** | `src/main.c` | 入口点：配置加载/验证、信号处理、启动编排、主事件循环 |
| **af_packet** | `src/af_packet.c/h` | AF_PACKET 原始套接字、BPF 过滤、MAC 发现、NIC MTU 管理 |
| **myproto** | `src/myproto.c/h` | MyProto 私有协议：帧封装/解析、控制帧/数据帧、CRC32 校验 |
| **crypto** | `src/crypto.c/h` | SM4-CBC 加密 + SM3-HMAC 认证（GNU Nettle） |
| **kcp_wrap** | `src/kcp_wrap.c/h` | KCP (ikcp) 库封装：创建/销毁、参数配置、输入/输出接口 |
| **channel** | `src/channel.c/h` | 核心模块：通道生命周期、7 状态机、哈希表、帧路由、心跳/超时 |
| **proxy** | `src/proxy.c/h` | TCP/UDP 透明代理：监听、连接、epoll 事件、数据桥接 |
| **ikcp** | `src/ikcp.c/h` | KCP 协议核心库（第三方，可靠传输协议实现） |

---

## 许可

参见源码文件头部声明。
