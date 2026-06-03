# 端口范围配置注意事项

本文档说明 `listen_port_range` / `remote_port_range` 的适用边界、常见误区和推荐范围。

## 1. 基本行为

- `listen_port_range` 会在配置加载阶段展开为多条静态通道。
- `remote_port_range` 会按一一对应方式展开，长度必须与监听范围一致。
- 也可以只写单个 `remote_port` 作为起始端口，随后按监听端口偏移自动递增。

例如：

```json
{
  "channel_id": 100,
  "listen_addr": "0.0.0.0",
  "listen_port_range": "5201-5203",
  "remote_addr": "192.168.1.67",
  "remote_port": 5201,
  "is_tcp": true,
  "max_sessions": 256
}
```

会展开为：

- `channel_id=100, 5201 -> 5201`
- `channel_id=101, 5202 -> 5202`
- `channel_id=102, 5203 -> 5203`

## 2. 不要把端口范围理解成“轻量规则”

在 `frontend` 节点上，每个 TCP 监听端口都要创建一个真实的监听 socket。

这意味着：

- `500` 个连续端口 = `500` 个监听 socket
- `45227` 个连续端口（如 `9100-54326`） = `45227` 个监听 socket

所以超大端口范围首先会碰到的是操作系统 fd 上限，而不是协议层逻辑。

## 3. 当前实现下的主要约束

### 3.1 frontend 的 fd 上限

`frontend` 每个静态 TCP listener 都会占用一个 fd。若进程 `ulimit -n` / `RLIMIT_NOFILE` 不够，启动时会直接报：

```text
proxy_start_listen: socket(TCP) failed: Too many open files
```

当前代码会在启动、热重载新增通道、`ctl add` 前做 fd 预算预检，但预检只能提前报错，不能绕过系统资源限制。

### 3.2 运行期动态通道创建限速

静态 listener 的启动阶段已经不受 `1000/sec` 创建限速影响，但运行期动态会话仍受该限制。

典型触发场景：

- `nmap -sT`
- 高频 TCP connect 扫描
- 同时有大量客户端并发打到很多监听端口

此时报错会类似：

```text
channel_create: rate limit exceeded (1000/sec)
```

因此即使静态端口范围本身能启动，扫描或突发连接流量仍可能撞上运行期动态通道限速。

### 3.3 通道总数上限

当前编译常量：

- `MAX_CHANNELS = 65536`

端口范围展开后的静态通道数不能超过这个上限；同时还要为运行期动态子通道留出容量。

## 4. 推荐范围

在没有专门调高系统 fd 上限、也没有刻意降低扫描速率的前提下，建议：

- 保守推荐：`500` 个连续端口以内
- 较激进但仍可控：`800` 个连续端口以内
- 不建议：上万级连续端口范围

可直接使用的示例：

```json
"listen_port_range": "9100-9599",
"remote_port_range": "9100-9599"
```

这是 `500` 个连续端口，适合作为默认建议值。

如果机器已经明确提高 `ulimit -n`，也可以考虑：

```json
"listen_port_range": "9100-9899",
"remote_port_range": "9100-9899"
```

这是 `800` 个连续端口，但仍不适合高强度扫描压测。

## 5. 大范围需求的正确做法

如果业务确实需要很多端口，不建议直接配置一个几万端口的连续范围。更可行的方式是：

1. 分段配置多个较小范围，而不是单个超大范围。
2. 提前提高 `ulimit -n` / systemd `LimitNOFILE`。
3. 控制 `nmap -sT` 或其他扫描工具的并发和速率。
4. 评估是否真的需要“一端口一静态 listener”，还是可以改为更少端口的转发模型。

## 6. frontend / backend 差异

- `frontend`：负责本地监听端口，最容易先撞 fd 上限。
- `backend`：不需要为这些静态映射批量创建本地监听 socket，但仍会受到运行期连接失败、动态通道创建和会话资源的影响。

所以大范围端口映射的瓶颈通常先出现在 `frontend`，不是 `backend`。
