# 测试文档 — KCP-over-AF_PACKET

本文档描述 KCP-over-AF_PACKET 的测试套件，涵盖测试概览、运行方法、测试分类、新增测试指南和持续集成建议。

---

## 目录

1. [测试套件概览](#1-测试套件概览)
2. [如何运行测试](#2-如何运行测试)
3. [测试分类详解](#3-测试分类详解)
4. [如何添加新测试](#4-如何添加新测试)
5. [持续集成建议](#5-持续集成建议)

---

## 1. 测试套件概览

KCP-over-AF_PACKET 拥有 **80+ 项测试**，覆盖 4 个测试套件，全部可在无真实网络硬件的情况下运行。

### 测试套件矩阵

| 套件 | 测试文件 | 测试数量（约） | 类型 | 依赖 |
|------|---------|--------------|------|------|
| 单元测试 | `tests/test_myproto.c` | ~29 项 | 白盒单元测试 | `libnettle` |
| 集成测试 I | `tests/test_integration.c` | ~26 项 | 模块集成测试 | `libjson-c`、`libnettle` |
| 集成测试 II | `tests/test_integration_v2.c` | ~20 项 | 扩展集成测试 | `libnettle` |
| 对比测试 | `tests/test_comparison.c` | ~18 项 | 交叉验证测试 | `libnettle` |

### 测试覆盖范围

```
模块覆盖:
  myproto.c     ████████████████████  (29 单元 + 20 集成)
  crypto.c      ████████████████████  (被 myproto 间接覆盖)
  channel.c     ██████████████████    (26 + 20 集成)
  kcp_wrap.c    ██████████████████    (26 + 20 集成)
  ikcp.c        ██████████████████    (被 kcp_wrap 间接覆盖)
  main.c        ████████████          (26 集成, 配置加载/验证)
  proxy.c       ██████                (被集成测试间接覆盖)
  af_packet.c   ██████                (通过 stub 模拟)

功能覆盖:
  帧编码/解码  ✅      多尺寸往返  ✅      控制帧(6种)  ✅
  CRC32 校验   ✅      加密/解密   ✅      HMAC 验证    ✅
  配置加载     ✅      配置验证     ✅      边界条件      ✅
  KCP 生命周期 ✅      通道状态机   ✅      哈希表操作    ✅
  MTU 预算分析 ✅      缓冲区溢出   ✅      MAC 地址解析  ✅
  IPv6 地址    ✅      参数更新     ✅      统计计数器    ✅
```

---

## 2. 如何运行测试

### 前置条件

```bash
# 安装测试依赖
sudo apt-get install -y build-essential gcc make libjson-c-dev nettle-dev
```

### 运行全部测试

```bash
cd /sandbox/workspace/kcp-afpacket-C

# 一键运行所有测试（单元 + 集成 I + 集成 II）
make test
```

### 按套件运行

```bash
# 仅运行单元测试（MyProto 协议模块，~29 项）
make test-unit

# 仅运行集成测试 I（配置加载、KCP 生命周期、通道管理等，~26 项）
make test-integ

# 仅运行集成测试 II（扩展测试：协议层、状态机、边界、IPv6 等，~20 项）
make test-integ2

# 运行对比测试（与原始项目交叉验证，~18 项）
make test-compare
```

### 清理测试产物

```bash
make test-clean
```

### 预期输出

所有测试通过时：

```
  [TEST 1] Header encode/decode round-trip ... OK
  [TEST 2] CRC32 known vector '123456789' ... OK
  [TEST 3] CRC append and verify round-trip ... OK
  ...
  [TEST 29] <test name> ... OK

========================================
  Test Summary: 29 run, 29 passed, 0 failed
========================================
```

有测试失败时：

```
  [TEST 5] <test name> ... FAIL: expected value mismatch
  ...

========================================
  Test Summary: 29 run, 28 passed, 1 failed
========================================
```

退出码：有失败 → 非零（CI 可据此判断）

---

## 3. 测试分类详解

### 3.1 单元测试（`test_myproto.c`，~29 项）

**编译**：
```bash
gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g \
    -o tests/test_myproto tests/test_myproto.c \
    src/myproto.c src/crypto.c -lnettle
```

**覆盖内容**：

| 类别 | 测试项 | 说明 |
|------|--------|------|
| 协议头编码/解码 | Header 往返测试 | 构造帧 → 解析帧 → 验证所有字段一致性 |
| CRC32 | 已知向量 `"123456789"` → `0xCBF43926` | 验证 CRC-32/ISO-HDLC 实现正确性 |
| CRC32 | 附加与验证往返 | 构造帧（含CRC）→ 解析并验证 CRC |
| 帧构造 | 多尺寸负载（0, 1, 16, 128, 256, 512, 1024, 1400） | 覆盖空帧到最大帧 |
| 控制帧 | SYN/ACK/FIN/RST/PING/PONG（6 种） | 验证标志位正确设置 |
| 帧验证 | 非法魔数、非法版本、超长 data_len | 验证错误检测能力 |
| 加密帧 | SM4-CBC 加密/解密往返 | 验证加密管线正确性 |
| HMAC | HMAC 校验失败 → 拒绝帧 | 验证完整性保护 |
| 缓冲区 | 缓冲区溢出保护 | 验证边界检查 |
| CRC | CRC 校验失败 → 拒绝帧 | 验证错误检测 |

### 3.2 集成测试 I（`test_integration.c`，~26 项）

**编译**：
```bash
gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -DTEST_BUILD -Isrc -O0 -g \
    -o tests/test_integration tests/test_integration.c \
    src/main.c src/af_packet.c src/myproto.c src/crypto.c \
    src/kcp_wrap.c src/channel.c src/proxy.c src/ikcp.c \
    -ljson-c -lrt -lnettle
```

**覆盖内容**：

| 类别 | 测试项 | 说明 |
|------|--------|------|
| 配置加载 | 有效 JSON、缺失字段、非法值 | 验证 `config_load()` + `validate_config()` |
| 配置验证 | `interface` 长度、`ethertype` 范围、重复 `channel_id` | 边界和合法性检查 |
| KCP 生命周期 | 创建/销毁实例、参数配置、默认值 | 验证 `kcp_wrap_*` 系列函数 |
| KCP 数据传输 | 单段发送/接收、多段、零长度、窗口满 | 数据路径正确性 |
| 通道创建 | 正常创建、重复 ID、非法角色 | 通道生命周期 |
| 通道状态机 | SYN → SYN_SENT → ESTABLISHED 转换 | 状态转换逻辑 |
| 通道超时 | 心跳超时、TIME_WAIT 清理 | 资源回收 |
| 哈希表 | 插入/查找/删除、冲突处理 | 哈希表操作正确性 |
| 帧路由 | 控制帧 → 状态机，数据帧 → KCP | 帧分发逻辑 |
| 统计 | 计数器递增验证 | 统计准确性 |

### 3.3 集成测试 II（`test_integration_v2.c`，~20 项）

**编译**：
```bash
gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g \
    -o tests/test_integration_v2 tests/test_integration_v2.c \
    src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c src/ikcp.c \
    -lrt -lnettle
```

**覆盖内容**：

| 类别 | 测试项 | 说明 |
|------|--------|------|
| 协议层 | 帧编码/解码多尺寸往返（0~1400 字节，8 种尺寸） | 全面覆盖各种负载大小 |
| 协议层 | 控制帧全部 6 种类型 | 标志位正确性 |
| 协议层 | 帧验证：非法魔数、非法版本、超长 data_len | 健壮性 |
| 协议层 | CRC32 完整管线（附加+校验、篡改检测） | CRC 完整性 |
| 状态机 | CLOSED→SYN_SENT→ESTABLISHED（发起方路径） | 正常连接建立 |
| 状态机 | CLOSED→SYN_RCVD→ESTABLISHED（响应方路径） | 被动接受连接 |
| 状态机 | ESTABLISHED→FIN_SENT→TIME_WAIT→CLOSED | 正常关闭 |
| 状态机 | 任意状态 + RST → CLOSED | 强制复位 |
| 状态机 | SYN_SENT 超时重试（模拟 3 次重试上限） | 超时处理 |
| 边界条件 | channel_id=0、channel_id=65535 | 边界 ID |
| 边界条件 | 空负载帧、最大负载帧 | 边界负载 |
| 边界条件 | 多通道并发（同时活跃多个通道） | 并发正确性 |
| IPv6 | IPv6 地址解析 | 地址处理 |
| MAC | MAC 地址解析（`"aa:bb:cc:dd:ee:ff"`） | MAC 辅助函数 |
| KCP | KCP 参数动态更新 | 运行时参数修改 |
| KCP | 拥塞控制开关（nc=0/1） | 流控模式切换 |
| MTU | MTU 预算计算验证 | 确保不超出链路限制 |

### 3.4 对比测试（`test_comparison.c`，~18 项）

**编译**：
```bash
gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g \
    -o tests/test_comparison tests/test_comparison.c \
    src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c src/ikcp.c \
    src/af_packet.c src/proxy.c -lrt -lnettle
```

**用途**：与原始 KCP-over-AF_PACKET 项目进行交叉验证，确保本项目实现与原项目行为一致。

---

## 4. 如何添加新测试

### 4.1 添加单元测试

编辑 `tests/test_myproto.c`：

```c
/*
 * Test N: <测试名称>
 */
static void test_my_new_feature(void)
{
    TEST("my new feature description");

    // 1. 准备测试数据
    const char *input = "test data";
    uint8_t buf[MAX_FRAME_SIZE];

    // 2. 执行被测函数
    ssize_t result = my_function_under_test(input, buf, sizeof(buf));

    // 3. 验证结果
    if (result < 0) {
        FAIL("unexpected error return");
        return;
    }
    if (result != expected_value) {
        printf("(got %zd, expected %d) ", result, expected_value);
        FAIL("result mismatch");
        return;
    }

    OK();
}
```

然后在 `main()` 函数中注册：

```c
int main(void)
{
    // ... 现有测试 ...
    test_my_new_feature();       // ← 添加新测试
    // ...
    print_summary();
    return tests_failed ? 1 : 0;
}
```

### 4.2 添加集成测试

编辑 `tests/test_integration.c` 或 `tests/test_integration_v2.c`，遵循相同的 TEST/PASS/FAIL/CHECK 模式。

### 4.3 测试编写规范

1. **命名**：函数名使用 `test_<模块>_<场景>()` 格式，如 `test_channel_state_syn_timeout()`
2. **独立性**：每个测试应独立，不依赖其他测试的副作用
3. **清理**：在函数结束前释放所有分配的资源
4. **无硬件依赖**：使用 stub 替代真实网络操作
5. **断言清晰**：使用 `FAIL("具体原因")` 而非笼统的"test failed"
6. **边界覆盖**：至少覆盖空输入、正常输入、边界输入、非法输入四类

### 4.4 添加 Stub

如果测试涉及网络操作，在测试文件中添加 stub：

```c
/* Stub: af_packet_send — 返回成功但不真实发送 */
ssize_t af_packet_send(int sock, int ifindex,
                       const uint8_t *dst_mac, const uint8_t *src_mac,
                       uint16_t ethertype,
                       const uint8_t *data, size_t data_len)
{
    (void)sock; (void)ifindex; (void)dst_mac; (void)src_mac;
    (void)ethertype; (void)data;
    return (ssize_t)data_len;  /* pretend success */
}
```

### 4.5 更新 Makefile

如果是新增独立测试文件，在 Makefile 中添加编译规则：

```makefile
# 新测试套件
TEST_NEW_SRC  := tests/test_new.c src/myproto.c src/crypto.c
TEST_NEW_BIN  := tests/test_new
TEST_NEW_LIBS := -lnettle

.PHONY: test-new

test-new: $(TEST_NEW_BIN)
	@echo "  RUN     $(TEST_NEW_BIN)"
	@./$(TEST_NEW_BIN)

$(TEST_NEW_BIN): $(TEST_NEW_SRC)
	@mkdir -p tests
	@echo "  CC      $@"
	$(CC) $(TEST_CFLAGS) -o $@ $(TEST_NEW_SRC) $(TEST_NEW_LIBS)

# 并入 make test
test: test-unit test-integ test-integ2 test-new
```

---

## 5. 持续集成建议

### 5.1 GitHub Actions 示例

```yaml
# .github/workflows/test.yml
name: Tests

on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        build-type: [release, debug]

    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y build-essential libjson-c-dev nettle-dev

      - name: Build (${{ matrix.build-type }})
        run: |
          if [ "${{ matrix.build-type }}" = "debug" ]; then
            make debug
          else
            make
          fi

      - name: Run unit tests
        run: make test-unit

      - name: Run integration tests I
        run: make test-integ

      - name: Run integration tests II
        run: make test-integ2

      - name: Upload test binaries on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: test-artifacts-${{ matrix.build-type }}
          path: tests/
```

### 5.2 本地 Git Hook（pre-commit）

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running tests before commit..."
make test
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Tests failed. Commit aborted."
    echo "   Use 'git commit --no-verify' to skip (not recommended)."
    exit 1
fi
echo "✅ All tests passed."
```

### 5.3 Jenkins Pipeline 示例

```groovy
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'sudo apt-get install -y libjson-c-dev nettle-dev'
                sh 'make clean && make'
            }
        }
        stage('Test') {
            parallel {
                stage('Unit Tests') {
                    steps { sh 'make test-unit' }
                }
                stage('Integration Tests') {
                    steps { sh 'make test-integ' }
                }
                stage('Extended Tests') {
                    steps { sh 'make test-integ2' }
                }
            }
        }
    }

    post {
        failure {
            archiveArtifacts artifacts: 'tests/*'
        }
    }
}
```

### 5.4 测试覆盖率（使用 gcov）

```bash
# 编译带覆盖率的 debug 版本
make debug CFLAGS="-Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -g -O0 --coverage"
make test

# 生成覆盖率报告
gcov -r src/*.c
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html
```

### 5.5 CI 检查清单

- [ ] 每次 push/PR 自动触发全部测试
- [ ] Release 和 Debug 两种编译模式都通过
- [ ] 测试失败时阻止合并
- [ ] 归档失败测试的产物和日志
- [ ] 定期检查测试覆盖率趋势（目标 > 70%）
- [ ] 新功能合并前必须包含对应测试
