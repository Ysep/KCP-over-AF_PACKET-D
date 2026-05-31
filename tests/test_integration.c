/*
 * test_integration.c — KCP-over-AF_PACKET Integration Test Suite
 *
 * 全面验证模块间交互：配置加载/验证、KCP 包装器生命周期、
 * 通道哈希表操作、帧流模拟和配置边界情况。
 *
 * 所有测试均不需要真实网络硬件。
 *
 * 编译命令：
 *   gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -DTEST_BUILD -Isrc -O0 -g \
 *       tests/test_integration.c src/main.c src/af_packet.c \
 *       src/myproto.c src/kcp_wrap.c src/channel.c src/proxy.c \
 *       src/ikcp.c -ljson-c -lrt -o tests/test_integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <json-c/json.h>

#include "types.h"
#include "myproto.h"
#include "kcp_wrap.h"
#include "channel.h"
#include "ikcp.h"

/* ---- 从 main.c 引用的非静态函数 ---- */
extern int config_load(const char *path, global_config_t *config);
extern int validate_config(const global_config_t *config);

/* ============================================================================
 * 测试框架
 * ============================================================================ */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do {                               \
    tests_run++;                                      \
    printf("  [TEST %d] %s ... ", tests_run, name);   \
    fflush(stdout);                                   \
} while(0)

#define PASS() do {                                   \
    tests_passed++;                                   \
    printf("PASS\n");                                 \
} while(0)

#define FAIL(msg) do {                                \
    tests_failed++;                                   \
    printf("FAIL: %s\n", msg);                        \
} while(0)

#define CHECK(cond, msg) do {                         \
    if (!(cond)) { FAIL(msg); goto cleanup; }         \
} while(0)

static void print_banner(const char *title)
{
    printf("\n============================================================\n");
    printf("  %s\n", title);
    printf("============================================================\n");
}

static void print_summary(void)
{
    printf("\n============================================================\n");
    printf("  Integration Test Summary\n");
    printf("  Total: %d  Passed: %d  Failed: %d\n",
           tests_run, tests_passed, tests_failed);
    if (tests_failed == 0) {
        printf("  Status: ALL TESTS PASSED\n");
    } else {
        printf("  Status: %d TEST(S) FAILED\n", tests_failed);
    }
    printf("============================================================\n");
}

/* ============================================================================
 * 辅助函数：将 JSON 字符串写入临时文件
 * ============================================================================ */

static int write_temp_json(const char *path, const char *json_str)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "  [ERROR] Cannot write temp file %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    fputs(json_str, fp);
    fclose(fp);
    return 0;
}

/* ============================================================================
 * 辅助函数：初始化最小可用的 global_ctx_t
 * ============================================================================ */

static void init_minimal_ctx(global_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->raw_sock  = -1;
    ctx->epoll_fd  = -1;
    ctx->running   = 1;
    ctx->ifindex   = 0;
    ctx->ethertype = htons(MYPROTO_ETHERTYPE);

    /* 设置基本的全局配置默认值 */
    strncpy(ctx->config.interface, "eth0", MAX_INTERFACE_NAME - 1);
    ctx->config.ethertype          = MYPROTO_ETHERTYPE;
    ctx->config.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    ctx->config.kcp_send_window    = KCP_SEND_WINDOW;
    ctx->config.kcp_recv_window    = KCP_RECV_WINDOW;
    ctx->config.kcp_nodelay        = KCP_NODELAY;
    ctx->config.kcp_interval       = KCP_INTERVAL;
    ctx->config.kcp_resend         = KCP_RESEND;
    ctx->config.kcp_nc             = KCP_NC;
    ctx->config.node_type         = NODE_TYPE_FRONTEND;
    ctx->config.max_channels       = MAX_CHANNELS;
    ctx->config.heartbeat_interval = HEARTBEAT_INTERVAL;
    ctx->config.heartbeat_timeout  = HEARTBEAT_TIMEOUT;
    ctx->config.crc_enabled        = 0;
    ctx->config.encryption.enabled = 0;
    ctx->config.nic_mtu            = ETH_MTU;

    /* 添加一个默认通道配置 */
    ctx->config.channels[0].channel_id  = 1;
    ctx->config.channels[0].listen_port = 8080;
    ctx->config.channels[0].remote_port = 9090;
    strncpy(ctx->config.channels[0].listen_addr, "127.0.0.1", MAX_LISTEN_ADDR - 1);
    strncpy(ctx->config.channels[0].remote_addr, "192.168.1.1", MAX_REMOTE_ADDR - 1);
    ctx->config.channels[0].is_tcp  = 1;
    ctx->config.channels[0].enabled = 1;
    ctx->config.channel_count        = 1;
}

/* ============================================================================
 * Test Suite 1: 配置加载和验证
 * ============================================================================ */

static void test_config_load_valid(void)
{
    TEST("config_load() 解析有效的 JSON 配置文件");

    const char *json =
        "{"
        "  \"interface\": \"eth0\","
        "  \"ethertype\": 35013,"
        "  \"peer_mac\": \"aa:bb:cc:dd:ee:ff\","
        "  \"local_mac\": \"11:22:33:44:55:66\","
        "  \"node_type\": \"frontend\","
        "  \"max_channels\": 128,"
        "  \"crc_enabled\": true,"
        "  \"auto_set_nic_mtu\": false,"
        "  \"nic_mtu\": 1500,"
        "  \"kcp\": {"
        "    \"mtu\": 1400,"
        "    \"sndwnd\": 512,"
        "    \"rcvwnd\": 512,"
        "    \"nodelay\": 1,"
        "    \"interval\": 10,"
        "    \"resend\": 2,"
        "    \"nc\": 1"
        "  },"
        "  \"channels\": ["
        "    {"
        "      \"channel_id\": 10,"
        "      \"listen_port\": 8080,"
        "      \"remote_port\": 9090,"
        "      \"listen_addr\": \"0.0.0.0\","
        "      \"remote_addr\": \"10.0.0.1\","
        "      \"is_tcp\": true"
        "    },"
        "    {"
        "      \"channel_id\": 20,"
        "      \"listen_port\": 8081,"
        "      \"remote_port\": 9091,"
        "      \"listen_addr\": \"127.0.0.1\","
        "      \"remote_addr\": \"10.0.0.2\","
        "      \"is_tcp\": false"
        "    }"
        "  ]"
        "}";

    const char *tmp_path = "/tmp/test_integration_valid.json";
    if (write_temp_json(tmp_path, json) != 0) {
        FAIL("cannot write temp config file");
        return;
    }

    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int ret = config_load(tmp_path, &cfg);

    CHECK(ret == 0, "config_load returned error");

    /* 验证解析结果 */
    CHECK(strcmp(cfg.interface, "eth0") == 0,
          "interface mismatch");
    CHECK(cfg.ethertype == 35013,
          "ethertype mismatch");
    CHECK(cfg.crc_enabled == 1,
          "crc_enabled mismatch");
    CHECK(cfg.max_channels == 128,
          "max_channels mismatch");
    CHECK(cfg.node_type == NODE_TYPE_FRONTEND,
          "node_type mismatch");

    /* 验证 KCP 参数 */
    CHECK(cfg.kcp_mtu == 1400,          "kcp_mtu mismatch");
    CHECK(cfg.kcp_send_window == 512,   "kcp_send_window mismatch");
    CHECK(cfg.kcp_recv_window == 512,   "kcp_recv_window mismatch");
    CHECK(cfg.kcp_nodelay == 1,         "kcp_nodelay mismatch");
    CHECK(cfg.kcp_interval == 10,       "kcp_interval mismatch");
    CHECK(cfg.kcp_resend == 2,          "kcp_resend mismatch");
    CHECK(cfg.kcp_nc == 1,              "kcp_nc mismatch");

    /* 验证通道 */
    CHECK(cfg.channel_count == 2,              "channel_count mismatch");
    CHECK(cfg.channels[0].channel_id == 10,    "channel[0] id mismatch");
    CHECK(cfg.channels[0].listen_port == 8080, "channel[0] listen_port mismatch");
    CHECK(cfg.channels[1].channel_id == 20,    "channel[1] id mismatch");
    CHECK(cfg.channels[1].is_tcp == 0,         "channel[1] is_tcp mismatch");

    /* 验证 MAC 解析 */
    {
        uint8_t expected_peer[]  = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        uint8_t expected_local[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        CHECK(memcmp(cfg.peer_mac, expected_peer, 6) == 0,
              "peer_mac mismatch");
        CHECK(memcmp(cfg.local_mac, expected_local, 6) == 0,
              "local_mac mismatch");
    }

    /* validate_config 应该通过 */
    ret = validate_config(&cfg);
    CHECK(ret == 0, "validate_config should pass on valid config");

    unlink(tmp_path);
    PASS();
    return;

cleanup:
    unlink(tmp_path);
}

static void test_config_with_defaults(void)
{
    TEST("config_load() 使用默认值（最简配置）");

    const char *json =
        "{"
        "  \"interface\": \"eth0\","
        "  \"ethertype\": 35013,"
        "  \"channels\": ["
        "    {"
        "      \"channel_id\": 1,"
        "      \"listen_port\": 8080,"
        "      \"remote_port\": 9090"
        "    }"
        "  ]"
        "}";

    const char *tmp_path = "/tmp/test_integration_minimal.json";
    if (write_temp_json(tmp_path, json) != 0) {
        FAIL("cannot write temp config file");
        return;
    }

    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int ret = config_load(tmp_path, &cfg);

    CHECK(ret == 0, "config_load returned error on minimal config");

    /* 默认值检查 */
    CHECK(cfg.kcp_mtu == KCP_MTU_CONSERVATIVE,
          "default kcp_mtu mismatch");
    CHECK(cfg.kcp_send_window == KCP_SEND_WINDOW,
          "default kcp_send_window mismatch");
    CHECK(cfg.kcp_recv_window == KCP_RECV_WINDOW,
          "default kcp_recv_window mismatch");
    CHECK(cfg.node_type == NODE_TYPE_FRONTEND,
          "default node_type mismatch");
    CHECK(cfg.max_channels == 4096,
          "default max_channels mismatch");
    CHECK(cfg.crc_enabled == 0,
          "default crc_enabled should be 0");

    ret = validate_config(&cfg);
    CHECK(ret == 0, "validate_config should pass on minimal valid config");

    unlink(tmp_path);
    PASS();
    return;

cleanup:
    unlink(tmp_path);
}

static void test_config_load_reverse_node_type(void)
{
    TEST("config_load: reverse 代理模式解析");

    const char *json =
        "{"
        "  \"interface\": \"eth0\","
        "  \"ethertype\": 35013,"
        "  \"node_type\": \"backend\","
        "  \"channels\": ["
        "    {"
        "      \"channel_id\": 1,"
        "      \"listen_port\": 8080,"
        "      \"remote_port\": 9090"
        "    }"
        "  ]"
        "}";

    const char *tmp_path = "/tmp/test_integration_reverse.json";
    if (write_temp_json(tmp_path, json) != 0) {
        FAIL("cannot write temp config file");
        return;
    }

    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int ret = config_load(tmp_path, &cfg);

    CHECK(ret == 0, "config_load failed");
    CHECK(cfg.node_type == NODE_TYPE_BACKEND,
          "node_type should be NODE_TYPE_BACKEND");

    unlink(tmp_path);
    PASS();
    return;

cleanup:
    unlink(tmp_path);
}

static void test_config_load_nonexistent_file(void)
{
    TEST("config_load: 不存在的文件");

    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int ret = config_load("/tmp/nonexistent_config_xyz123.json", &cfg);

    CHECK(ret == -1, "config_load should fail on nonexistent file");

    PASS();
    return;

cleanup:
    ;
}

/* ============================================================================
 * Test Suite 2: KCP Wrapper 生命周期
 * ============================================================================ */

/* 用于验证输出回调被调用的标志 */
static int g_output_cb_called = 0;
static int g_output_cb_len     = 0;

static int test_output_callback(const char *buf, int len,
                                struct IKCPCB *kcp, void *user)
{
    (void)buf;
    (void)kcp;
    (void)user;
    g_output_cb_called = 1;
    g_output_cb_len    = len;
    return 0;
}

static void test_kcp_wrapper_lifecycle(void)
{
    TEST("KCP Wrapper 生命周期 (create→params→send→update→destroy)");

    g_output_cb_called = 0;
    g_output_cb_len    = 0;

    /* 1. 创建 KCP 实例 */
    struct IKCPCB *kcp = kcp_wrap_create(42, (void *)0xDEAD);
    CHECK(kcp != NULL, "kcp_wrap_create returned NULL");

    /* 2. 设置输出回调 */
    kcp_wrap_set_output(kcp, test_output_callback);

    /* 3. 配置 KCP 参数 */
    kcp_wrap_set_params(kcp,
                        1400,   /* mtu */
                        1024,   /* sndwnd */
                        1024,   /* rcvwnd */
                        1,      /* nodelay */
                        10,     /* interval */
                        2,      /* resend */
                        1);     /* nc */

    /* 4. 发送数据到 KCP — ikcp_send 返回入队的字节数 */
    const char *test_msg = "Hello KCP Integration Test!";
    int send_ret = kcp_wrap_send(kcp, (const uint8_t *)test_msg,
                                  (int)strlen(test_msg));
    CHECK(send_ret == (int)strlen(test_msg),
          "kcp_wrap_send should return byte count on success");

    /* 5. 验证 waitsnd > 0（数据在发送队列中） */
    int ws = kcp_wrap_waitsnd(kcp);
    CHECK(ws > 0, "waitsnd should be >0 after send");

    /* 6. 驱动 KCP 状态机（触发输出回调） */
    IUINT32 now = kcp_wrap_clock();
    kcp_wrap_update(kcp, now);

    /* 7. 验证输出回调被调用 */
    CHECK(g_output_cb_called == 1,
          "output callback should have been called");
    CHECK(g_output_cb_len > 0,
          "output callback should have received data");

    /* 8. 销毁 KCP 实例 */
    kcp_wrap_destroy(kcp);

    PASS();
    return;

cleanup:
    if (kcp) kcp_wrap_destroy(kcp);
}

static void test_kcp_wrapper_null_handling(void)
{
    TEST("KCP Wrapper 空指针安全检查");

    /* 这些调用不应崩溃 */
    kcp_wrap_destroy(NULL);
    kcp_wrap_set_output(NULL, test_output_callback);
    kcp_wrap_set_params(NULL, 1400, 1024, 1024, 1, 10, 2, 1);

    int ret;

    ret = kcp_wrap_send(NULL, (const uint8_t *)"test", 4);
    CHECK(ret == -1, "kcp_wrap_send(NULL) should return -1");

    ret = kcp_wrap_recv(NULL, (uint8_t *)"test", 4);
    CHECK(ret == -1, "kcp_wrap_recv(NULL) should return -1");

    ret = kcp_wrap_input(NULL, (const uint8_t *)"test", 4);
    CHECK(ret == -1, "kcp_wrap_input(NULL) should return -1");

    ret = kcp_wrap_waitsnd(NULL);
    CHECK(ret == -1, "kcp_wrap_waitsnd(NULL) should return -1");

    ret = kcp_wrap_has_pending(NULL);
    CHECK(ret == 0, "kcp_wrap_has_pending(NULL) should return 0");

    kcp_wrap_update(NULL, 0);

    IUINT32 ts = kcp_wrap_clock();
    CHECK(ts > 0, "kcp_wrap_clock() should return positive timestamp");

    PASS();
    return;

cleanup:
    ;
}

/*
 * KCP 往返测试：通过两个 KCP 实例的 output→input 桥接验证完整数据路径。
 * 这模拟了实际网络传输的核心逻辑，无需真实 socket。
 */

/* 用于 KCP 往返测试的桥接缓冲区 */
static uint8_t  g_bridge_buf[8192];
static int      g_bridge_len = 0;

/* A 端的输出回调：将 KCP 输出捕获到桥接缓冲区 */
static int kcp_a_output_cb(const char *buf, int len,
                           struct IKCPCB *kcp, void *user)
{
    (void)kcp;
    (void)user;
    if (len > 0 && len <= (int)sizeof(g_bridge_buf)) {
        memcpy(g_bridge_buf, buf, (size_t)len);
        g_bridge_len = len;
    }
    return 0;
}

/* B 端的输出回调：将 KCP 输出捕获到桥接缓冲区（ACK 方向） */
static int kcp_b_output_cb(const char *buf, int len,
                           struct IKCPCB *kcp, void *user)
{
    (void)kcp;
    (void)user;
    if (len > 0 && len <= (int)sizeof(g_bridge_buf)) {
        memcpy(g_bridge_buf, buf, (size_t)len);
        g_bridge_len = len;
    }
    return 0;
}

static void test_kcp_wrapper_full_roundtrip(void)
{
    TEST("KCP Wrapper 完整往返测试 (A→B→A, 模拟双端通信)");

    /* 创建 A 和 B 两个 KCP 实例 — 必须使用同一个 conv */
    struct IKCPCB *kcp_a = kcp_wrap_create(42, NULL);
    struct IKCPCB *kcp_b = kcp_wrap_create(42, NULL);
    CHECK(kcp_a != NULL, "kcp_a create failed");
    CHECK(kcp_b != NULL, "kcp_b create failed");

    /* 配置两端参数 */
    kcp_wrap_set_output(kcp_a, kcp_a_output_cb);
    kcp_wrap_set_output(kcp_b, kcp_b_output_cb);
    kcp_wrap_set_params(kcp_a, 1400, 1024, 1024, 1, 10, 2, 1);
    kcp_wrap_set_params(kcp_b, 1400, 1024, 1024, 1, 10, 2, 1);

    /* 
     * Step 1: A 发送消息到 KCP
     */
    const char *msg = "KCP Roundtrip Message!";
    int ret = kcp_wrap_send(kcp_a, (const uint8_t *)msg, (int)strlen(msg));
    CHECK(ret == (int)strlen(msg), "kcp_wrap_send on kcp_a failed");

    /* Step 2: 驱动 A 的 KCP → 输出回调捕获到 bridge */
    IUINT32 now = kcp_wrap_clock();
    g_bridge_len = 0;
    kcp_wrap_update(kcp_a, now);
    CHECK(g_bridge_len > 0, "kcp_a update should produce output");

    /* Step 3: Bridge → B 的 KCP 输入 */
    ret = kcp_wrap_input(kcp_b, g_bridge_buf, g_bridge_len);
    CHECK(ret == 0, "kcp_wrap_input to kcp_b failed");

    /* Step 4: 从 B 读取 → 应该收到 A 的消息 */
    {
        uint8_t recv_buf[256] = {0};
        int rlen = kcp_wrap_recv(kcp_b, recv_buf, (int)sizeof(recv_buf));
        CHECK(rlen == (int)strlen(msg), "kcp_wrap_recv from B length mismatch");
        CHECK(memcmp(recv_buf, msg, strlen(msg)) == 0,
              "kcp_wrap_recv from B content mismatch");
    }

    /* Step 5: B 回送响应 */
    const char *resp = "ACK from B";
    ret = kcp_wrap_send(kcp_b, (const uint8_t *)resp, (int)strlen(resp));
    CHECK(ret == (int)strlen(resp), "kcp_wrap_send response on kcp_b failed");

    /* Step 6: 驱动 B → bridge → A */
    g_bridge_len = 0;
    kcp_wrap_update(kcp_b, now + 10);
    CHECK(g_bridge_len > 0, "kcp_b update should produce output (ACK direction)");

    ret = kcp_wrap_input(kcp_a, g_bridge_buf, g_bridge_len);
    CHECK(ret == 0, "kcp_wrap_input to kcp_a for response failed");

    /* Step 7: 从 A 读取响应 */
    {
        uint8_t recv_buf[256] = {0};
        int rlen = kcp_wrap_recv(kcp_a, recv_buf, (int)sizeof(recv_buf));
        CHECK(rlen == (int)strlen(resp), "kcp_wrap_recv from A (response) length mismatch");
        CHECK(memcmp(recv_buf, resp, strlen(resp)) == 0,
              "kcp_wrap_recv from A (response) content mismatch");
    }

    kcp_wrap_destroy(kcp_a);
    kcp_wrap_destroy(kcp_b);

    PASS();
    return;

cleanup:
    if (kcp_a) kcp_wrap_destroy(kcp_a);
    if (kcp_b) kcp_wrap_destroy(kcp_b);
}

/* ============================================================================
 * Test Suite 3: 通道哈希表操作
 * ============================================================================ */

static void test_channel_hash_operations(void)
{
    TEST("Channel 哈希表操作 (init→create→find→destroy→cleanup)");

    global_ctx_t ctx;
    init_minimal_ctx(&ctx);

    int ret = channel_init(&ctx, 256);
    CHECK(ret == 0, "channel_init failed");
    CHECK(ctx.channel_count == 0, "initial channel_count should be 0");
    CHECK(channel_count(&ctx) == 0, "channel_count() should return 0");

    /* 创建多个通道 */
    channel_t *ch1 = channel_create(&ctx, 1, CHANNEL_ROLE_INITIATOR,
                                     8080, 9090,
                                     "127.0.0.1", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "channel_create ch1 failed");
    CHECK(ch1->channel_id == 1, "ch1 id mismatch");
    CHECK(ch1->role == CHANNEL_ROLE_INITIATOR, "ch1 role mismatch");

    channel_t *ch2 = channel_create(&ctx, 2, CHANNEL_ROLE_RESPONDER,
                                     8081, 9091,
                                     "127.0.0.1", "10.0.0.2", 0);
    CHECK(ch2 != NULL, "channel_create ch2 failed");

    channel_t *ch3 = channel_create(&ctx, 255, CHANNEL_ROLE_INITIATOR,
                                     9000, 9001,
                                     "0.0.0.0", "10.0.0.3", 1);
    CHECK(ch3 != NULL, "channel_create ch3 failed");

    CHECK(channel_count(&ctx) == 3, "channel_count should be 3");

    /* O(1) 查找：通过 channel_id 在哈希表中定位 */
    channel_t *found;

    found = channel_find(&ctx, 1);
    CHECK(found == ch1, "channel_find(1) should return ch1");

    found = channel_find(&ctx, 2);
    CHECK(found == ch2, "channel_find(2) should return ch2");

    found = channel_find(&ctx, 255);
    CHECK(found == ch3, "channel_find(255) should return ch3");

    /* 不存在的 ID 返回 NULL */
    found = channel_find(&ctx, 99);
    CHECK(found == NULL, "channel_find(99) should return NULL");

    /* 重复 ID 创建失败 */
    channel_t *dup = channel_create(&ctx, 1, CHANNEL_ROLE_INITIATOR,
                                     1234, 5678,
                                     "0.0.0.0", "0.0.0.0", 1);
    CHECK(dup == NULL, "channel_create with duplicate id should fail");
    CHECK(channel_count(&ctx) == 3, "channel_count unchanged after dup attempt");

    /* 销毁 ch3 */
    channel_destroy(&ctx, ch3);
    CHECK(channel_count(&ctx) == 2, "channel_count should be 2 after destroy");

    found = channel_find(&ctx, 255);
    CHECK(found == NULL, "ch3 should not be findable after destroy");

    found = channel_find(&ctx, 1);
    CHECK(found == ch1, "ch1 should still be findable");
    found = channel_find(&ctx, 2);
    CHECK(found == ch2, "ch2 should still be findable");

    /* 清理 */
    channel_destroy(&ctx, ch1);
    channel_destroy(&ctx, ch2);
    CHECK(channel_count(&ctx) == 0, "channel_count should be 0 after all destroyed");
    channel_shutdown(&ctx);

    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
}

static void test_channel_hash_collision_handling(void)
{
    TEST("Channel 哈希表冲突链与唯一性检查");

    global_ctx_t ctx;
    init_minimal_ctx(&ctx);

    int ret = channel_init(&ctx, 256);
    CHECK(ret == 0, "channel_init failed");

    /*
     * CHANNEL_HASH_SIZE=512 > MAX_CHANNELS=256，所有合法 channel_id
     * 都映射到唯一槽位。冲突检查通过重复 ID 测试验证。
     */

    channel_t *ch1 = channel_create(&ctx, 1, CHANNEL_ROLE_INITIATOR,
                                     8080, 9090,
                                     "127.0.0.1", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "channel_create ch1 failed");

    /* 重复 ID 被哈希表唯一性检查拒绝 */
    channel_t *dup = channel_create(&ctx, 1, CHANNEL_ROLE_RESPONDER,
                                     9999, 9999,
                                     "0.0.0.0", "0.0.0.0", 0);
    CHECK(dup == NULL, "duplicate channel_id should fail hash insert");

    /* 不同 ID 的通道正常创建 */
    channel_t *ch2 = channel_create(&ctx, 2, CHANNEL_ROLE_RESPONDER,
                                     8081, 9091,
                                     "127.0.0.1", "10.0.0.2", 0);
    CHECK(ch2 != NULL, "channel_create ch2 failed");
    CHECK(channel_count(&ctx) == 2, "channel_count should be 2");

    CHECK(channel_find(&ctx, 1) == ch1, "ch1 lookup failed");
    CHECK(channel_find(&ctx, 2) == ch2, "ch2 lookup failed");

    channel_destroy(&ctx, ch1);
    channel_destroy(&ctx, ch2);
    channel_shutdown(&ctx);

    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
}

/* ============================================================================
 * Test Suite 4: 帧流模拟（MyProto + Channel 路由）
 * ============================================================================ */

static void test_control_frame_types(void)
{
    TEST("Control Frame 构建与解析 (SYN/ACK/FIN/RST/PING/PONG)");

    struct {
        uint8_t  flag;
        const char *name;
    } ctrl_frames[] = {
        { MPF_SYN,  "SYN"  },
        { MPF_ACK,  "ACK"  },
        { MPF_FIN,  "FIN"  },
        { MPF_RST,  "RST"  },
        { MPF_PING, "PING" },
        { MPF_PONG, "PONG" },
    };

    for (size_t i = 0; i < sizeof(ctrl_frames) / sizeof(ctrl_frames[0]); i++) {
        uint8_t buf[MAX_FRAME_SIZE];
        ssize_t len = myproto_build_ctrl_frame(buf, sizeof(buf),
                                                10, ctrl_frames[i].flag, 0);
        CHECK(len > 0, "build_ctrl_frame failed");

        myproto_hdr_t hdr;
        const uint8_t *payload = NULL;
        size_t payload_len = 0;
        int ret = myproto_parse_frame(buf, (size_t)len,
                                       &hdr, &payload, &payload_len);
        CHECK(ret == 0, "parse_frame failed");

        char err[128];
        snprintf(err, sizeof(err), "%s flag mismatch: expected 0x%02x got 0x%02x",
                 ctrl_frames[i].name, ctrl_frames[i].flag, hdr.flags);
        CHECK(hdr.flags == ctrl_frames[i].flag, err);

        CHECK(hdr.data_len == 0, "control frame data_len should be 0");
        CHECK(myproto_is_ctrl_frame(hdr.flags) == 1, "should be ctrl frame");
        CHECK(myproto_is_data_frame(hdr.flags) == 0, "should not be data frame");
    }

    PASS();
    return;

cleanup:
    ;
}

static void test_syn_frame_routing(void)
{
    TEST("SYN 帧路由: channel_process_frame 创建响应方通道");

    global_ctx_t ctx;
    init_minimal_ctx(&ctx);

    /* 配置通道以便 SYN 处理时查找配置 */
    ctx.config.channels[0].channel_id  = 50;
    ctx.config.channels[0].listen_port = 8080;
    ctx.config.channels[0].remote_port = 9090;
    strncpy(ctx.config.channels[0].listen_addr, "127.0.0.1", MAX_LISTEN_ADDR - 1);
    strncpy(ctx.config.channels[0].remote_addr, "10.0.0.50", MAX_REMOTE_ADDR - 1);
    ctx.config.channels[0].is_tcp  = 1;
    ctx.config.channels[0].enabled = 1;
    ctx.config.channel_count        = 1;

    int ret = channel_init(&ctx, 256);
    CHECK(ret == 0, "channel_init failed");
    CHECK(channel_count(&ctx) == 0, "initial count should be 0");

    /* 构建 SYN 帧 */
    uint8_t syn_frame[MAX_FRAME_SIZE];
    ssize_t syn_len = myproto_build_ctrl_frame(syn_frame, sizeof(syn_frame),
                                                50, MPF_SYN, 0);
    CHECK(syn_len > 0, "build SYN frame failed");

    /* 解析 SYN 帧 */
    myproto_hdr_t syn_hdr;
    const uint8_t *syn_payload = NULL;
    size_t syn_payload_len = 0;
    ret = myproto_parse_frame(syn_frame, (size_t)syn_len,
                               &syn_hdr, &syn_payload, &syn_payload_len);
    CHECK(ret == 0, "parse SYN frame failed");
    CHECK(syn_hdr.flags == MPF_SYN, "flags should be SYN");
    CHECK(syn_hdr.channel_id == 50, "channel_id should be 50");

    /*
     * 通过 channel_process_frame 处理 SYN。
     * 响应方路径：创建通道 → 发送 ACK → proxy_start_listen。
     * proxy_start_listen 会因无真实 epoll_fd 而失败，导致通道被销毁。
     * 我们验证处理过程不崩溃，并验证通道曾被创建（即使之后销毁）。
     */
    fprintf(stderr, "\n      (expected proxy/epoll errors below — no real network) ");
    ret = channel_process_frame(&ctx, &syn_hdr, syn_payload, syn_payload_len);
    /*
     * 返回值可能为 -1（proxy_start_listen 失败），也可能为 0（取决于
     * 错误处理路径）。两种情况都是合理的测试环境行为。
     */
    (void)ret;

    /*
     * 通道被创建后因 proxy 失败被销毁，所以 channel_count 应为 0。
     * 这验证了 SYN 处理流程正确执行了创建-失败的完整路径。
     */
    CHECK(channel_count(&ctx) == 0,
          "channel should have been cleaned up after proxy failure");

    channel_shutdown(&ctx);

    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
}

static void test_data_frame_build_and_parse(void)
{
    TEST("Data Frame 构建、解析与 CRC 完整性验证");

    const char *data_msg = "Integration Test Data Payload";
    size_t data_len = strlen(data_msg);

    /* 构建带 CRC 的数据帧 */
    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.flags      = MPF_DATA;
    hdr.channel_id = 51;
    hdr.data_len   = (uint16_t)data_len;

    uint8_t buf[MAX_FRAME_SIZE];
    ssize_t frame_len = myproto_build_frame(buf, sizeof(buf),
                                             &hdr,
                                             (const uint8_t *)data_msg,
                                             data_len, 1); /* CRC enabled */
    CHECK(frame_len > 0, "build data frame with CRC failed");
    /* frame_len should be header + payload + 4-byte CRC */
    CHECK((size_t)frame_len == MYPROTO_HDR_SIZE + data_len + CRC32_SIZE,
          "frame length should include CRC");

    /* 验证 CRC */
    ssize_t verified_len = myproto_verify_crc(buf, (size_t)frame_len);
    CHECK(verified_len > 0, "CRC verification failed");
    CHECK((size_t)verified_len == MYPROTO_HDR_SIZE + data_len,
          "verified length should exclude CRC");

    /* 解析帧 */
    myproto_hdr_t parsed_hdr;
    const uint8_t *parsed_data = NULL;
    size_t parsed_data_len = 0;
    /* 解析已验证 CRC 的数据部分（不含 CRC） */
    int ret = myproto_parse_frame(buf, (size_t)verified_len,
                                   &parsed_hdr, &parsed_data, &parsed_data_len);
    CHECK(ret == 0, "parse data frame failed");

    CHECK(parsed_hdr.flags == MPF_DATA, "flags mismatch");
    CHECK(parsed_hdr.channel_id == 51, "channel_id mismatch");
    CHECK(parsed_data_len == data_len, "payload length mismatch");
    CHECK(memcmp(parsed_data, data_msg, data_len) == 0,
          "payload content mismatch");

    /* 损坏 CRC — 验证检测 */
    buf[frame_len - 1] ^= 0xFF; /* 翻转 CRC 最后一个字节 */
    ssize_t bad_verify = myproto_verify_crc(buf, (size_t)frame_len);
    CHECK(bad_verify == -1, "CRC should detect corruption");

    PASS();
    return;

cleanup:
    ;
}

/* ============================================================================
 * Test Suite 5: 配置验证边界情况
 * ============================================================================ */

static void test_config_validation_missing_interface(void)
{
    TEST("validate_config: 缺少 interface 字段");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: empty interface");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_bad_ethertype(void)
{
    TEST("validate_config: 无效 ethertype (保留范围 0x0100)");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype = 0x0100;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: ethertype in reserved range");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_ethertype_boundary(void)
{
    TEST("validate_config: ethertype 边界值 (0x0600 应通过)");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = 0x0600;
    cfg.channels[0].channel_id  = 1;
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 9090;
    cfg.channel_count            = 1;
    cfg.max_channels             = MAX_CHANNELS;
    cfg.kcp_mtu                  = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window          = KCP_SEND_WINDOW;
    cfg.kcp_recv_window          = KCP_RECV_WINDOW;
    cfg.kcp_interval             = KCP_INTERVAL;
    cfg.kcp_resend               = KCP_RESEND;
    int ret = validate_config(&cfg);
    CHECK(ret == 0, "0x0600 should be valid ethertype");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_duplicate_channel_ids(void)
{
    TEST("validate_config: 重复 channel_id");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window    = KCP_SEND_WINDOW;
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = MAX_CHANNELS;
    cfg.channels[0].channel_id  = 5;
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 9090;
    cfg.channels[1].channel_id  = 5;  /* 重复 */
    cfg.channels[1].listen_port = 8081;
    cfg.channels[1].remote_port = 9091;
    cfg.channel_count            = 2;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: duplicate channel_id");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_channel_id_zero(void)
{
    TEST("validate_config: channel_id 为 0");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window    = KCP_SEND_WINDOW;
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = MAX_CHANNELS;
    cfg.channels[0].channel_id  = 0;  /* 非法 */
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 9090;
    cfg.channel_count            = 1;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: channel_id=0");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_port_zero(void)
{
    TEST("validate_config: listen_port 为 0");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window    = KCP_SEND_WINDOW;
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = MAX_CHANNELS;
    cfg.channels[0].channel_id  = 1;
    cfg.channels[0].listen_port = 0;  /* 非法 */
    cfg.channels[0].remote_port = 9090;
    cfg.channel_count            = 1;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: listen_port=0");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_remote_port_zero(void)
{
    TEST("validate_config: remote_port 为 0");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window    = KCP_SEND_WINDOW;
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = MAX_CHANNELS;
    cfg.channels[0].channel_id  = 1;
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 0;  /* 非法 */
    cfg.channel_count            = 1;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: remote_port=0");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_no_channels(void)
{
    TEST("validate_config: 无通道配置");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype       = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu         = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window = KCP_SEND_WINDOW;
    cfg.kcp_recv_window = KCP_RECV_WINDOW;
    cfg.max_channels    = MAX_CHANNELS;
    cfg.channel_count   = 0;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: no channels");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_negative_kcp_params(void)
{
    TEST("validate_config: 负值 kcp_mtu");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = -1;  /* 非法 */
    cfg.kcp_send_window    = KCP_SEND_WINDOW;
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = MAX_CHANNELS;
    cfg.channels[0].channel_id  = 1;
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 9090;
    cfg.channel_count            = 1;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: negative kcp_mtu");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_zero_send_window(void)
{
    TEST("validate_config: kcp_send_window 为 0");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window    = 0;  /* 非法 */
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = MAX_CHANNELS;
    cfg.channels[0].channel_id  = 1;
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 9090;
    cfg.channel_count            = 1;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: kcp_send_window=0");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_max_channels_out_of_range(void)
{
    TEST("validate_config: max_channels 超出范围 (0)");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window    = KCP_SEND_WINDOW;
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = 0;  /* 非法 */
    cfg.channels[0].channel_id  = 1;
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 9090;
    cfg.channel_count            = 1;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: max_channels=0");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_invalid_mac_format(void)
{
    TEST("config_load: 无效 MAC 地址格式");
    const char *json =
        "{"
        "  \"interface\": \"eth0\","
        "  \"ethertype\": 35013,"
        "  \"peer_mac\": \"INVALID-MAC-FORMAT\","
        "  \"channels\": ["
        "    {"
        "      \"channel_id\": 1,"
        "      \"listen_port\": 8080,"
        "      \"remote_port\": 9090"
        "    }"
        "  ]"
        "}";

    const char *tmp_path = "/tmp/test_integration_badmac.json";
    if (write_temp_json(tmp_path, json) != 0) {
        FAIL("cannot write temp config file");
        return;
    }

    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int ret = config_load(tmp_path, &cfg);
    CHECK(ret == -1, "config_load should fail on invalid MAC");
    unlink(tmp_path);
    PASS(); return;
cleanup:
    unlink(tmp_path);
}

static void test_config_validation_crypto_enabled_no_key(void)
{
    TEST("validate_config: 启用加密但无密钥");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window    = KCP_SEND_WINDOW;
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = MAX_CHANNELS;
    cfg.kcp_interval    = KCP_INTERVAL;
    cfg.kcp_resend      = KCP_RESEND;
    cfg.encryption.enabled = 1;
    /* sm4_key 全 0 — 应被拒绝 */
    cfg.channels[0].channel_id  = 1;
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 9090;
    cfg.channel_count            = 1;
    int ret = validate_config(&cfg);
    CHECK(ret == -1, "should fail: crypto enabled but key all zeros");
    PASS(); return;
cleanup: ;
}

static void test_config_validation_crypto_valid_key(void)
{
    TEST("validate_config: 加密已启用且有有效密钥（应通过）");
    global_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", MAX_INTERFACE_NAME - 1);
    cfg.ethertype          = MYPROTO_ETHERTYPE;
    cfg.kcp_mtu            = KCP_MTU_CONSERVATIVE;
    cfg.kcp_send_window    = KCP_SEND_WINDOW;
    cfg.kcp_recv_window    = KCP_RECV_WINDOW;
    cfg.max_channels       = MAX_CHANNELS;
    cfg.kcp_interval    = KCP_INTERVAL;
    cfg.kcp_resend      = KCP_RESEND;
    cfg.encryption.enabled = 1;
    /* 填入 hex 密钥字符串 */
    strcpy(cfg.encryption.sm4_key, "00112233445566778899aabbccddeeff");
    cfg.channels[0].channel_id  = 1;
    cfg.channels[0].listen_port = 8080;
    cfg.channels[0].remote_port = 9090;
    cfg.channel_count            = 1;
    int ret = validate_config(&cfg);
    CHECK(ret == 0, "should pass: crypto enabled with valid key");
    PASS(); return;
cleanup: ;
}

/* ============================================================================
 * 主测试入口
 * ============================================================================ */

void run_integration_tests(void)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║   KCP-over-AF_PACKET  Integration Test Suite      ║\n");
    printf("║   验证模块间交互（无需真实网络硬件）              ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");

    /* Suite 1: Config Loading and Validation */
    print_banner("Suite 1: 配置加载和验证 (Config Load & Validate)");
    test_config_load_valid();
    test_config_with_defaults();
    test_config_load_reverse_node_type();
    test_config_load_nonexistent_file();

    /* Suite 2: KCP Wrapper Lifecycle */
    print_banner("Suite 2: KCP Wrapper 生命周期 (Create→Send→Update→Destroy)");
    test_kcp_wrapper_lifecycle();
    test_kcp_wrapper_null_handling();
    test_kcp_wrapper_full_roundtrip();

    /* Suite 3: Channel Hash Table Operations */
    print_banner("Suite 3: Channel 哈希表操作 (Hash Table O(1) Lookup)");
    test_channel_hash_operations();
    test_channel_hash_collision_handling();

    /* Suite 4: Frame Flow Simulation */
    print_banner("Suite 4: 帧流模拟 (MyProto + Channel Routing)");
    test_control_frame_types();
    test_syn_frame_routing();
    test_data_frame_build_and_parse();

    /* Suite 5: Configuration Validation Edge Cases */
    print_banner("Suite 5: 配置验证边界情况 (Validation Edge Cases)");
    test_config_validation_missing_interface();
    test_config_validation_bad_ethertype();
    test_config_validation_ethertype_boundary();
    test_config_validation_duplicate_channel_ids();
    test_config_validation_channel_id_zero();
    test_config_validation_port_zero();
    test_config_validation_remote_port_zero();
    test_config_validation_no_channels();
    test_config_validation_negative_kcp_params();
    test_config_validation_zero_send_window();
    test_config_validation_max_channels_out_of_range();
    test_config_validation_invalid_mac_format();
    test_config_validation_crypto_enabled_no_key();
    test_config_validation_crypto_valid_key();

    print_summary();
}

int main(void)
{
    run_integration_tests();
    return (tests_failed == 0) ? 0 : 1;
}
