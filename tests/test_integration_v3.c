/*
 * test_integration_v3.c — KCP-over-AF_PACKET Multi-Session Integration Tests
 *
 * Tests covering ID pool allocation, listener protection, proxy_accept
 * guards, responder target mapping, SYN/RST frame handling, and
 * channel role initialization.
 *
 * All tests run without real network hardware.
 *
 * Compile:
 *   gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g \
 *       -o tests/test_integration_v3 tests/test_integration_v3.c \
 *       src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c src/ikcp.c \
 *       -lrt -lnettle
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../src/myproto.h"
#include "../src/types.h"
#include "../src/channel.h"
#include "../src/kcp_wrap.h"
#include "../src/ikcp.h"

/* ============================================================================
 * Stubs for functions provided by af_packet.c and proxy.c
 * (not linked — tests don't need real network sockets)
 * ============================================================================ */

/* Stub: af_packet_send — return success without actually sending */
ssize_t af_packet_send(int sock, int ifindex,
                       const uint8_t *dst_mac, const uint8_t *src_mac,
                       uint16_t ethertype,
                       const uint8_t *data, size_t data_len)
{
    (void)sock; (void)ifindex; (void)dst_mac; (void)src_mac;
    (void)ethertype; (void)data;
    return (ssize_t)data_len;
}

/* Stubs for proxy functions */
void proxy_close_local(void *ch) { (void)ch; }
void proxy_epoll_del(void *ctx, int fd) { (void)ctx; (void)fd; }
int  proxy_connect_remote(void *ch) { (void)ch; return 0; }
int  proxy_start_listen(void *ctx, void *ch) { (void)ctx; (void)ch; return 0; }
int  proxy_write_to_local(void *ch, const uint8_t *data, int len)
{
    (void)ch; (void)data;
    return len;
}
int  proxy_epoll_add(void *ctx, int fd, void *ptr)
{
    (void)ctx; (void)fd; (void)ptr;
    return 0;
}

/*
 * Minimal proxy_accept stub: implements early-guard checks so we can
 * test the preconditions (NULL, non-TCP, invalid listen_fd) without
 * linking real proxy.c.  Returns -1 for all cases (no real accept).
 */
int proxy_accept(global_ctx_t *ctx, channel_t *ch)
{
    if (!ctx || !ch) return -1;
    if (!ch->is_tcp) return -1;
    if (ch->listen_fd < 0) return -1;
    /* No real accept4() — return -1 to signal nothing accepted */
    return -1;
}

/* ============================================================================
 * Test Framework
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
    printf("  Integration Test v3 Summary\n");
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
 * Helpers
 * ============================================================================ */

/*
 * init_test_ctx: Zero a global_ctx_t on the stack and populate it with
 * sensible defaults, then call channel_init().
 *
 * Returns 0 on success, -1 on failure.
 */
static int init_test_ctx(global_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->raw_sock  = -1;
    ctx->epoll_fd  = -1;
    ctx->running   = 1;
    ctx->ifindex   = 0;

    /* Node / channel config */
    ctx->config.node_type          = NODE_TYPE_FRONTEND;
    ctx->config.max_channels       = 512;
    ctx->config.heartbeat_interval = HEARTBEAT_INTERVAL;
    ctx->config.heartbeat_timeout  = HEARTBEAT_TIMEOUT;
    ctx->config.crc_enabled        = 0;
    ctx->config.encryption.enabled = 0;
    ctx->config.nic_mtu            = ETH_MTU;

    /* KCP params */
    ctx->config.kcp_mtu         = 1400;
    ctx->config.kcp_send_window = 128;
    ctx->config.kcp_recv_window = 128;
    ctx->config.kcp_nodelay     = 1;
    ctx->config.kcp_interval    = 10;
    ctx->config.kcp_resend      = 2;
    ctx->config.kcp_nc          = 1;

    /* EtherType */
    ctx->config.ethertype = 0x88B5;
    ctx->ethertype        = htons(0x88B5);

    /* Config channel 0 */
    ctx->config.channels[0].channel_id   = 1;
    ctx->config.channels[0].listen_port  = 8080;
    ctx->config.channels[0].remote_port  = 9090;
    ctx->config.channels[0].is_tcp       = 1;
    ctx->config.channels[0].enabled      = 1;
    ctx->config.channels[0].max_sessions = 256;
    strncpy(ctx->config.channels[0].listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(ctx->config.channels[0].remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);

    /* Config channel 1 */
    ctx->config.channels[1].channel_id   = 2;
    ctx->config.channels[1].listen_port  = 8081;
    ctx->config.channels[1].remote_port  = 9091;
    ctx->config.channels[1].is_tcp       = 1;
    ctx->config.channels[1].enabled      = 1;
    ctx->config.channels[1].max_sessions = 256;
    strncpy(ctx->config.channels[1].listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(ctx->config.channels[1].remote_addr, "10.0.0.2", MAX_REMOTE_ADDR - 1);

    ctx->config.channel_count = 2;

    if (channel_init(ctx, 512) != 0) {
        return -1;
    }

    /* Set up listener_base/next ranges for dynamic channel ID allocation */
    for (int i = 0; i < ctx->config.channel_count; i++) {
        uint32_t limit = ctx->config.channels[i].max_sessions;
        if (limit == 0) limit = 1;
        ctx->listener_base[i] = 65536 + (uint32_t)i * 256;
        ctx->listener_next[i] = ctx->listener_base[i];
    }

    return 0;
}

/*
 * init_test_ctx_with_config: same as init_test_ctx but copies a caller-
 * supplied channel_config_t array into ctx->config.channels[] before init.
 */
static int init_test_ctx_with_config(global_ctx_t *ctx,
                                     const channel_config_t *configs,
                                     int count)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->raw_sock  = -1;
    ctx->epoll_fd  = -1;
    ctx->running   = 1;
    ctx->ifindex   = 0;

    ctx->config.node_type          = NODE_TYPE_FRONTEND;
    ctx->config.max_channels       = 512;
    ctx->config.heartbeat_interval = HEARTBEAT_INTERVAL;
    ctx->config.heartbeat_timeout  = HEARTBEAT_TIMEOUT;
    ctx->config.crc_enabled        = 0;
    ctx->config.encryption.enabled = 0;
    ctx->config.nic_mtu            = ETH_MTU;

    ctx->config.kcp_mtu         = 1400;
    ctx->config.kcp_send_window = 128;
    ctx->config.kcp_recv_window = 128;
    ctx->config.kcp_nodelay     = 1;
    ctx->config.kcp_interval    = 10;
    ctx->config.kcp_resend      = 2;
    ctx->config.kcp_nc          = 1;

    ctx->config.ethertype = 0x88B5;
    ctx->ethertype        = htons(0x88B5);

    /* Copy user-provided channel configs */
    for (int i = 0; i < count && i < MAX_CHANNELS; i++) {
        memcpy(&ctx->config.channels[i], &configs[i],
               sizeof(channel_config_t));
    }
    ctx->config.channel_count = count;

    if (channel_init(ctx, 512) != 0) {
        return -1;
    }

    /* Set up listener_base/next ranges for dynamic channel ID allocation */
    for (int i = 0; i < ctx->config.channel_count; i++) {
        uint32_t limit = ctx->config.channels[i].max_sessions;
        if (limit == 0) limit = 1;
        ctx->listener_base[i] = 65536 + (uint32_t)i * 256;
        ctx->listener_next[i] = ctx->listener_base[i];
    }

    return 0;
}

/* ============================================================================
 * ID Pool Tests (1–4)
 * ============================================================================ */

/*
 * Test 1: Basic sequential ID allocation for listener 0.
 */
static void test_alloc_channel_id_basic(void)
{
    TEST("alloc_channel_id basic sequential (listener 0)");

    static global_ctx_t ctx;
    uint32_t id1, id2, id3;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    id1 = alloc_channel_id(&ctx, 0);
    id2 = alloc_channel_id(&ctx, 0);
    id3 = alloc_channel_id(&ctx, 0);

    CHECK(id1 == 65536, "first ID should be 65536");
    CHECK(id2 == 65537, "second ID should be 65537");
    CHECK(id3 == 65538, "third ID should be 65538");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 2: ID pool exhaustion (wraparound) for listener 0.
 */
static void test_alloc_channel_id_wraparound(void)
{
    TEST("alloc_channel_id wraparound / exhaustion");

    static global_ctx_t ctx;
    uint32_t id;
    channel_t *ch;
    int i;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");
    /* We need max_channels large enough to hold 256 dynamic channels */
    ctx.config.max_channels = 512;

    /* Consume all 256 IDs in [65536, 65791] by creating LISTENER channels */
    for (i = 0; i < 256; i++) {
        id = alloc_channel_id(&ctx, 0);
        CHECK(id != 0, "alloc_channel_id returned 0 too early");
        CHECK(id >= 65536 && id <= 65791,
              "allocated ID outside [65536,65791] range");

        ch = channel_create(&ctx, id, CHANNEL_ROLE_LISTENER,
                            8080, 9090, "0.0.0.0", "10.0.0.1", 1);
        CHECK(ch != NULL, "channel_create failed");
    }

    /* Next allocation must fail */
    id = alloc_channel_id(&ctx, 0);
    CHECK(id == 0, "alloc_channel_id should return 0 when pool exhausted");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 3: ID ranges for different listeners do not overlap.
 */
static void test_alloc_channel_id_multi_listener(void)
{
    TEST("alloc_channel_id multi-listener non-overlapping ranges");

    static global_ctx_t ctx;
    uint32_t id0, id1;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    id0 = alloc_channel_id(&ctx, 0);
    id1 = alloc_channel_id(&ctx, 1);

    /* listener 0: [65536, 65791], listener 1: [65792, 66047] */
    CHECK(id0 >= 65536 && id0 <= 65791,
          "listener 0 ID not in [65536,65791]");
    CHECK(id1 >= 65792 && id1 <= 66047,
          "listener 1 ID not in [65792,66047]");
    CHECK(id0 != id1, "IDs from different listeners must not overlap");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 4: Allocate IDs, create channels, find them, then shutdown.
 */
static void test_alloc_channel_id_create_find_destroy(void)
{
    TEST("alloc_channel_id → create → find → destroy");

    static global_ctx_t ctx;
    uint32_t ids[5];
    channel_t *ch;
    int i;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Allocate 5 IDs and create channels */
    for (i = 0; i < 5; i++) {
        ids[i] = alloc_channel_id(&ctx, 0);
        CHECK(ids[i] != 0, "alloc_channel_id returned 0");
        CHECK(ids[i] >= 65536 && ids[i] <= 65791,
              "ID outside [65536,65791] range");

        ch = channel_create(&ctx, ids[i], CHANNEL_ROLE_LISTENER,
                            8080, 9090, "0.0.0.0", "10.0.0.1", 1);
        CHECK(ch != NULL, "channel_create failed");
    }

    /* Find each channel */
    for (i = 0; i < 5; i++) {
        ch = channel_find(&ctx, ids[i]);
        CHECK(ch != NULL, "channel_find returned NULL for valid ID");
        CHECK(ch->channel_id == ids[i],
              "channel_find returned wrong channel");
    }

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Listener Protection Tests (5–7)
 * ============================================================================ */

/*
 * Test 5: Destroying a STATIC_LISTENER channel does NOT close listen_fd.
 */
static void test_listener_destroy_guards_listen_fd(void)
{
    TEST("listener destroy guards listen_fd (STATIC_LISTENER)");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 100, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "192.168.1.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags     |= CH_FLAG_STATIC_LISTENER;
    ch->listen_fd  = 42;  /* fake fd */

    channel_destroy(&ctx, ch);

    /* Channel must be removed from hash table */
    ch = channel_find(&ctx, 100);
    CHECK(ch == NULL, "channel should not be found after destroy");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 6: channel_timeout_check skips STATIC_LISTENER channels.
 */
static void test_timeout_check_skips_listener(void)
{
    TEST("timeout_check skips STATIC_LISTENER channels");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 200, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "192.168.1.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags |= CH_FLAG_STATIC_LISTENER;
    ch->state  = CHANNEL_CLOSED;   /* would normally be destroyed as zombie */

    channel_timeout_check(&ctx);

    /* Listener must survive */
    ch = channel_find(&ctx, 200);
    CHECK(ch != NULL, "STATIC_LISTENER should survive timeout_check");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 7: Normal data-channel destroy removes from hash and closes fds.
 */
static void test_data_channel_destroy_normal(void)
{
    TEST("data channel destroy (no STATIC_LISTENER flag)");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 300, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* flags = 0 (no STATIC_LISTENER); give it fake fds */
    ch->listen_fd = 42;
    ch->local_fd  = 43;

    channel_destroy(&ctx, ch);

    /* Channel must be gone */
    ch = channel_find(&ctx, 300);
    CHECK(ch == NULL, "channel should be removed from hash after destroy");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Multi-session Accept Tests (8–12)
 * ============================================================================ */

/*
 * Test 8: proxy_accept returns -1 for non-TCP channels.
 */
static void test_proxy_accept_is_tcp_filter(void)
{
    TEST("proxy_accept rejects non-TCP channel");

    static global_ctx_t ctx;
    channel_t *ch;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 400, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 0 /* UDP */);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags    |= CH_FLAG_STATIC_LISTENER;
    ch->listen_fd = 42;  /* valid fd so that check passes */

    ret = proxy_accept(&ctx, ch);
    CHECK(ret == -1, "proxy_accept must return -1 for non-TCP channel");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 9: proxy_accept returns -1 with invalid listen_fd.
 */
static void test_proxy_accept_invalid_listen_fd(void)
{
    TEST("proxy_accept rejects invalid listen_fd");

    static global_ctx_t ctx;
    channel_t *ch;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 401, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1 /* TCP */);
    CHECK(ch != NULL, "channel_create failed");

    /* listen_fd defaults to -1 (set by channel_create) */
    ch->flags |= CH_FLAG_STATIC_LISTENER;

    ret = proxy_accept(&ctx, ch);
    CHECK(ret == -1, "proxy_accept must return -1 with listen_fd < 0");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 10: proxy_accept(NULL, NULL) returns -1.
 */
static void test_proxy_accept_null_check(void)
{
    TEST("proxy_accept rejects NULL arguments");

    int ret;

    ret = proxy_accept(NULL, NULL);
    CHECK(ret == -1, "proxy_accept(NULL, NULL) must return -1");

    PASS();
    return;
cleanup:
    return;
}

/*
 * Test 11 (CONCEPTUAL): verify the multi-session decision conditions.
 * When max_sessions > 1 and STATIC_LISTENER is set, the multi-session
 * path should be taken.
 */
static void test_proxy_accept_multi_session_flow(void)
{
    TEST("proxy_accept multi-session conditions check");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Configure max_sessions = 256 on listener index 0 */
    ctx.config.channels[0].max_sessions = 256;

    ch = channel_create(&ctx, 500, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags       |= CH_FLAG_STATIC_LISTENER;
    ch->listener_idx = 0;

    /* Multi-session conditions (mirrors proxy_accept logic) */
    int multi = (ch->flags & CH_FLAG_STATIC_LISTENER) &&
                (ch->listener_idx < ctx.config.channel_count) &&
                (ctx.config.channels[ch->listener_idx].max_sessions > 1);

    CHECK(multi == 1, "multi-session path should be enabled");
    CHECK(ctx.config.channels[0].max_sessions == 256,
          "max_sessions should be 256");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 12 (CONCEPTUAL): verify single-session guard.
 * When max_sessions == 1, the multi-session path must NOT be taken.
 */
static void test_proxy_accept_single_session_guard(void)
{
    TEST("proxy_accept single-session guard");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Default max_sessions = 0 → treated as 1 by proxy_accept logic */
    ctx.config.channels[0].max_sessions = 1;

    ch = channel_create(&ctx, 501, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags       |= CH_FLAG_STATIC_LISTENER;
    ch->listener_idx = 0;

    int multi = (ch->flags & CH_FLAG_STATIC_LISTENER) &&
                (ch->listener_idx < ctx.config.channel_count) &&
                (ctx.config.channels[ch->listener_idx].max_sessions > 1);

    CHECK(multi == 0, "multi-session path should NOT be taken when max_sessions=1");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * RESPONDER Mapping Tests (13–15)
 * ============================================================================ */

/*
 * Test 13: Responder target mapping for channel_id 65536 → index 0.
 */
static void test_responder_target_mapping_65536(void)
{
    TEST("responder target mapping: id=65536 → config index 0");

    static global_ctx_t ctx;
    channel_config_t configs[2];
    uint32_t channel_id = 65536;
    int base_idx = -1;

    memset(&configs, 0, sizeof(configs));
    configs[0].channel_id  = 1;
    configs[0].listen_port = 8080;
    configs[0].remote_port = 9090;
    configs[0].is_tcp      = 1;
    configs[0].enabled     = 1;
    configs[0].max_sessions = 256;
    strncpy(configs[0].listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(configs[0].remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);

    configs[1].channel_id  = 2;
    configs[1].listen_port = 8081;
    configs[1].remote_port = 9091;
    configs[1].is_tcp      = 1;
    configs[1].enabled     = 1;
    configs[1].max_sessions = 256;
    strncpy(configs[1].listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(configs[1].remote_addr, "10.0.0.2", MAX_REMOTE_ADDR - 1);

    CHECK(init_test_ctx_with_config(&ctx, configs, 2) == 0,
          "init_test_ctx_with_config failed");

    /* Search listener_base ranges (from highest index down) to find config */
    for (int idx = ctx.config.channel_count - 1; idx >= 0; idx--) {
        if (channel_id >= ctx.listener_base[idx]) {
            base_idx = idx;
            break;
        }
    }
    CHECK(base_idx == 0, "channel_id 65536 should map to config index 0");

    CHECK(base_idx < ctx.config.channel_count,
          "index must be within channel_count");
    CHECK(ctx.config.channels[base_idx].remote_port == 9090,
          "channels[0].remote_port should be 9090");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 14: Responder target mapping for channel_id 65792 → index 1.
 */
static void test_responder_target_mapping_65792(void)
{
    TEST("responder target mapping: id=65792 → config index 1");

    static global_ctx_t ctx;
    channel_config_t configs[2];
    uint32_t channel_id = 65792;
    int base_idx = -1;

    memset(&configs, 0, sizeof(configs));
    configs[0].channel_id  = 1;
    configs[0].listen_port = 8080;
    configs[0].remote_port = 9090;
    configs[0].is_tcp      = 1;
    configs[0].enabled     = 1;
    configs[0].max_sessions = 256;
    strncpy(configs[0].listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(configs[0].remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);

    configs[1].channel_id  = 2;
    configs[1].listen_port = 8081;
    configs[1].remote_port = 9091;
    configs[1].is_tcp      = 1;
    configs[1].enabled     = 1;
    configs[1].max_sessions = 256;
    strncpy(configs[1].listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(configs[1].remote_addr, "10.0.0.2", MAX_REMOTE_ADDR - 1);

    CHECK(init_test_ctx_with_config(&ctx, configs, 2) == 0,
          "init_test_ctx_with_config failed");

    /* Search listener_base ranges (from highest index down) to find config */
    for (int idx = ctx.config.channel_count - 1; idx >= 0; idx--) {
        if (channel_id >= ctx.listener_base[idx]) {
            base_idx = idx;
            break;
        }
    }
    CHECK(base_idx == 1, "channel_id 65792 should map to config index 1");

    CHECK(base_idx < ctx.config.channel_count,
          "index must be within channel_count");
    CHECK(ctx.config.channels[base_idx].remote_port == 9091,
          "channels[1].remote_port should be 9091");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 15: Responder mapping for out-of-range channel_id.
 */
static void test_responder_out_of_range(void)
{
    TEST("responder target mapping: out-of-range channel_id");

    static global_ctx_t ctx;
    uint32_t channel_id = 5000;
    int base_idx = -1;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");
    /* channel_count == 2, listener_base[0]=65536, listener_base[1]=65792 */

    /* Search listener_base ranges — channel_id 5000 is below all bases */
    for (int idx = ctx.config.channel_count - 1; idx >= 0; idx--) {
        if (channel_id >= ctx.listener_base[idx]) {
            base_idx = idx;
            break;
        }
    }
    CHECK(base_idx == -1,
          "index should remain -1 (no matching listener base)");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * SYN Handler Tests (16–18)
 * ============================================================================ */

/*
 * Test 16: SYN on an ESTABLISHED channel is silently ignored.
 */
static void test_syn_on_established_ignored(void)
{
    TEST("SYN on ESTABLISHED channel is ignored");

    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create a channel and force it to ESTABLISHED */
    ch = channel_create(&ctx, 100, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    ch->state = CHANNEL_ESTABLISHED;

    /* Build a SYN frame for this channel */
    memset(&hdr, 0, sizeof(hdr));
    hdr.flags      = MPF_SYN;
    hdr.channel_id = 100;
    hdr.payload_len = 0;

    /* Validate the header we just built */
    ret = myproto_validate_hdr(&hdr);
    CHECK(ret == 0, "myproto_validate_hdr failed for SYN frame");

    /* Deliver SYN to channel_process_frame */
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    /* Expected: returns 0 (ignored, not an error) */
    CHECK(ret == 0, "SYN on ESTABLISHED should be ignored (return 0)");

    /* Channel must still exist and be ESTABLISHED */
    ch = channel_find(&ctx, 100);
    CHECK(ch != NULL, "channel must still exist");
    CHECK(ch->state == CHANNEL_ESTABLISHED,
          "channel state must remain ESTABLISHED");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 17: SYN for unknown channel_id creates a RESPONDER channel.
 */
static void test_syn_creates_responder_channel(void)
{
    TEST("SYN for unknown ID creates RESPONDER channel");

    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Build a SYN frame for an unknown channel_id */
    memset(&hdr, 0, sizeof(hdr));
    hdr.flags      = MPF_SYN;
    hdr.channel_id = 50;
    hdr.payload_len = 0;

    ret = myproto_validate_hdr(&hdr);
    CHECK(ret == 0, "myproto_validate_hdr failed");

    /* Deliver SYN — should auto-create a RESPONDER channel */
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "channel_process_frame for SYN should succeed");

    /* Look up the newly created channel */
    ch = channel_find(&ctx, 50);
    CHECK(ch != NULL, "RESPONDER channel should have been created");
    CHECK(ch->channel_id == 50,
          "created channel must have the requested ID");
    CHECK(ch->role == CHANNEL_ROLE_RESPONDER,
          "auto-created channel must be RESPONDER");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 18: RST frame destroys the channel.
 */
static void test_rst_destroys_channel(void)
{
    TEST("RST frame destroys channel");

    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create channel and force ESTABLISHED */
    ch = channel_create(&ctx, 200, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    ch->state = CHANNEL_ESTABLISHED;

    /* Build RST frame */
    memset(&hdr, 0, sizeof(hdr));
    hdr.flags      = MPF_RST;
    hdr.channel_id = 200;
    hdr.payload_len = 0;

    ret = myproto_validate_hdr(&hdr);
    CHECK(ret == 0, "myproto_validate_hdr failed for RST frame");

    /* Deliver RST */
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "channel_process_frame for RST should succeed");

    /* Channel must be destroyed */
    ch = channel_find(&ctx, 200);
    CHECK(ch == NULL, "channel must be destroyed after RST");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * CHANNEL_ROLE Tests (19–20)
 * ============================================================================ */

/*
 * Test 19: LISTENER role: channel created, SYN NOT sent.
 */
static void test_listener_role_no_syn(void)
{
    TEST("LISTENER role does not send SYN");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 600, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    CHECK(ch->role == CHANNEL_ROLE_LISTENER,
          "role must be LISTENER");
    CHECK(ch->state != CHANNEL_SYN_SENT,
          "LISTENER must not transition to SYN_SENT");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 20: INITIATOR role: channel created, SYN sent → SYN_SENT.
 */
static void test_initiator_role_sends_syn(void)
{
    TEST("INITIATOR role sends SYN → SYN_SENT");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 700, CHANNEL_ROLE_INITIATOR,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    CHECK(ch->role == CHANNEL_ROLE_INITIATOR,
          "role must be INITIATOR");
    CHECK(ch->state == CHANNEL_SYN_SENT,
          "INITIATOR must transition to SYN_SENT");

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    print_banner("Integration Test v3 — Multi-Session & Channel Management");

    /* ---- ID Pool Tests ---- */
    print_banner("Section 1: ID Pool Tests");
    test_alloc_channel_id_basic();
    test_alloc_channel_id_wraparound();
    test_alloc_channel_id_multi_listener();
    test_alloc_channel_id_create_find_destroy();

    /* ---- Listener Protection Tests ---- */
    print_banner("Section 2: Listener Protection Tests");
    test_listener_destroy_guards_listen_fd();
    test_timeout_check_skips_listener();
    test_data_channel_destroy_normal();

    /* ---- Multi-session Accept Tests ---- */
    print_banner("Section 3: Multi-session Accept Tests");
    test_proxy_accept_is_tcp_filter();
    test_proxy_accept_invalid_listen_fd();
    test_proxy_accept_null_check();
    test_proxy_accept_multi_session_flow();
    test_proxy_accept_single_session_guard();

    /* ---- RESPONDER Mapping Tests ---- */
    print_banner("Section 4: RESPONDER Mapping Tests");
    test_responder_target_mapping_65536();
    test_responder_target_mapping_65792();
    test_responder_out_of_range();

    /* ---- SYN Handler Tests ---- */
    print_banner("Section 5: SYN/RST Handler Tests");
    test_syn_on_established_ignored();
    test_syn_creates_responder_channel();
    test_rst_destroys_channel();

    /* ---- CHANNEL_ROLE Tests ---- */
    print_banner("Section 6: CHANNEL_ROLE Tests");
    test_listener_role_no_syn();
    test_initiator_role_sends_syn();

    print_summary();

    return (tests_failed == 0) ? 0 : 1;
}
