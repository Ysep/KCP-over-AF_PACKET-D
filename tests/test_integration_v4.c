/*
 * test_integration_v4.c — KCP-over-AF_PACKET Integration Tests: Part II/III/ctl
 *
 * Tests covering channel_config_changed, channel_update_config,
 * alloc_channel_id edge cases, RESPONDER reverse scan, channel flags
 * (STATIC_LISTENER / RELOAD_MARKED), HEARTBEAT_CH_ID size assertion,
 * LISTENER role initialization, and ctl add/delete lifecycle.
 *
 * All tests run without real network hardware.
 *
 * Compile:
 *   gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g \
 *       -o tests/test_integration_v4 tests/test_integration_v4.c \
 *       src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c src/ikcp.c \
 *       -lrt -lnettle
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "../src/types.h"
#include "../src/channel.h"
#include "../src/myproto.h"
#include "../src/proxy.h"

/* ============================================================================
 * Stubs for functions provided by af_packet.c and proxy.c
 * (not linked — tests don't need real network sockets)
 * ============================================================================ */

/* af_packet.c stubs */
ssize_t af_packet_send(int sock, int ifindex,
                       const uint8_t dst_mac[ETH_MAC_ADDR_LEN],
                       const uint8_t src_mac[ETH_MAC_ADDR_LEN],
                       uint16_t ethertype,
                       const uint8_t *payload, size_t payload_len)
{
    (void)sock; (void)ifindex; (void)dst_mac; (void)src_mac;
    (void)ethertype; (void)payload;
    return (ssize_t)payload_len;
}

void af_packet_close(int sock)
{
    (void)sock;
}

/* proxy.c stubs */
void proxy_close_local(channel_t *ch)
{
    if (ch) ch->local_fd = -1;
}

int proxy_epoll_del(global_ctx_t *ctx, int fd)
{
    (void)ctx; (void)fd;
    return 0;
}

int proxy_connect_remote(channel_t *ch)
{
    (void)ch;
    return 0;
}

int proxy_start_listen(global_ctx_t *ctx, channel_t *ch)
{
    (void)ctx;
    if (ch) ch->listen_fd = 55;
    return 0;
}

int proxy_write_to_local(channel_t *ch, const uint8_t *data, int len)
{
    (void)ch; (void)data; (void)len;
    return 0;
}

int proxy_epoll_add(global_ctx_t *ctx, int fd, void *ptr)
{
    (void)ctx; (void)fd; (void)ptr;
    return 0;
}

int proxy_accept(global_ctx_t *ctx, channel_t *ch)
{
    (void)ctx; (void)ch;
    return -1;
}

void proxy_stop_listen(global_ctx_t *ctx, channel_t *ch)
{
    (void)ctx;
    if (ch) ch->listen_fd = -1;
}

int proxy_port_probe(const char *addr, uint16_t port, int is_tcp)
{
    (void)addr; (void)port; (void)is_tcp;
    return 0;
}

int proxy_port_conflict(global_ctx_t *ctx, const char *listen_addr,
                        uint16_t listen_port, uint32_t exclude_id)
{
    (void)ctx; (void)listen_addr; (void)listen_port; (void)exclude_id;
    return 0;
}

/* ============================================================================
 * Test Framework
 * ============================================================================ */

static int tests_run, tests_passed, tests_failed;

#define TEST(name)  do { tests_run++; printf("  [TEST %d] %s ... ", tests_run, name); fflush(stdout); } while(0)
#define PASS()      do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg)   do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)
#define CHECK(cond, msg) do { if(!(cond)){FAIL(msg);goto cleanup;} } while(0)

static void print_banner(const char *title)
{
    printf("\n============================================================\n");
    printf("  %s\n", title);
    printf("============================================================\n");
}

static void print_summary(void)
{
    printf("\n============================================================\n");
    printf("  Integration Test v4 Summary\n");
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

    ctx->config.node_type       = NODE_TYPE_FRONTEND;
    ctx->config.max_channels    = 512;
    ctx->channel_hash_size = 1024;
    ctx->config.ethertype       = 0x88B5;
    ctx->config.kcp_mtu         = 1400;
    ctx->config.kcp_send_window = 128;
    ctx->config.kcp_recv_window = 128;
    ctx->config.kcp_nodelay     = 1;
    ctx->config.kcp_interval    = 10;
    ctx->config.kcp_resend      = 2;
    ctx->config.kcp_nc          = 1;

    /* Config channel 0 */
    ctx->config.channel_count = 2;
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

    if (channel_init(ctx, 512) != 0)
        return -1;

    for (int i = 0; i < ctx->config.channel_count; i++) {
        uint32_t limit = ctx->config.channels[i].max_sessions;
        if (limit == 0) limit = 1;
        ctx->listener_base[i] = 65536 + (uint32_t)i * limit;
        ctx->listener_next[i] = ctx->listener_base[i];
    }

    return 0;
}

/*
 * Helper: replicate the RESPONDER reverse-scan logic from
 * channel_process_frame for lookup tests.
 */
static int find_listener_idx_for_id(global_ctx_t *ctx, uint32_t data_id)
{
    for (int idx = ctx->config.channel_count - 1; idx >= 0; idx--) {
        if (data_id >= ctx->listener_base[idx])
            return idx;
    }
    return -1;
}

/* ============================================================================
 * Test 1: channel_config_changed — all 5 fields detected
 * ============================================================================ */
static void test_channel_config_changed_all_fields(void)
{
    TEST("channel_config_changed — all 5 fields");

    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create a listener channel with known values */
    ch = channel_create(&ctx, 100, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* Same config — no change */
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    ret = channel_config_changed(ch, &cfg);
    CHECK(ret == 0, "identical config should return 0 (no change)");

    /* Change listen_port */
    cfg.listen_port = 8081;
    ret = channel_config_changed(ch, &cfg);
    CHECK(ret == 1, "listen_port change should be detected");

    /* Change remote_port */
    cfg.listen_port = 8080;   /* restore */
    cfg.remote_port = 9091;
    ret = channel_config_changed(ch, &cfg);
    CHECK(ret == 1, "remote_port change should be detected");

    /* Change listen_addr */
    cfg.remote_port = 9090;   /* restore */
    strncpy(cfg.listen_addr, "1.2.3.4", MAX_LISTEN_ADDR - 1);
    ret = channel_config_changed(ch, &cfg);
    CHECK(ret == 1, "listen_addr change should be detected");

    /* Change remote_addr */
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);  /* restore */
    strncpy(cfg.remote_addr, "5.6.7.8", MAX_REMOTE_ADDR - 1);
    ret = channel_config_changed(ch, &cfg);
    CHECK(ret == 1, "remote_addr change should be detected");

    /* Change is_tcp */
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);  /* restore */
    cfg.is_tcp = 0;
    ret = channel_config_changed(ch, &cfg);
    CHECK(ret == 1, "is_tcp change should be detected");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 2: channel_config_changed — no changes
 * ============================================================================ */
static void test_channel_config_changed_no_change(void)
{
    TEST("channel_config_changed — no changes");

    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 200, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* Build identical config */
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    ret = channel_config_changed(ch, &cfg);
    CHECK(ret == 0, "identical config must return 0");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 3: channel_update_config — all 5 fields written
 * ============================================================================ */
static void test_channel_update_config_all_fields(void)
{
    TEST("channel_update_config — all 5 fields written");

    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create listener with default values */
    ch = channel_create(&ctx, 300, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* Build new config */
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 9999;
    cfg.remote_port = 8888;
    strncpy(cfg.listen_addr, "1.2.3.4", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "5.6.7.8", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 0;

    channel_update_config(ch, &cfg);

    /* Verify fields */
    CHECK(ch->listen_port == 9999, "listen_port should be 9999");
    CHECK(ch->remote_port == 8888, "remote_port should be 8888");
    CHECK(strcmp(ch->listen_addr, "1.2.3.4") == 0, "listen_addr should be 1.2.3.4");
    CHECK(strcmp(ch->remote_addr, "5.6.7.8") == 0, "remote_addr should be 5.6.7.8");
    CHECK(ch->is_tcp == 0, "is_tcp should be 0");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 4: alloc_channel_id — max_sessions=3 exhaustion
 * ============================================================================ */
static void test_alloc_channel_id_max_sessions_3(void)
{
    TEST("alloc_channel_id — max_sessions=3 exhaustion");

    static global_ctx_t ctx;
    uint32_t id;
    channel_t *dummy_ch[3] = {NULL, NULL, NULL};

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Override max_sessions and reset ID pool */
    ctx.config.channels[0].max_sessions = 3;
    ctx.listener_base[0] = 65536;
    ctx.listener_next[0] = 65536;

    /* Allocate 3 IDs and occupy the hash */
    for (int i = 0; i < 3; i++) {
        id = alloc_channel_id(&ctx, 0);
        CHECK(id != 0, "alloc within limit should succeed");
        CHECK(id >= 65536 && id <= 65538, "ID out of range");

        dummy_ch[i] = channel_create(&ctx, id, CHANNEL_ROLE_RESPONDER,
                                     8080, 9090, "0.0.0.0", "10.0.0.1", 1);
        CHECK(dummy_ch[i] != NULL, "channel_create should succeed");
    }

    /* 4th alloc — must exhaust and return 0 */
    id = alloc_channel_id(&ctx, 0);
    CHECK(id == 0, "4th alloc must return 0 (exhausted)");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 5: alloc_channel_id — DYNAMIC_CHANNEL_BASE threshold
 * ============================================================================ */
static void test_alloc_channel_id_dynamic_base(void)
{
    TEST("alloc_channel_id — DYNAMIC_CHANNEL_BASE threshold");

    static global_ctx_t ctx;
    uint32_t id;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Allocate first ID from listener 0 */
    id = alloc_channel_id(&ctx, 0);
    CHECK(id >= 65536, "first dynamic ID must be >= DYNAMIC_CHANNEL_BASE (65536)");

    /* Allocate first ID from listener 1 — also >= 65536 */
    id = alloc_channel_id(&ctx, 1);
    CHECK(id >= 65536, "listener 1 first dynamic ID must also be >= 65536");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 6: RESPONDER reverse scan for data_id resolution
 * ============================================================================ */
static void test_responder_reverse_scan(void)
{
    TEST("RESPONDER reverse scan for data_id lookup");

    static global_ctx_t ctx;
    int idx;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /*
     * With default init: listener_base[0]=65536, listener_base[1]=65792.
     * The reverse-scan iterates from the last listener to the first.
     */

    /* data_id 65536 — should match listener_base[0] */
    idx = find_listener_idx_for_id(&ctx, 65536);
    CHECK(idx == 0, "65536 should match listener_base[0]");

    /* data_id 65792 — should match listener_base[1] */
    idx = find_listener_idx_for_id(&ctx, 65792);
    CHECK(idx == 1, "65792 should match listener_base[1]");

    /* data_id 65535 — below DYNAMIC_CHANNEL_BASE, should NOT match */
    idx = find_listener_idx_for_id(&ctx, 65535);
    CHECK(idx == -1, "65535 should NOT match any listener (< 65536)");

    /* data_id 65537 — between base[0] and base[1], reverse scan
     * checks idx=1 first: 65537 >= 65792? No.
     * then idx=0: 65537 >= 65536? Yes → match listener 0 */
    idx = find_listener_idx_for_id(&ctx, 65537);
    CHECK(idx == 0, "65537 should match listener_base[0] via reverse scan");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 7: CH_FLAG_RELOAD_MARKED + STATIC_LISTENER
 * ============================================================================ */
static void test_channel_flags_marked_and_static(void)
{
    TEST("CH_FLAG_RELOAD_MARKED + STATIC_LISTENER flags");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create listener with STATIC_LISTENER flag */
    ch = channel_create(&ctx, 400, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    ch->flags |= CH_FLAG_STATIC_LISTENER;
    CHECK(ch->flags & CH_FLAG_STATIC_LISTENER, "STATIC_LISTENER should be set");

    /* Set RELOAD_MARKED */
    ch->flags |= CH_FLAG_RELOAD_MARKED;
    CHECK(ch->flags & CH_FLAG_RELOAD_MARKED, "RELOAD_MARKED should be set");
    CHECK(ch->flags & CH_FLAG_STATIC_LISTENER, "STATIC_LISTENER should still be set");

    /* Clear MARKED flag */
    ch->flags &= ~CH_FLAG_RELOAD_MARKED;
    CHECK(!(ch->flags & CH_FLAG_RELOAD_MARKED), "RELOAD_MARKED should be cleared");
    CHECK(ch->flags & CH_FLAG_STATIC_LISTENER, "STATIC_LISTENER should remain");

    /* Clear STATIC_LISTENER and destroy */
    ch->flags &= ~CH_FLAG_STATIC_LISTENER;
    channel_destroy(&ctx, ch);

    /* Verify channel is gone */
    channel_t *found = channel_find(&ctx, 400);
    CHECK(found == NULL, "channel should be gone after destroy");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 8: HEARTBEAT_CH_ID = 0xFFFFFFFF (was uint16_t, now uint32_t)
 * ============================================================================ */
static void test_heartbeat_ch_id_size(void)
{
    TEST("HEARTBEAT_CH_ID = 0xFFFFFFFF (sizeof == 4)");

    static global_ctx_t ctx;
    channel_t *found;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Verify sizeof — was 2 for uint16_t, now must be 4 for uint32_t */
    CHECK(sizeof(HEARTBEAT_CH_ID) == 4, "sizeof(HEARTBEAT_CH_ID) must be 4 (uint32_t)");

    /* Verify exact value */
    CHECK(HEARTBEAT_CH_ID == 0xFFFFFFFFu, "HEARTBEAT_CH_ID must be 0xFFFFFFFF");

    /* Should not be a real channel */
    found = channel_find(&ctx, HEARTBEAT_CH_ID);
    CHECK(found == NULL, "HEARTBEAT_CH_ID should not resolve to a real channel");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 9: LISTENER role — no SYN sent, state = ESTABLISHED
 * ============================================================================ */
static void test_listener_role_no_syn(void)
{
    TEST("LISTENER role — no SYN sent, state ESTABLISHED");

    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create listener channel */
    ch = channel_create(&ctx, 500, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* State must be ESTABLISHED, NOT SYN_SENT */
    CHECK(ch->state != CHANNEL_SYN_SENT, "LISTENER must not be in SYN_SENT");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "LISTENER must be ESTABLISHED");

    /* Role must be LISTENER */
    CHECK(ch->role == CHANNEL_ROLE_LISTENER, "role must be LISTENER");

    /* Call proxy_start_listen (as main.c would) and verify listen_fd */
    proxy_start_listen(&ctx, ch);
    CHECK(ch->listen_fd == 55, "listen_fd should be set to 55 by stub");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Test 10: ctl lifecycle — add, verify, delete, verify gone
 * ============================================================================ */
static void test_ctl_lifecycle(void)
{
    TEST("ctl lifecycle — add, verify, delete, verify gone");

    static global_ctx_t ctx;
    channel_t *ch, *found;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* ---- Add: ctl-like programmatic flow ---- */
    ch = channel_create(&ctx, 600, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "ctl channel_create failed");

    /* Set network info + flags (typical ctl setup) */
    ch->flags |= CH_FLAG_STATIC_LISTENER;
    proxy_start_listen(&ctx, ch);

    /* Verify it exists */
    found = channel_find(&ctx, 600);
    CHECK(found != NULL, "channel should be found after creation");
    CHECK(found->channel_id == 600, "found channel ID should match");
    CHECK(found->flags & CH_FLAG_STATIC_LISTENER, "STATIC_LISTENER should be set");

    /* ---- Delete: ctl-like deletion flow ---- */
    proxy_stop_listen(&ctx, ch);
    CHECK(ch->listen_fd == -1, "listen_fd should be -1 after stop");

    /* Clear STATIC_LISTENER guard so channel_destroy can proceed */
    ch->flags &= ~CH_FLAG_STATIC_LISTENER;
    channel_destroy(&ctx, ch);

    /* Verify it's gone */
    found = channel_find(&ctx, 600);
    CHECK(found == NULL, "channel should NOT be found after deletion");

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
    print_banner("KCP-over-AF_PACKET Integration Tests v4");
    printf("  Part II: config change detection & update\n");
    printf("  Part III: ID pool, responder scan, flags\n");
    printf("  ctl: add/delete lifecycle\n");

    test_channel_config_changed_all_fields();
    test_channel_config_changed_no_change();
    test_channel_update_config_all_fields();
    test_alloc_channel_id_max_sessions_3();
    test_alloc_channel_id_dynamic_base();
    test_responder_reverse_scan();
    test_channel_flags_marked_and_static();
    test_heartbeat_ch_id_size();
    test_listener_role_no_syn();
    test_ctl_lifecycle();

    print_summary();

    return tests_failed == 0 ? 0 : 1;
}
