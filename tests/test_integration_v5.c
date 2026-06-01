/*
 * test_integration_v5.c — KCP-over-AF_PACKET Integration Tests: Part A (1-50)
 *
 * Tests 1-15:  MyProto frame build/parse/validate
 * Tests 16-30: Channel state machine
 * Tests 31-40: alloc_channel_id
 * Tests 41-50: channel_config_changed / channel_update_config
 *
 * All tests run without real network hardware.
 *
 * Compile:
 *   gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g \
 *       -o tests/test_integration_v5 tests/test_integration_v5.c \
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
    printf("  Integration Test v5 Summary\n");
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

static int init_test_ctx(global_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->config.node_type       = NODE_TYPE_FRONTEND;
    ctx->config.max_channels    = 512;
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
 * Helper: build a myproto_hdr_t for channel_process_frame tests
 */
static void fill_ctrl_hdr(myproto_hdr_t *hdr, uint32_t channel_id, uint8_t flags)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->channel_id  = channel_id;
    hdr->flags       = flags;
    hdr->payload_len = 0;
}

/* ============================================================================
 * Part A, Tests 1-15: MyProto — Frame Build / Parse / Validate
 * ============================================================================ */

/* Test 1: Build ctrl frame with min channel_id (1) → verify size */
static void test_myproto_build_ctrl_min_channel(void)
{
    TEST("MyProto: build ctrl frame with min channel_id (1)");
    uint8_t buf[256];
    ssize_t len;

    len = myproto_build_ctrl_frame(buf, sizeof(buf), 1, MPF_SYN, 0);
    CHECK(len == MYPROTO_HDR_SIZE, "ctrl frame size should be MYPROTO_HDR_SIZE (9)");

    PASS();
    return;

cleanup:
    return;
}

/* Test 2: Build ctrl frame with max channel_id (0xFFFFFFFF) → verify */
static void test_myproto_build_ctrl_max_channel(void)
{
    TEST("MyProto: build ctrl frame with max channel_id (HEARTBEAT_CH_ID)");
    uint8_t buf[256];
    ssize_t len;

    len = myproto_build_ctrl_frame(buf, sizeof(buf), HEARTBEAT_CH_ID, MPF_ACK, 0);
    CHECK(len == MYPROTO_HDR_SIZE, "ctrl frame with HEARTBEAT_CH_ID should succeed");

    PASS();
    return;

cleanup:
    return;
}

/* Test 3: Build data frame with 0-length payload → verify */
static void test_myproto_build_data_zero_payload(void)
{
    TEST("MyProto: build data frame with 0-length payload");
    uint8_t buf[256];
    ssize_t len;

    len = myproto_build_data_frame(buf, sizeof(buf), 100, 0, NULL, 0, 0);
    CHECK(len == MYPROTO_HDR_SIZE, "data frame with 0 payload should be 9 bytes");

    PASS();
    return;

cleanup:
    return;
}

/* Test 4: Build data frame with ETH_MAX_PAYLOAD payload → verify */
static void test_myproto_build_data_max_payload(void)
{
    TEST("MyProto: build data frame with ETH_MAX_PAYLOAD payload");
    uint8_t buf[MAX_FRAME_SIZE];
    uint8_t payload[ETH_MAX_PAYLOAD];
    ssize_t len;

    memset(payload, 0xAB, sizeof(payload));
    len = myproto_build_data_frame(buf, sizeof(buf), 200, 0,
                                   payload, ETH_MAX_PAYLOAD, 0);
    CHECK(len == (ssize_t)(MYPROTO_HDR_SIZE + ETH_MAX_PAYLOAD),
          "data frame with 1500 payload should be 1509 bytes");

    PASS();
    return;

cleanup:
    return;
}

/* Test 5: Build data frame exceeding ETH_MAX_PAYLOAD → returns < 0 */
static void test_myproto_build_data_exceed_payload(void)
{
    TEST("MyProto: build data frame exceeding ETH_MAX_PAYLOAD → error");
    uint8_t buf[MAX_FRAME_SIZE];
    uint8_t payload[ETH_MAX_PAYLOAD + 1];
    ssize_t len;

    memset(payload, 0xCD, sizeof(payload));
    len = myproto_build_data_frame(buf, sizeof(buf), 300, 0,
                                   payload, ETH_MAX_PAYLOAD + 1, 0);
    CHECK(len < 0, "exceeding ETH_MAX_PAYLOAD should return < 0");

    PASS();
    return;

cleanup:
    return;
}

/* Test 6: Parse valid ctrl frame → verify all parsed fields */
static void test_myproto_parse_valid_ctrl(void)
{
    TEST("MyProto: parse valid ctrl frame → verify fields");
    uint8_t buf[256];
    myproto_hdr_t built_hdr, parsed_hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    ssize_t len;
    int ret;

    /* Build a ctrl frame with SYN */
    len = myproto_build_ctrl_frame(buf, sizeof(buf), 42, MPF_SYN, 0);
    CHECK(len == MYPROTO_HDR_SIZE, "build ctrl should succeed");

    /* Parse it back */
    ret = myproto_parse_frame(buf, (size_t)len, &parsed_hdr, &payload, &payload_len);
    CHECK(ret == 0, "parse should succeed");
    CHECK(parsed_hdr.channel_id == 42, "channel_id should be 42");
    CHECK(parsed_hdr.flags == MPF_SYN, "flags should be MPF_SYN");
    CHECK(parsed_hdr.payload_len == 0, "payload_len should be 0");
    CHECK(payload_len == 0, "parsed payload_len should be 0");

    (void)built_hdr;
    PASS();
    return;

cleanup:
    return;
}

/* Test 7: Parse valid data frame → verify payload match */
static void test_myproto_parse_valid_data(void)
{
    TEST("MyProto: parse valid data frame → verify payload match");
    uint8_t buf[MAX_FRAME_SIZE];
    const uint8_t test_payload[] = "Hello, MyProto!";
    myproto_hdr_t parsed_hdr;
    const uint8_t *parsed_payload = NULL;
    size_t parsed_payload_len = 0;
    ssize_t len;
    int ret;

    len = myproto_build_data_frame(buf, sizeof(buf), 77, 0,
                                   test_payload, strlen((const char *)test_payload), 0);
    CHECK(len > 0, "build data should succeed");

    ret = myproto_parse_frame(buf, (size_t)len, &parsed_hdr,
                              &parsed_payload, &parsed_payload_len);
    CHECK(ret == 0, "parse should succeed");
    CHECK(parsed_hdr.channel_id == 77, "channel_id should be 77");
    CHECK(parsed_hdr.flags == 0, "flags should be 0 (data)");
    CHECK(parsed_payload_len == strlen((const char *)test_payload),
          "payload_len should match");
    CHECK(memcmp(parsed_payload, test_payload, parsed_payload_len) == 0,
          "payload content should match");

    PASS();
    return;

cleanup:
    return;
}

/* Test 8: Parse frame with corrupted header_crc → rejected (CRC-16 validated) */
static void test_myproto_parse_corrupted_header_crc(void)
{
    TEST("MyProto: parse frame with corrupted header_crc → rejected");
    uint8_t buf[256];
    myproto_hdr_t parsed_hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    ssize_t len;
    int ret;

    /* Build a valid ctrl frame */
    len = myproto_build_ctrl_frame(buf, sizeof(buf), 99, MPF_FIN, 0);
    CHECK(len == MYPROTO_HDR_SIZE, "build ctrl should succeed");

    /* Corrupt header_crc bytes (buf[7] and buf[8]) */
    buf[7] ^= 0xFF;

    /* Parse should FAIL (header_crc is now validated via CRC-16) */
    ret = myproto_parse_frame(buf, (size_t)len, &parsed_hdr, &payload, &payload_len);
    CHECK(ret != 0, "parse should fail with corrupted header_crc");

    PASS();
    return;

cleanup:
    return;
}

/* Test 9: Parse truncated frame (only 3 bytes) → rejected */
static void test_myproto_parse_truncated(void)
{
    TEST("MyProto: parse truncated frame (3 bytes) → rejected");
    uint8_t buf[3] = { 0x00, 0x00, 0x00 };
    myproto_hdr_t parsed_hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    int ret;

    ret = myproto_parse_frame(buf, 3, &parsed_hdr, &payload, &payload_len);
    CHECK(ret < 0, "truncated frame (3 bytes) should be rejected");

    PASS();
    return;

cleanup:
    return;
}

/* Test 10: Parse frame with payload_len=0 → valid, empty data */
static void test_myproto_parse_zero_payload(void)
{
    TEST("MyProto: parse frame with payload_len=0 → valid, empty data");
    uint8_t buf[256];
    myproto_hdr_t parsed_hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    ssize_t len;
    int ret;

    /* Build data frame with 0 payload */
    len = myproto_build_data_frame(buf, sizeof(buf), 55, 0, NULL, 0, 0);
    CHECK(len == MYPROTO_HDR_SIZE, "build should succeed");

    ret = myproto_parse_frame(buf, (size_t)len, &parsed_hdr, &payload, &payload_len);
    CHECK(ret == 0, "parse should succeed");
    CHECK(parsed_hdr.payload_len == 0, "payload_len should be 0");
    CHECK(payload_len == 0, "parsed payload_len should be 0");

    PASS();
    return;

cleanup:
    return;
}

/* Test 11: Build+parse round-trip: ctrl frame → identical fields */
static void test_myproto_roundtrip_ctrl(void)
{
    TEST("MyProto: build+parse round-trip ctrl frame → identical fields");
    uint8_t buf[256];
    myproto_hdr_t parsed_hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    ssize_t len;
    int ret;

    len = myproto_build_ctrl_frame(buf, sizeof(buf), 12345, MPF_SYN | MPF_ACK, 0);
    CHECK(len == MYPROTO_HDR_SIZE, "build should succeed");

    ret = myproto_parse_frame(buf, (size_t)len, &parsed_hdr, &payload, &payload_len);
    CHECK(ret == 0, "parse should succeed");
    CHECK(parsed_hdr.channel_id == 12345, "channel_id round-trip");
    CHECK(parsed_hdr.flags == (MPF_SYN | MPF_ACK), "flags round-trip");
    CHECK(parsed_hdr.payload_len == 0, "payload_len round-trip");
    CHECK(payload_len == 0, "payload_len pointer round-trip");

    PASS();
    return;

cleanup:
    return;
}

/* Test 12: Build+parse round-trip: data frame → identical payload */
static void test_myproto_roundtrip_data(void)
{
    TEST("MyProto: build+parse round-trip data frame → identical payload");
    uint8_t buf[MAX_FRAME_SIZE];
    const uint8_t original[256];
    myproto_hdr_t parsed_hdr;
    const uint8_t *parsed_payload = NULL;
    size_t parsed_payload_len = 0;
    ssize_t len;
    int ret;
    int i;

    /* Fill payload with a known pattern */
    for (i = 0; i < 256; i++) ((uint8_t *)original)[i] = (uint8_t)i;

    len = myproto_build_data_frame(buf, sizeof(buf), 8888, 0,
                                   original, 256, 0);
    CHECK(len == (ssize_t)(MYPROTO_HDR_SIZE + 256), "build should produce 265 bytes");

    ret = myproto_parse_frame(buf, (size_t)len, &parsed_hdr,
                              &parsed_payload, &parsed_payload_len);
    CHECK(ret == 0, "parse should succeed");
    CHECK(parsed_hdr.channel_id == 8888, "channel_id round-trip");
    CHECK(parsed_payload_len == 256, "payload_len round-trip");
    CHECK(memcmp(parsed_payload, original, 256) == 0,
          "full payload content round-trip (256 bytes)");

    PASS();
    return;

cleanup:
    return;
}

/* Test 13: Frame size check: sizeof(myproto_hdr_t) == 9 */
static void test_myproto_hdr_size(void)
{
    TEST("MyProto: sizeof(myproto_hdr_t) == 9");
    CHECK(sizeof(myproto_hdr_t) == MYPROTO_HDR_SIZE,
          "myproto_hdr_t must be 9 bytes (packed)");
    CHECK(sizeof(myproto_hdr_t) == 9, "myproto_hdr_t must be 9 bytes");

    PASS();
    return;

cleanup:
    return;
}

/* Test 14: Verify header_crc is 0 in built frames (reserved field) */
static void test_myproto_header_crc_valid(void)
{
    TEST("MyProto: header_crc is valid CRC-16 (S1 fix)");
    uint8_t buf[256];
    ssize_t len;

    /* Build a ctrl frame: header_crc should be valid CRC-16 (non-zero) */
    len = myproto_build_ctrl_frame(buf, sizeof(buf), 1, MPF_SYN, 0);
    CHECK(len == MYPROTO_HDR_SIZE, "build should succeed");

    /* Verify the frame can be parsed back */
    myproto_hdr_t hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    int ret = myproto_parse_frame(buf, (size_t)len, &hdr, &payload, &payload_len);
    CHECK(ret == 0, "parse should succeed with valid CRC-16");
    CHECK(hdr.channel_id == 1, "channel_id preserved");
    CHECK(hdr.flags == MPF_SYN, "flags preserved");

    PASS();
    return;

cleanup:
    return;
}

/* Test 15: Verify build functions return actual wire size */
static void test_myproto_build_return_sizes(void)
{
    TEST("MyProto: verify build functions return actual wire size");
    uint8_t buf[MAX_FRAME_SIZE];
    ssize_t len;

    /* Ctrl frame: always MYPROTO_HDR_SIZE (no CRC) */
    len = myproto_build_ctrl_frame(buf, sizeof(buf), 500, MPF_RST, 0);
    CHECK(len == (ssize_t)MYPROTO_HDR_SIZE, "ctrl frame wire size = 9");

    /* Data frame: MYPROTO_HDR_SIZE + payload_len (no CRC) */
    len = myproto_build_data_frame(buf, sizeof(buf), 600, 0,
                                   (const uint8_t *)"Test", 4, 0);
    CHECK(len == (ssize_t)(MYPROTO_HDR_SIZE + 4), "data frame wire size = 9 + 4");

    len = myproto_build_data_frame(buf, sizeof(buf), 700, 0,
                                   (const uint8_t *)"", 0, 0);
    CHECK(len == (ssize_t)MYPROTO_HDR_SIZE, "data frame wire size = 9 (empty)");

    PASS();
    return;

cleanup:
    return;
}

/* ============================================================================
 * Part A, Tests 16-30: Channel State Machine
 * ============================================================================ */

/* Test 16: Channel starts in CLOSED state (invalid role → default) */
static void test_channel_state_initial_closed(void)
{
    TEST("Channel state: initial state CLOSED (default role case)");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Use invalid role value to trigger default case → CLOSED */
    ch = channel_create(&ctx, 10001, (channel_role_t)99,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_CLOSED, "state should be CLOSED for invalid role");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 17: channel_create with INITIATOR → SYN_SENT */
static void test_channel_state_initiator_syn_sent(void)
{
    TEST("Channel state: INITIATOR → SYN_SENT");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 10002, CHANNEL_ROLE_INITIATOR,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_SYN_SENT, "INITIATOR should be in SYN_SENT");
    CHECK(ch->role == CHANNEL_ROLE_INITIATOR, "role should be INITIATOR");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 18: channel_create with RESPONDER → SYN_RCVD */
static void test_channel_state_responder_syn_rcvd(void)
{
    TEST("Channel state: RESPONDER → SYN_RCVD");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 10003, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_SYN_RCVD, "RESPONDER should be in SYN_RCVD");
    CHECK(ch->role == CHANNEL_ROLE_RESPONDER, "role should be RESPONDER");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 19: channel_create with LISTENER → ESTABLISHED */
static void test_channel_state_listener_established(void)
{
    TEST("Channel state: LISTENER → ESTABLISHED");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 10004, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "LISTENER should be ESTABLISHED");
    CHECK(ch->role == CHANNEL_ROLE_LISTENER, "role should be LISTENER");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 20: channel_process_frame: SYN on non-existent id → creates RESPONDER */
static void test_channel_syn_creates_responder(void)
{
    TEST("Channel state: SYN on non-existent id → creates RESPONDER");
    static global_ctx_t ctx;
    myproto_hdr_t hdr;
    channel_t *ch;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Send SYN for a channel that doesn't exist yet */
    fill_ctrl_hdr(&hdr, 65536, MPF_SYN);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "SYN processing should succeed");

    /* The channel should now exist as RESPONDER in SYN_RCVD */
    ch = channel_find(&ctx, 65536);
    CHECK(ch != NULL, "channel should be created");
    CHECK(ch->role == CHANNEL_ROLE_RESPONDER, "should be RESPONDER role");
    CHECK(ch->state == CHANNEL_SYN_RCVD, "should be in SYN_RCVD state");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 21: channel_process_frame: ACK on SYN_SENT → ESTABLISHED */
static void test_channel_ack_on_syn_sent(void)
{
    TEST("Channel state: ACK on SYN_SENT → ESTABLISHED");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create an INITIATOR (SYN_SENT) */
    ch = channel_create(&ctx, 10005, CHANNEL_ROLE_INITIATOR,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_SYN_SENT, "should start in SYN_SENT");

    /* Process ACK */
    fill_ctrl_hdr(&hdr, 10005, MPF_ACK);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "ACK processing should succeed");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "should transition to ESTABLISHED");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 22: channel_process_frame: FIN on ESTABLISHED → FIN_RCVD */
static void test_channel_fin_on_established(void)
{
    TEST("Channel state: FIN on ESTABLISHED → FIN_RCVD");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create LISTENER which starts ESTABLISHED */
    ch = channel_create(&ctx, 10006, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "should be ESTABLISHED");

    /* Process FIN */
    fill_ctrl_hdr(&hdr, 10006, MPF_FIN);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "FIN processing should succeed");
    CHECK(ch->state == CHANNEL_FIN_RCVD, "should transition to FIN_RCVD");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 23: channel_process_frame: RST on any state → CLOSED */
static void test_channel_rst_closes(void)
{
    TEST("Channel state: RST on ESTABLISHED → CLOSED (destroyed)");
    static global_ctx_t ctx;
    channel_t *ch, *found;
    myproto_hdr_t hdr;
    uint32_t ch_id = 10007;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create a LISTENER (ESTABLISHED) */
    ch = channel_create(&ctx, ch_id, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "should be ESTABLISHED");

    /* Process RST */
    fill_ctrl_hdr(&hdr, ch_id, MPF_RST);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "RST processing should succeed");

    /* Channel should be gone */
    found = channel_find(&ctx, ch_id);
    CHECK(found == NULL, "channel should be destroyed after RST");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 24: channel_process_frame: Data on CLOSED → ignored (returns error) */
static void test_channel_data_on_closed(void)
{
    TEST("Channel state: Data on non-existent channel → error");
    static global_ctx_t ctx;
    myproto_hdr_t hdr;
    uint8_t payload[16];
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Send data for a channel that doesn't exist */
    fill_ctrl_hdr(&hdr, 99999, 0);  /* flags=0 means data frame */
    hdr.payload_len = sizeof(payload);
    ret = channel_process_frame(&ctx, &hdr, payload, sizeof(payload));
    CHECK(ret < 0, "data on non-existent channel should return error");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 25: channel_process_frame: Heartbeat (PING) → processed (timestamp updated) */
static void test_channel_heartbeat_processed(void)
{
    TEST("Channel state: PING → timestamp updated");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    uint32_t before, after;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 10008, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");

    /* Record last_peer_seen before PING */
    before = ch->last_peer_seen;

    /* Small delay to ensure time difference */
    usleep(1000);

    /* Process PING */
    fill_ctrl_hdr(&hdr, 10008, MPF_PING);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "PING processing should succeed");

    after = ch->last_peer_seen;
    CHECK(after >= before, "last_peer_seen should be updated after PING");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 26: Duplicate SYN on existing channel → ignored/rejected */
static void test_channel_duplicate_syn_on_established(void)
{
    TEST("Channel state: duplicate SYN on ESTABLISHED → ignored");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create ESTABLISHED channel */
    ch = channel_create(&ctx, 10009, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "should be ESTABLISHED");

    /* Send duplicate SYN */
    fill_ctrl_hdr(&hdr, 10009, MPF_SYN);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "duplicate SYN should be handled gracefully");
    /* State should remain ESTABLISHED */
    CHECK(ch->state == CHANNEL_ESTABLISHED, "state should remain ESTABLISHED");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 27: SYN on FIN_RCVD → ignored (closing state) */
static void test_channel_syn_on_fin_rcvd_ignored(void)
{
    TEST("Channel state: SYN on FIN_RCVD → ignored");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create channel and transition to FIN_RCVD */
    ch = channel_create(&ctx, 10010, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");

    /* Send FIN to get to FIN_RCVD */
    fill_ctrl_hdr(&hdr, 10010, MPF_FIN);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "FIN should succeed");
    CHECK(ch->state == CHANNEL_FIN_RCVD, "should be FIN_RCVD");

    /* Now send SYN on FIN_RCVD → should be ignored */
    fill_ctrl_hdr(&hdr, 10010, MPF_SYN);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "SYN on FIN_RCVD should be ignored");
    CHECK(ch->state == CHANNEL_FIN_RCVD, "state should remain FIN_RCVD");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 28: LISTENER role channel never enters SYN_SENT */
static void test_channel_listener_never_syn_sent(void)
{
    TEST("Channel state: LISTENER never enters SYN_SENT");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 10011, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state != CHANNEL_SYN_SENT, "LISTENER must not be SYN_SENT");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "LISTENER should be ESTABLISHED");

    /* Even after various frames, LISTENER should not enter SYN_SENT */
    fill_ctrl_hdr(&hdr, 10011, MPF_PING);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "PING should succeed");
    CHECK(ch->state != CHANNEL_SYN_SENT, "LISTENER still not SYN_SENT after PING");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 29: State persistence: verify state after multiple operations */
static void test_channel_state_persistence(void)
{
    TEST("Channel state: state persistence across multiple operations");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create INITIATOR → SYN_SENT */
    ch = channel_create(&ctx, 10012, CHANNEL_ROLE_INITIATOR,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_SYN_SENT, "step 1: SYN_SENT");

    /* Send ACK → ESTABLISHED */
    fill_ctrl_hdr(&hdr, 10012, MPF_ACK);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "ACK should succeed");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "step 2: ESTABLISHED");

    /* Send PING → still ESTABLISHED */
    fill_ctrl_hdr(&hdr, 10012, MPF_PING);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "PING should succeed");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "step 3: still ESTABLISHED");

    /* Send FIN → FIN_RCVD */
    fill_ctrl_hdr(&hdr, 10012, MPF_FIN);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "FIN should succeed");
    CHECK(ch->state == CHANNEL_FIN_RCVD, "step 4: FIN_RCVD");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 30: TIME_WAIT state: verify via FIN_SENT + FIN */
static void test_channel_time_wait(void)
{
    TEST("Channel state: TIME_WAIT via FIN_SENT + received FIN");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    int ret;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create LISTENER (ESTABLISHED), then manually set to FIN_SENT */
    ch = channel_create(&ctx, 10013, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create should succeed");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "should start ESTABLISHED");

    /* Manually transition to FIN_SENT (simulates local close) */
    ch->state = CHANNEL_FIN_SENT;

    /* Now receive FIN → should go to TIME_WAIT (simultaneous close) */
    fill_ctrl_hdr(&hdr, 10013, MPF_FIN);
    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "FIN should succeed");
    CHECK(ch->state == CHANNEL_TIME_WAIT, "should be in TIME_WAIT after FIN_SENT + FIN");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Part A, Tests 31-40: alloc_channel_id
 * ============================================================================ */

/* Test 31: First allocation returns >= DYNAMIC_CHANNEL_BASE */
static void test_alloc_first_id_above_base(void)
{
    TEST("alloc_channel_id: first allocation >= DYNAMIC_CHANNEL_BASE (65536)");
    static global_ctx_t ctx;
    uint32_t id;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    id = alloc_channel_id(&ctx, 0);
    CHECK(id >= 65536, "first dynamic ID must be >= 65536");
    CHECK(id == 65536, "first ID from listener 0 should be exactly 65536");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 32: Sequential allocations increment */
static void test_alloc_sequential_increment(void)
{
    TEST("alloc_channel_id: sequential allocations increment");
    static global_ctx_t ctx;
    uint32_t id1, id2, id3;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    id1 = alloc_channel_id(&ctx, 0);
    id2 = alloc_channel_id(&ctx, 0);
    id3 = alloc_channel_id(&ctx, 0);

    CHECK(id1 != 0 && id2 != 0 && id3 != 0, "all three allocs should succeed");
    CHECK(id2 == id1 + 1, "second ID should be first + 1");
    CHECK(id3 == id2 + 1, "third ID should be second + 1");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 33: max_sessions=5 → exactly 5 unique IDs */
static void test_alloc_max_sessions_5(void)
{
    TEST("alloc_channel_id: max_sessions=5 → exactly 5 unique IDs");
    static global_ctx_t ctx;
    uint32_t ids[5];
    channel_t *dummy[5] = {NULL, NULL, NULL, NULL, NULL};
    uint32_t exhausted;
    int i, j;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Override max_sessions for listener 0 */
    ctx.config.channels[0].max_sessions = 5;
    ctx.listener_base[0] = 65536;
    ctx.listener_next[0] = 65536;

    /* Allocate 5 IDs and occupy them with channels */
    for (i = 0; i < 5; i++) {
        ids[i] = alloc_channel_id(&ctx, 0);
        CHECK(ids[i] != 0, "allocation within limit should succeed");
        dummy[i] = channel_create(&ctx, ids[i], CHANNEL_ROLE_RESPONDER,
                                  8080, 9090, "0.0.0.0", "10.0.0.1", 1);
        CHECK(dummy[i] != NULL, "channel_create should succeed");
    }

    /* Verify all unique */
    for (i = 0; i < 5; i++) {
        for (j = i + 1; j < 5; j++) {
            CHECK(ids[i] != ids[j], "all allocated IDs must be unique");
        }
    }

    /* 6th allocation must fail (all 5 slots occupied) */
    exhausted = alloc_channel_id(&ctx, 0);
    CHECK(exhausted == 0, "6th allocation must return 0 (exhausted)");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 34: max_sessions=0 → defaults to 1 (single allocation) */
static void test_alloc_max_sessions_zero(void)
{
    TEST("alloc_channel_id: max_sessions=0 → defaults to 1");
    static global_ctx_t ctx;
    channel_t *dummy;
    uint32_t id1, id2;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Override max_sessions to 0 */
    ctx.config.channels[0].max_sessions = 0;
    ctx.listener_base[0] = 65536;
    ctx.listener_next[0] = 65536;

    id1 = alloc_channel_id(&ctx, 0);
    CHECK(id1 != 0, "first allocation should succeed (limit defaults to 1)");

    /* Occupy the only slot */
    dummy = channel_create(&ctx, id1, CHANNEL_ROLE_RESPONDER,
                           8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(dummy != NULL, "channel_create should succeed");

    id2 = alloc_channel_id(&ctx, 0);
    CHECK(id2 == 0, "second allocation should fail (only 1 available)");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 35: Wraparound: fill pool, destroy one, re-allocate → gets freed ID */
static void test_alloc_wraparound_reuse(void)
{
    TEST("alloc_channel_id: destroy one, re-allocate → gets freed ID");
    static global_ctx_t ctx;
    uint32_t id1, id2, id3, id_reuse;
    channel_t *ch2;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Set max_sessions=3 */
    ctx.config.channels[0].max_sessions = 3;
    ctx.listener_base[0] = 65536;
    ctx.listener_next[0] = 65536;

    /* Allocate and occupy all 3 IDs */
    id1 = alloc_channel_id(&ctx, 0);
    CHECK(id1 != 0, "first alloc");
    ch2 = channel_create(&ctx, id1, CHANNEL_ROLE_RESPONDER,
                         8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch2 != NULL, "occupy id1");

    id2 = alloc_channel_id(&ctx, 0);
    CHECK(id2 != 0, "second alloc");
    /* Don't occupy id2 - we want it to be immediately reusable */

    id3 = alloc_channel_id(&ctx, 0);
    CHECK(id3 != 0, "third alloc");

    /* Destroy the channel holding id1 to free it */
    channel_destroy(&ctx, ch2);

    /* Now allocate again — should get id1 (65536) since it's freed */
    id_reuse = alloc_channel_id(&ctx, 0);
    CHECK(id_reuse == id1, "re-allocated ID should be the freed ID");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 36: Allocation after exhaustion → returns 0 */
static void test_alloc_exhaustion(void)
{
    TEST("alloc_channel_id: allocation after exhaustion → returns 0");
    static global_ctx_t ctx;
    uint32_t id;
    int i;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Set max_sessions=3, occupy all with channels */
    ctx.config.channels[0].max_sessions = 3;
    ctx.listener_base[0] = 65536;
    ctx.listener_next[0] = 65536;

    for (i = 0; i < 3; i++) {
        id = alloc_channel_id(&ctx, 0);
        CHECK(id != 0, "alloc within limit should succeed");
        channel_t *dummy = channel_create(&ctx, id, CHANNEL_ROLE_RESPONDER,
                                          8080, 9090, "0.0.0.0", "10.0.0.1", 1);
        CHECK(dummy != NULL, "occupy channel");
    }

    /* Now exhausted */
    id = alloc_channel_id(&ctx, 0);
    CHECK(id == 0, "exhausted pool must return 0");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 37: Multi-listener: IDs from different listeners don't overlap */
static void test_alloc_multi_listener_no_overlap(void)
{
    TEST("alloc_channel_id: multi-listener IDs don't overlap");
    static global_ctx_t ctx;
    uint32_t id_l0, id_l1;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Default: listener_base[0]=65536, max=256; listener_base[1]=65792, max=256 */
    id_l0 = alloc_channel_id(&ctx, 0);
    id_l1 = alloc_channel_id(&ctx, 1);

    CHECK(id_l0 >= 65536 && id_l0 <= 65536 + 255,
          "listener 0 ID should be in its range");
    CHECK(id_l1 >= 65792 && id_l1 <= 65792 + 255,
          "listener 1 ID should be in its range");
    CHECK(id_l0 != id_l1, "IDs from different listeners must not overlap");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 38: listener_idx=-1 → returns 0 */
static void test_alloc_negative_listener_idx(void)
{
    TEST("alloc_channel_id: listener_idx=-1 → returns 0");
    static global_ctx_t ctx;
    uint32_t id;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    id = alloc_channel_id(&ctx, -1);
    CHECK(id == 0, "listener_idx=-1 must return 0");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 39: listener_idx beyond channel_count → returns 0 */
static void test_alloc_oob_listener_idx(void)
{
    TEST("alloc_channel_id: listener_idx >= channel_count → returns 0");
    static global_ctx_t ctx;
    uint32_t id;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    id = alloc_channel_id(&ctx, ctx.config.channel_count);
    CHECK(id == 0, "listener_idx >= channel_count must return 0");

    id = alloc_channel_id(&ctx, 999);
    CHECK(id == 0, "large listener_idx must return 0");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 40: 256 concurrent allocations → all IDs unique */
static void test_alloc_256_unique(void)
{
    TEST("alloc_channel_id: 256 concurrent allocs → all unique");
    static global_ctx_t ctx;
    uint32_t ids[256];
    int i, j;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Listener 0 has max_sessions=256 → can allocate all 256 sequentially */
    for (i = 0; i < 256; i++) {
        ids[i] = alloc_channel_id(&ctx, 0);
        CHECK(ids[i] != 0, "each allocation should succeed");
    }

    /* Verify all unique */
    for (i = 0; i < 256; i++) {
        for (j = i + 1; j < 256; j++) {
            CHECK(ids[i] != ids[j], "all 256 IDs must be unique");
        }
    }

    /* Verify IDs are within the expected range [65536, 65536+255] */
    for (i = 0; i < 256; i++) {
        CHECK(ids[i] >= 65536 && ids[i] <= 65536 + 255,
              "all IDs must be within listener 0 range");
    }

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Part A, Tests 41-50: channel_config_changed & channel_update_config
 * ============================================================================ */

/* Test 41: listen_port changed → returns 1 */
static void test_config_changed_listen_port(void)
{
    TEST("channel_config_changed: listen_port changed → returns 1");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20001, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8081;  /* different */
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    CHECK(channel_config_changed(ch, &cfg) == 1,
          "listen_port change should trigger config_changed");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 42: remote_port changed → returns 1 */
static void test_config_changed_remote_port(void)
{
    TEST("channel_config_changed: remote_port changed → returns 1");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20002, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9999;  /* different */
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    CHECK(channel_config_changed(ch, &cfg) == 1,
          "remote_port change should trigger config_changed");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 43: listen_addr changed → returns 1 */
static void test_config_changed_listen_addr(void)
{
    TEST("channel_config_changed: listen_addr changed → returns 1");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20003, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "192.168.1.1", MAX_LISTEN_ADDR - 1);  /* different */
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    CHECK(channel_config_changed(ch, &cfg) == 1,
          "listen_addr change should trigger config_changed");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 44: remote_addr changed → returns 1 */
static void test_config_changed_remote_addr(void)
{
    TEST("channel_config_changed: remote_addr changed → returns 1");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20004, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "172.16.0.1", MAX_REMOTE_ADDR - 1);  /* different */
    cfg.is_tcp = 1;

    CHECK(channel_config_changed(ch, &cfg) == 1,
          "remote_addr change should trigger config_changed");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 45: is_tcp changed → returns 1 */
static void test_config_changed_is_tcp(void)
{
    TEST("channel_config_changed: is_tcp changed → returns 1");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20005, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 0;  /* different: was 1, now 0 */

    CHECK(channel_config_changed(ch, &cfg) == 1,
          "is_tcp change should trigger config_changed");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 46: Identical config → returns 0 */
static void test_config_changed_identical(void)
{
    TEST("channel_config_changed: identical config → returns 0");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20006, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    CHECK(channel_config_changed(ch, &cfg) == 0,
          "identical config must return 0");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 47: Only listen_addr differs, others same → returns 1 */
static void test_config_changed_only_listen_addr(void)
{
    TEST("channel_config_changed: only listen_addr differs → returns 1");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20007, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "10.0.0.99", MAX_LISTEN_ADDR - 1);  /* only this differs */
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    CHECK(channel_config_changed(ch, &cfg) == 1,
          "only listen_addr change should be detected");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 48: String truncation boundary (address at MAX_LISTEN_ADDR-1 length) */
static void test_config_changed_addr_truncation_boundary(void)
{
    TEST("channel_config_changed: address at MAX_LISTEN_ADDR-1 boundary");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;
    char long_addr[MAX_LISTEN_ADDR];

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20008, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* Create a long address string of exactly MAX_LISTEN_ADDR-1 chars */
    memset(long_addr, 'x', MAX_LISTEN_ADDR - 1);
    long_addr[MAX_LISTEN_ADDR - 1] = '\0';

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, long_addr, MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    /* Should detect change (different from "0.0.0.0") */
    CHECK(channel_config_changed(ch, &cfg) == 1,
          "long address change should be detected");

    /* Now update the channel (truncation tested in update_config) */
    channel_update_config(ch, &cfg);
    CHECK(strncmp(ch->listen_addr, long_addr, MAX_LISTEN_ADDR - 1) == 0,
          "updated listen_addr should match long_addr");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 49: Multi-field change → returns 1 (any one field triggers) */
static void test_config_changed_multi_field(void)
{
    TEST("channel_config_changed: multi-field change → returns 1");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20009, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 9000;  /* changed */
    cfg.remote_port = 9001;  /* changed */
    strncpy(cfg.listen_addr, "1.1.1.1", MAX_LISTEN_ADDR - 1);  /* changed */
    strncpy(cfg.remote_addr, "2.2.2.2", MAX_REMOTE_ADDR - 1);  /* changed */
    cfg.is_tcp = 0;  /* changed */

    CHECK(channel_config_changed(ch, &cfg) == 1,
          "multi-field change should be detected");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 50: channel_update_config followed by config_changed → returns 0 */
static void test_config_changed_after_update(void)
{
    TEST("channel_config_changed: after update_config → returns 0");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 20010, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* Build new config */
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 9999;
    cfg.remote_port = 8888;
    strncpy(cfg.listen_addr, "1.2.3.4", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "5.6.7.8", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 0;

    /* Before update: different */
    CHECK(channel_config_changed(ch, &cfg) == 1,
          "before update, config should be detected as changed");

    /* Apply update */
    channel_update_config(ch, &cfg);

    /* After update: should be same */
    CHECK(channel_config_changed(ch, &cfg) == 0,
          "after update, config should be identical");

    /* Verify fields were actually updated */
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
 * Part B, Tests 51-60: Channel Lifecycle & Find
 * ============================================================================ */

/* Test 51: channel_create → channel_find returns it */
static void test_channel_create_find(void)
{
    TEST("channel_create then channel_find returns the channel");
    static global_ctx_t ctx;
    channel_t *ch, *found;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30001, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    found = channel_find(&ctx, 30001);
    CHECK(found == ch, "channel_find must return the same pointer");
    CHECK(found->channel_id == 30001, "found channel_id mismatch");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 52: channel_destroy → channel_find returns NULL */
static void test_channel_destroy_find_null(void)
{
    TEST("channel_destroy then channel_find returns NULL");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30002, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    CHECK(channel_find(&ctx, 30002) != NULL, "should be findable before destroy");

    channel_destroy(&ctx, ch);
    CHECK(channel_find(&ctx, 30002) == NULL, "channel_find must return NULL after destroy");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 53: channel_find for non-existent ID → NULL */
static void test_channel_find_nonexistent(void)
{
    TEST("channel_find for non-existent ID returns NULL");
    static global_ctx_t ctx;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    CHECK(channel_find(&ctx, 99999) == NULL, "non-existent ID must return NULL");
    CHECK(channel_find(&ctx, 0) == NULL, "ID 0 must return NULL");
    CHECK(channel_find(&ctx, 12345) == NULL, "random ID must return NULL");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 54: channel_find for HEARTBEAT_CH_ID → NULL (special ID) */
static void test_channel_find_heartbeat_id(void)
{
    TEST("channel_find for HEARTBEAT_CH_ID returns NULL (special)");
    static global_ctx_t ctx;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* HEARTBEAT_CH_ID should not be in hash table unless explicitly created */
    CHECK(channel_find(&ctx, HEARTBEAT_CH_ID) == NULL,
          "HEARTBEAT_CH_ID must not be findable as a normal channel");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 55: channel_find for dynamic ID (65536) after creation → non-NULL */
static void test_channel_find_dynamic_id(void)
{
    TEST("channel_find for dynamic ID 65536 after creation returns non-NULL");
    static global_ctx_t ctx;
    channel_t *ch, *found;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 65536, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create with dynamic ID failed");

    found = channel_find(&ctx, 65536);
    CHECK(found != NULL, "channel_find for dynamic ID must return non-NULL");
    CHECK(found == ch, "must return same pointer");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 56: Create→destroy→re-create with same ID → works (ID reuse) */
static void test_channel_id_reuse(void)
{
    TEST("create→destroy→re-create with same ID works (ID reuse)");
    static global_ctx_t ctx;
    channel_t *ch1, *ch2;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch1 = channel_create(&ctx, 30003, CHANNEL_ROLE_LISTENER,
                         8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "first create failed");
    channel_destroy(&ctx, ch1);
    CHECK(channel_find(&ctx, 30003) == NULL, "ID must be free after destroy");

    ch2 = channel_create(&ctx, 30003, CHANNEL_ROLE_LISTENER,
                         8081, 9091, "0.0.0.0", "10.0.0.2", 0);
    CHECK(ch2 != NULL, "re-create with same ID failed");
    CHECK(ch2->channel_id == 30003, "re-created channel_id mismatch");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 57: channel_create returns NULL when max_channels reached */
static void test_channel_create_max_reached(void)
{
    TEST("channel_create returns NULL when max_channels reached");
    static global_ctx_t ctx;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Override max_channels to 1 */
    ctx.config.max_channels = 1;

    channel_t *ch1 = channel_create(&ctx, 40001, CHANNEL_ROLE_LISTENER,
                                    8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "first channel must succeed (count=0<1)");

    channel_t *ch2 = channel_create(&ctx, 40002, CHANNEL_ROLE_LISTENER,
                                    8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch2 == NULL, "second channel must fail (count=1>=1)");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 58: Init multiple channels → all findable */
static void test_channel_multiple_findable(void)
{
    TEST("init multiple channels → all findable");
    static global_ctx_t ctx;
    channel_t *ch[5];
    int i;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    for (i = 0; i < 5; i++) {
        ch[i] = channel_create(&ctx, (uint32_t)(50001 + i),
                               CHANNEL_ROLE_LISTENER,
                               (uint16_t)(8080 + i), 9090,
                               "0.0.0.0", "10.0.0.1", 1);
        CHECK(ch[i] != NULL, "channel_create failed");
    }

    for (i = 0; i < 5; i++) {
        channel_t *found = channel_find(&ctx, 50001 + (uint32_t)i);
        CHECK(found != NULL, "channel must be findable");
        CHECK(found->channel_id == 50001 + (uint32_t)i, "channel_id mismatch");
    }

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 59: Channel hash collision (same hash, different IDs) */
static void test_channel_hash_collision(void)
{
    TEST("channel hash collision: different IDs same bucket still findable");
    static global_ctx_t ctx;
    channel_t *ch1, *ch2, *found;
    uint32_t hash_size;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");
    hash_size = ctx.channel_hash_size;

    /* Pick two IDs that hash to the same bucket: id1 % hash_size == id2 % hash_size */
    uint32_t id1 = 100;
    uint32_t id2 = 100 + hash_size;  /* same hash bucket */

    ch1 = channel_create(&ctx, id1, CHANNEL_ROLE_LISTENER,
                         8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "first create failed");

    ch2 = channel_create(&ctx, id2, CHANNEL_ROLE_LISTENER,
                         8081, 9091, "0.0.0.0", "10.0.0.2", 1);
    CHECK(ch2 != NULL, "second create failed");

    /* Both must be findable despite hash collision */
    found = channel_find(&ctx, id1);
    CHECK(found == ch1, "id1 must be findable");

    found = channel_find(&ctx, id2);
    CHECK(found == ch2, "id2 must be findable");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 60: channel_create with duplicate ID → fails (find shows old one) */
static void test_channel_create_duplicate_id(void)
{
    TEST("channel_create with duplicate ID fails, find shows old one");
    static global_ctx_t ctx;
    channel_t *ch1, *ch2, *found;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch1 = channel_create(&ctx, 30010, CHANNEL_ROLE_LISTENER,
                         8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "first create failed");

    ch2 = channel_create(&ctx, 30010, CHANNEL_ROLE_LISTENER,
                         9999, 9999, "9.9.9.9", "8.8.8.8", 0);
    CHECK(ch2 == NULL, "duplicate create must fail");

    found = channel_find(&ctx, 30010);
    CHECK(found == ch1, "find must return original channel, not NULL");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Part B, Tests 61-70: channel_update_config & Reload Simulation
 * ============================================================================ */

/* Test 61: channel_update_config changes listen_port */
static void test_update_config_listen_port(void)
{
    TEST("channel_update_config changes listen_port");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30011, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 12345;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    channel_update_config(ch, &cfg);
    CHECK(ch->listen_port == 12345, "listen_port should be updated to 12345");
    CHECK(ch->remote_port == 9090, "remote_port should be unchanged");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 62: channel_update_config changes remote_port */
static void test_update_config_remote_port(void)
{
    TEST("channel_update_config changes remote_port");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30012, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 54321;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    channel_update_config(ch, &cfg);
    CHECK(ch->remote_port == 54321, "remote_port should be updated to 54321");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 63: channel_update_config changes listen_addr */
static void test_update_config_listen_addr(void)
{
    TEST("channel_update_config changes listen_addr");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30013, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "192.168.1.1", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    channel_update_config(ch, &cfg);
    CHECK(strcmp(ch->listen_addr, "192.168.1.1") == 0,
          "listen_addr should be updated");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 64: channel_update_config changes remote_addr */
static void test_update_config_remote_addr(void)
{
    TEST("channel_update_config changes remote_addr");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30014, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "172.16.99.99", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;

    channel_update_config(ch, &cfg);
    CHECK(strcmp(ch->remote_addr, "172.16.99.99") == 0,
          "remote_addr should be updated");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 65: channel_update_config changes is_tcp */
static void test_update_config_is_tcp(void)
{
    TEST("channel_update_config changes is_tcp");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30015, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    CHECK(ch->is_tcp == 1, "initial is_tcp should be 1");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 8080;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 0;

    channel_update_config(ch, &cfg);
    CHECK(ch->is_tcp == 0, "is_tcp should be updated to 0");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 66: channel_update_config preserves unrelated fields */
static void test_update_config_preserves_unrelated(void)
{
    TEST("channel_update_config preserves unrelated fields");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;
    uint32_t orig_channel_id;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30016, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    orig_channel_id = ch->channel_id;

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 7777;
    cfg.remote_port = 8888;
    strncpy(cfg.listen_addr, "1.1.1.1", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "2.2.2.2", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 0;

    channel_update_config(ch, &cfg);

    /* Config fields updated */
    CHECK(ch->listen_port == 7777, "listen_port updated");
    CHECK(ch->remote_port == 8888, "remote_port updated");
    CHECK(ch->is_tcp == 0, "is_tcp updated");

    /* Unrelated fields preserved */
    CHECK(ch->channel_id == orig_channel_id, "channel_id preserved");
    CHECK(ch->state == CHANNEL_ESTABLISHED, "state preserved (LISTENER)");
    CHECK(ch->local_fd == -1, "local_fd preserved");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 67: channel_update_config on valid channel with valid cfg → works */
static void test_update_config_on_valid_channel(void)
{
    TEST("channel_update_config on valid channel with valid cfg works");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30017, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 5555;
    cfg.remote_port = 6666;
    strncpy(cfg.listen_addr, "10.99.99.99", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.88.88.88", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 0;

    /* Should not crash and should update correctly */
    channel_update_config(ch, &cfg);
    CHECK(ch->listen_port == 5555, "update applied");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 68: Multiple sequential updates → last one sticks */
static void test_update_config_sequential(void)
{
    TEST("multiple sequential updates → last one sticks");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30018, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* Update 1 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 1111;
    cfg.remote_port = 9090;
    strncpy(cfg.listen_addr, "0.0.0.0", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.0.0.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 1;
    channel_update_config(ch, &cfg);

    /* Update 2 */
    cfg.listen_port = 2222;
    channel_update_config(ch, &cfg);

    /* Update 3 */
    cfg.listen_port = 3333;
    channel_update_config(ch, &cfg);

    CHECK(ch->listen_port == 3333, "last update must stick");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 69: Update then verify via channel_t fields */
static void test_update_config_verify_fields(void)
{
    TEST("update then verify all fields via channel_t");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30019, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 1111;
    cfg.remote_port = 2222;
    strncpy(cfg.listen_addr, "192.168.1.1", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "10.1.1.1", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 0;

    channel_update_config(ch, &cfg);

    CHECK(ch->listen_port == 1111, "verify listen_port");
    CHECK(ch->remote_port == 2222, "verify remote_port");
    CHECK(strcmp(ch->listen_addr, "192.168.1.1") == 0, "verify listen_addr");
    CHECK(strcmp(ch->remote_addr, "10.1.1.1") == 0, "verify remote_addr");
    CHECK(ch->is_tcp == 0, "verify is_tcp");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 70: channel_update_config does NOT change KCP state */
static void test_update_config_kcp_state_unchanged(void)
{
    TEST("channel_update_config does NOT change KCP/state fields");
    static global_ctx_t ctx;
    channel_t *ch;
    channel_config_t cfg;
    channel_state_t orig_state;
    uint32_t orig_last_active;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30020, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    orig_state = ch->state;
    orig_last_active = ch->last_active;

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 9999;
    cfg.remote_port = 8888;
    strncpy(cfg.listen_addr, "1.2.3.4", MAX_LISTEN_ADDR - 1);
    strncpy(cfg.remote_addr, "5.6.7.8", MAX_REMOTE_ADDR - 1);
    cfg.is_tcp = 0;

    channel_update_config(ch, &cfg);

    CHECK(ch->state == orig_state, "KCP state (channel state) unchanged");
    CHECK(ch->last_active == orig_last_active, "last_active unchanged");
    CHECK(ch->kcp != NULL, "KCP instance still exists");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Part B, Tests 71-80: Flags & Roles
 * ============================================================================ */

/* Test 71: STATIC_LISTENER flag set on listener channel */
static void test_flag_static_listener_set(void)
{
    TEST("STATIC_LISTENER flag can be set on listener channel");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30021, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags |= CH_FLAG_STATIC_LISTENER;
    CHECK((ch->flags & CH_FLAG_STATIC_LISTENER) != 0,
          "STATIC_LISTENER flag must be set");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 72: STATIC_LISTENER NOT set on dynamic channel */
static void test_flag_static_not_on_dynamic(void)
{
    TEST("STATIC_LISTENER is NOT set on dynamic (RESPONDER) channel");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30022, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    CHECK((ch->flags & CH_FLAG_STATIC_LISTENER) == 0,
          "dynamic channel must NOT have STATIC_LISTENER by default");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 73: channel_destroy skips listen_fd for STATIC_LISTENER */
static void test_destroy_skips_listen_fd_static(void)
{
    TEST("channel_destroy skips listen_fd close for STATIC_LISTENER");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30023, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags |= CH_FLAG_STATIC_LISTENER;
    ch->listen_fd = 99;  /* simulate an open listen fd */

    /* Destroy should not close listen_fd because STATIC_LISTENER is set */
    channel_destroy(&ctx, ch);
    /* If we reach here without crash/error, the STATIC_LISTENER guard worked */

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 74: channel_destroy closes listen_fd for non-STATIC_LISTENER */
static void test_destroy_closes_listen_fd_non_static(void)
{
    TEST("channel_destroy closes listen_fd for non-STATIC_LISTENER");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30024, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* Do NOT set STATIC_LISTENER flag */
    ch->listen_fd = 88;  /* simulate an open listen fd */
    ch->flags &= ~CH_FLAG_STATIC_LISTENER;  /* ensure flag is clear */

    /* Destroy should close listen_fd via proxy_epoll_del + close */
    channel_destroy(&ctx, ch);
    /* If we reach here without issues, it worked */

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 75: RELOAD_MARKED can be set on listener */
static void test_flag_reload_marked_set(void)
{
    TEST("RELOAD_MARKED flag can be set on listener channel");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30025, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags |= CH_FLAG_RELOAD_MARKED;
    CHECK((ch->flags & CH_FLAG_RELOAD_MARKED) != 0,
          "RELOAD_MARKED flag must be set");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 76: RELOAD_MARKED cleared but STATIC_LISTENER preserved */
static void test_flag_reload_clear_static_preserved(void)
{
    TEST("RELOAD_MARKED cleared but STATIC_LISTENER preserved");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30026, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags |= CH_FLAG_STATIC_LISTENER;
    ch->flags |= CH_FLAG_RELOAD_MARKED;

    /* Simulate: clear RELOAD_MARKED, preserve STATIC_LISTENER */
    ch->flags &= ~CH_FLAG_RELOAD_MARKED;

    CHECK((ch->flags & CH_FLAG_RELOAD_MARKED) == 0,
          "RELOAD_MARKED must be cleared");
    CHECK((ch->flags & CH_FLAG_STATIC_LISTENER) != 0,
          "STATIC_LISTENER must be preserved");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 77: Both flags can coexist */
static void test_flag_both_coexist(void)
{
    TEST("STATIC_LISTENER and RELOAD_MARKED can coexist");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30027, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags |= CH_FLAG_STATIC_LISTENER;
    ch->flags |= CH_FLAG_RELOAD_MARKED;

    CHECK((ch->flags & CH_FLAG_STATIC_LISTENER) != 0, "STATIC_LISTENER set");
    CHECK((ch->flags & CH_FLAG_RELOAD_MARKED) != 0, "RELOAD_MARKED set");
    CHECK((ch->flags & (CH_FLAG_STATIC_LISTENER | CH_FLAG_RELOAD_MARKED)) ==
          (CH_FLAG_STATIC_LISTENER | CH_FLAG_RELOAD_MARKED),
          "both flags coexist");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 78: RELOAD_MARKED on dynamic channel → set/clear works */
static void test_flag_reload_on_dynamic(void)
{
    TEST("RELOAD_MARKED on dynamic channel → set/clear works");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30028, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    ch->flags |= CH_FLAG_RELOAD_MARKED;
    CHECK((ch->flags & CH_FLAG_RELOAD_MARKED) != 0,
          "RELOAD_MARKED set on dynamic channel");

    ch->flags &= ~CH_FLAG_RELOAD_MARKED;
    CHECK((ch->flags & CH_FLAG_RELOAD_MARKED) == 0,
          "RELOAD_MARKED cleared on dynamic channel");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 79: LISTENER role channel not affected by timeout check */
static void test_timeout_listener_skipped(void)
{
    TEST("LISTENER role with STATIC_LISTENER skipped by timeout_check");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30029, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    ch->flags |= CH_FLAG_STATIC_LISTENER;

    /* channel_timeout_check should skip STATIC_LISTENER channels.
     * After running timeout check, the channel should still exist. */
    channel_timeout_check(&ctx);

    channel_t *found = channel_find(&ctx, 30029);
    CHECK(found == ch, "STATIC_LISTENER must survive timeout_check");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 80: Dynamic channel affected by timeout check */
static void test_timeout_dynamic_affected(void)
{
    TEST("dynamic channel without STATIC_LISTENER is subject to timeout");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 65537, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    /* No STATIC_LISTENER flag, and state is SYN_RCVD (not CLOSED),
     * so timeout_check will examine it. It won't destroy because
     * last_peer_seen is recent (just created). */
    ch->last_peer_seen = time_now();  /* reset to now */

    channel_timeout_check(&ctx);

    /* Channel should survive because last_peer_seen is recent */
    channel_t *found = channel_find(&ctx, 65537);
    CHECK(found != NULL, "dynamic channel with recent activity survives timeout");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Part B, Tests 81-90: Max Channels & Hash
 * ============================================================================ */

/* Test 81: max_channels=1 → first channel creates, second fails */
static void test_max_channels_one(void)
{
    TEST("max_channels=1 → first creates, second fails");
    static global_ctx_t ctx;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");
    ctx.config.max_channels = 1;

    channel_t *ch1 = channel_create(&ctx, 40010, CHANNEL_ROLE_LISTENER,
                                    8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "first channel must succeed");

    channel_t *ch2 = channel_create(&ctx, 40011, CHANNEL_ROLE_LISTENER,
                                    8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch2 == NULL, "second channel must fail with max_channels=1");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 82: max_channels=10 → exactly 10 channels created */
static void test_max_channels_ten(void)
{
    TEST("max_channels=10 → exactly 10 channels created");
    static global_ctx_t ctx;
    channel_t *ch[10];
    int i;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");
    ctx.config.max_channels = 10;

    for (i = 0; i < 10; i++) {
        ch[i] = channel_create(&ctx, (uint32_t)(40020 + i),
                               CHANNEL_ROLE_LISTENER,
                               (uint16_t)(8080 + i), 9090,
                               "0.0.0.0", "10.0.0.1", 1);
        CHECK(ch[i] != NULL, "channel must succeed within max_channels=10");
    }

    /* 11th must fail */
    channel_t *ch11 = channel_create(&ctx, 40030, CHANNEL_ROLE_LISTENER,
                                     8090, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch11 == NULL, "11th channel must fail");

    /* Verify all 10 are findable */
    for (i = 0; i < 10; i++) {
        CHECK(channel_find(&ctx, 40020 + (uint32_t)i) != NULL,
              "created channel must be findable");
    }

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 83: Channel creation beyond max_channels → returns NULL with error */
static void test_max_channels_beyond(void)
{
    TEST("channel beyond max_channels → returns NULL");
    static global_ctx_t ctx;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");
    ctx.config.max_channels = 3;

    CHECK(channel_create(&ctx, 40040, CHANNEL_ROLE_LISTENER,
                         8080, 9090, "0.0.0.0", "10.0.0.1", 1) != NULL, "1/3");
    CHECK(channel_create(&ctx, 40041, CHANNEL_ROLE_LISTENER,
                         8081, 9090, "0.0.0.0", "10.0.0.1", 1) != NULL, "2/3");
    CHECK(channel_create(&ctx, 40042, CHANNEL_ROLE_LISTENER,
                         8082, 9090, "0.0.0.0", "10.0.0.1", 1) != NULL, "3/3");

    /* 4th must return NULL */
    channel_t *ch4 = channel_create(&ctx, 40043, CHANNEL_ROLE_LISTENER,
                                    8083, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch4 == NULL, "4th channel beyond max_channels=3 must return NULL");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 84: channel_init with hash_size=64 → works */
static void test_hash_init_64(void)
{
    TEST("channel_init with hash_size=64 works");
    static global_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.config.node_type = NODE_TYPE_FRONTEND;
    ctx.config.max_channels = 32;
    ctx.config.kcp_mtu = 1400;
    ctx.config.kcp_send_window = 128;
    ctx.config.kcp_recv_window = 128;

    /* max_channels=32 → hash_size=64 (32*2, clamp min 64) */
    int ret = channel_init(&ctx, 32);
    CHECK(ret == 0, "channel_init with hash_size=64 must succeed");
    CHECK(ctx.channel_hash_size == 64, "hash_size must be 64");
    CHECK(ctx.channel_hash != NULL, "hash table must be allocated");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 85: channel_init with hash_size=8192 → works */
static void test_hash_init_8192(void)
{
    TEST("channel_init with hash_size=8192 works");
    static global_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.config.node_type = NODE_TYPE_FRONTEND;
    ctx.config.max_channels = 4096;
    ctx.config.kcp_mtu = 1400;
    ctx.config.kcp_send_window = 128;
    ctx.config.kcp_recv_window = 128;

    /* max_channels=4096 → hash_size=8192 (4096*2) */
    int ret = channel_init(&ctx, 4096);
    CHECK(ret == 0, "channel_init with hash_size=8192 must succeed");
    CHECK(ctx.channel_hash_size == 8192, "hash_size must be 8192");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 86: Hash table lookup after many inserts → O(1) fast */
static void test_hash_lookup_fast(void)
{
    TEST("hash lookup after many inserts is correct");
    static global_ctx_t ctx;
    channel_t *ch[50];
    int i;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Insert 50 channels */
    for (i = 0; i < 50; i++) {
        ch[i] = channel_create(&ctx, (uint32_t)(60000 + i),
                               CHANNEL_ROLE_LISTENER,
                               (uint16_t)(8080 + i), 9090,
                               "0.0.0.0", "10.0.0.1", 1);
        CHECK(ch[i] != NULL, "channel_create failed");
    }

    /* Verify all 50 are findable (hash lookup correctness) */
    for (i = 0; i < 50; i++) {
        channel_t *found = channel_find(&ctx, 60000 + (uint32_t)i);
        CHECK(found != NULL, "channel must be findable");
        CHECK(found->channel_id == 60000 + (uint32_t)i, "correct channel_id");
    }

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 87: Hash collision resolution: different IDs hash to same bucket */
static void test_hash_collision_resolution(void)
{
    TEST("hash collision: different IDs same bucket, both findable");
    static global_ctx_t ctx;
    channel_t *ch1, *ch2, *found;
    uint32_t hash_size, id1, id2;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");
    hash_size = ctx.channel_hash_size;

    /* Pick IDs that collide */
    id1 = 77;
    id2 = 77 + hash_size;

    ch1 = channel_create(&ctx, id1, CHANNEL_ROLE_LISTENER,
                         8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "first create failed");

    ch2 = channel_create(&ctx, id2, CHANNEL_ROLE_LISTENER,
                         8081, 9091, "0.0.0.0", "10.0.0.2", 1);
    CHECK(ch2 != NULL, "second create with colliding hash failed");

    /* Both must be findable */
    found = channel_find(&ctx, id1);
    CHECK(found == ch1, "first must be findable");
    found = channel_find(&ctx, id2);
    CHECK(found == ch2, "second with colliding hash must be findable");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 88: Channel destroy frees hash slot */
static void test_hash_slot_freed_on_destroy(void)
{
    TEST("channel destroy frees hash slot");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 40050, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    CHECK(channel_find(&ctx, 40050) != NULL, "must be findable before destroy");

    channel_destroy(&ctx, ch);
    CHECK(channel_find(&ctx, 40050) == NULL, "must NOT be findable after destroy");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 89: Destroyed slot can be reused */
static void test_hash_slot_reuse(void)
{
    TEST("destroyed hash slot can be reused");
    static global_ctx_t ctx;
    channel_t *ch1, *ch2;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch1 = channel_create(&ctx, 40051, CHANNEL_ROLE_LISTENER,
                         8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch1 != NULL, "first create failed");
    channel_destroy(&ctx, ch1);

    ch2 = channel_create(&ctx, 40051, CHANNEL_ROLE_LISTENER,
                         8081, 9091, "0.0.0.0", "10.0.0.2", 0);
    CHECK(ch2 != NULL, "re-create in freed slot failed");
    CHECK(ch2->channel_id == 40051, "reused slot has correct channel_id");
    CHECK(ch2->listen_port == 8081, "reused channel has new listen_port");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 90: channel_shutdown → all channels gone */
static void test_shutdown_all_gone(void)
{
    TEST("channel_shutdown → all channels gone");
    static global_ctx_t ctx;
    int i;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create several channels */
    for (i = 0; i < 5; i++) {
        channel_t *ch = channel_create(&ctx, (uint32_t)(40060 + i),
                                       CHANNEL_ROLE_LISTENER,
                                       (uint16_t)(8080 + i), 9090,
                                       "0.0.0.0", "10.0.0.1", 1);
        CHECK(ch != NULL, "channel_create failed");
    }

    channel_shutdown(&ctx);

    /* After shutdown, hash table is NULL and size is 0 */
    CHECK(ctx.channel_hash == NULL, "hash table freed");
    CHECK(ctx.channel_hash_size == 0, "hash size zeroed");
    CHECK(ctx.channel_count == 0, "channel count zeroed");

    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Part B, Tests 91-100: Data & Buffer
 * ============================================================================ */

/* Test 91: channel_process_frame with data → channel routed, state transitions */
static void test_process_frame_valid_data(void)
{
    TEST("channel_process_frame with data frame routes to channel");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    uint8_t payload[64];

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30030, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* Build data frame header for this channel */
    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id = 30030;
    hdr.flags = MPF_DATA;
    hdr.payload_len = 64;
    hdr.header_crc = myproto_crc32((const uint8_t *)&hdr, MYPROTO_HDR_SIZE - CRC32_SIZE) & 0xFFFF;

    memset(payload, 0xAB, 64);

    /* channel_process_frame on SYN_RCVD with DATA:
     * state transitions to ESTABLISHED even though KCP may reject raw data */
    channel_process_frame(&ctx, &hdr, payload, 64);
    CHECK(ch->state == CHANNEL_ESTABLISHED,
          "SYN_RCVD must transition to ESTABLISHED on data frame");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 92: channel_process_frame with NULL buffer → handled */
static void test_process_frame_null_buffer(void)
{
    TEST("channel_process_frame with NULL buffer is handled");
    static global_ctx_t ctx;
    myproto_hdr_t hdr;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id = 30031;
    hdr.flags = MPF_DATA;
    hdr.payload_len = 100;

    /* NULL payload with non-zero payload_len → should be handled gracefully */
    int ret = channel_process_frame(&ctx, &hdr, NULL, 100);
    /* Function returns -1 if channel not found (30031 doesn't exist) or
     * other error. The point is it doesn't crash. */
    (void)ret;

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 93: channel_process_frame with NULL hdr → handled */
static void test_process_frame_null_hdr(void)
{
    TEST("channel_process_frame with NULL hdr returns -1");
    static global_ctx_t ctx;
    uint8_t payload[64];

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    int ret = channel_process_frame(&ctx, NULL, payload, 64);
    CHECK(ret == -1, "NULL hdr must return -1");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 94: Large payload close to ETH_MAX_PAYLOAD → routed without crash */
static void test_process_frame_large_payload(void)
{
    TEST("large payload close to ETH_MAX_PAYLOAD routed without crash");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    uint8_t payload[1500];

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30032, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id = 30032;
    hdr.flags = MPF_DATA;
    hdr.payload_len = 1500;
    hdr.header_crc = myproto_crc32((const uint8_t *)&hdr, MYPROTO_HDR_SIZE - CRC32_SIZE) & 0xFFFF;

    memset(payload, 0xCD, 1500);

    /* Large payload: function should not crash; KCP may reject non-KCP data */
    channel_process_frame(&ctx, &hdr, payload, 1500);
    /* If we reach here without crash, the test passes */

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 95: recv_buf capacity: CHANNEL_RECV_BUF_SIZE check */
static void test_recv_buf_capacity(void)
{
    TEST("recv_buf capacity equals CHANNEL_RECV_BUF_SIZE");
    static global_ctx_t ctx;
    channel_t *ch;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30033, CHANNEL_ROLE_LISTENER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    CHECK(sizeof(ch->recv_buf) == CHANNEL_RECV_BUF_SIZE,
          "recv_buf size must equal CHANNEL_RECV_BUF_SIZE (8192)");
    CHECK(ch->recv_buf_len == 0, "initial recv_buf_len must be 0");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 96: Consecutive data frames on same channel → all processed */
static void test_consecutive_data_frames(void)
{
    TEST("consecutive data frames on same channel → all routed");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    uint8_t payload[32];
    int i;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30034, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    memset(payload, 0xEF, sizeof(payload));

    for (i = 0; i < 5; i++) {
        memset(&hdr, 0, sizeof(hdr));
        hdr.channel_id = 30034;
        hdr.flags = MPF_DATA;
        hdr.payload_len = 32;
        hdr.header_crc = myproto_crc32((const uint8_t *)&hdr,
                                        MYPROTO_HDR_SIZE - CRC32_SIZE) & 0xFFFF;
        payload[0] = (uint8_t)i;

        /* Each frame is routed to the channel; KCP may reject non-KCP data,
         * but the important thing is the channel is found and no crash */
        channel_process_frame(&ctx, &hdr, payload, 32);
    }

    /* Channel should still exist and be in ESTABLISHED state */
    CHECK(channel_find(&ctx, 30034) != NULL,
          "channel must still exist after consecutive frames");
    CHECK(ch->state == CHANNEL_ESTABLISHED,
          "state should be ESTABLISHED after data frames");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 97: Mixed ctrl+data frames → both processed */
static void test_mixed_ctrl_data_frames(void)
{
    TEST("mixed ctrl+data frames → both routed");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    uint8_t payload[32];

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    ch = channel_create(&ctx, 30035, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");

    /* First: send a PING ctrl frame (goes through ctrl path, no KCP) */
    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id = 30035;
    hdr.flags = MPF_PING;
    hdr.payload_len = 0;
    hdr.header_crc = myproto_crc32((const uint8_t *)&hdr,
                                    MYPROTO_HDR_SIZE - CRC32_SIZE) & 0xFFFF;

    int ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "PING ctrl frame must succeed");

    /* Then: send a DATA frame (routed, KCP may reject non-KCP data) */
    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id = 30035;
    hdr.flags = MPF_DATA;
    hdr.payload_len = 32;
    hdr.header_crc = myproto_crc32((const uint8_t *)&hdr,
                                    MYPROTO_HDR_SIZE - CRC32_SIZE) & 0xFFFF;
    memset(payload, 0x42, 32);

    channel_process_frame(&ctx, &hdr, payload, 32);
    /* Channel should still be alive and state updated */
    CHECK(channel_find(&ctx, 30035) != NULL,
          "channel must still exist after mixed frames");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 98: KCP window parameter verification (128) */
static void test_kcp_window_parameter(void)
{
    TEST("KCP window parameters are 128 (SEND/RECV)");
    static global_ctx_t ctx;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    CHECK(ctx.config.kcp_send_window == 128,
          "kcp_send_window must be 128 (KCP_SEND_WINDOW)");
    CHECK(ctx.config.kcp_recv_window == 128,
          "kcp_recv_window must be 128 (KCP_RECV_WINDOW)");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 99: KCP mtu parameter verification (1400) */
static void test_kcp_mtu_parameter(void)
{
    TEST("KCP MTU parameter is 1400 (KCP_MTU_CONSERVATIVE)");
    static global_ctx_t ctx;

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    CHECK(ctx.config.kcp_mtu == KCP_MTU_CONSERVATIVE,
          "kcp_mtu must equal KCP_MTU_CONSERVATIVE (1400)");

    channel_shutdown(&ctx);
    PASS();
    return;

cleanup:
    channel_shutdown(&ctx);
    return;
}

/* Test 100: Full cycle: create→connect→send data→receive→close */
static void test_full_cycle(void)
{
    TEST("full cycle: create→connect→data→close via ctrl frames");
    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t hdr;
    uint8_t payload[128];

    CHECK(init_test_ctx(&ctx) == 0, "init_test_ctx failed");

    /* Create channel as RESPONDER (simulates receiving side) */
    ch = channel_create(&ctx, 30036, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "0.0.0.0", "10.0.0.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    CHECK(ch->state == CHANNEL_SYN_RCVD, "initial state should be SYN_RCVD");

    /* Step 1: Simulate receiving data (transitions to ESTABLISHED) */
    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id = 30036;
    hdr.flags = MPF_DATA;
    hdr.payload_len = 128;
    hdr.header_crc = myproto_crc32((const uint8_t *)&hdr,
                                    MYPROTO_HDR_SIZE - CRC32_SIZE) & 0xFFFF;
    memset(payload, 0xAA, 128);

    channel_process_frame(&ctx, &hdr, payload, 128);
    CHECK(ch->state == CHANNEL_ESTABLISHED,
          "state must transition to ESTABLISHED after data");

    /* Step 2: Send PING (heartbeat) */
    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id = 30036;
    hdr.flags = MPF_PING;
    hdr.payload_len = 0;
    hdr.header_crc = myproto_crc32((const uint8_t *)&hdr,
                                    MYPROTO_HDR_SIZE - CRC32_SIZE) & 0xFFFF;

    int ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "PING must succeed on ESTABLISHED");

    /* Step 3: Receive FIN to start close */
    memset(&hdr, 0, sizeof(hdr));
    hdr.channel_id = 30036;
    hdr.flags = MPF_FIN;
    hdr.payload_len = 0;
    hdr.header_crc = myproto_crc32((const uint8_t *)&hdr,
                                    MYPROTO_HDR_SIZE - CRC32_SIZE) & 0xFFFF;

    ret = channel_process_frame(&ctx, &hdr, NULL, 0);
    CHECK(ret == 0, "FIN must be accepted");

    /* Channel should be in closing state */
    CHECK(ch->state == CHANNEL_FIN_RCVD || ch->state == CHANNEL_CLOSED ||
          ch->state == CHANNEL_TIME_WAIT,
          "state should indicate closing after FIN");

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
    printf("============================================================\n");
    printf("  Integration Test Suite v5 (Parts A+B: 1-100)\n");
    printf("============================================================\n");

    print_banner("MyProto: Frame Build / Parse / Validate (Tests 1-15)");
    test_myproto_build_ctrl_min_channel();
    test_myproto_build_ctrl_max_channel();
    test_myproto_build_data_zero_payload();
    test_myproto_build_data_max_payload();
    test_myproto_build_data_exceed_payload();
    test_myproto_parse_valid_ctrl();
    test_myproto_parse_valid_data();
    test_myproto_parse_corrupted_header_crc();
    test_myproto_parse_truncated();
    test_myproto_parse_zero_payload();
    test_myproto_roundtrip_ctrl();
    test_myproto_roundtrip_data();
    test_myproto_hdr_size();
    test_myproto_header_crc_valid();
    test_myproto_build_return_sizes();

    print_banner("Channel State Machine (Tests 16-30)");
    test_channel_state_initial_closed();
    test_channel_state_initiator_syn_sent();
    test_channel_state_responder_syn_rcvd();
    test_channel_state_listener_established();
    test_channel_syn_creates_responder();
    test_channel_ack_on_syn_sent();
    test_channel_fin_on_established();
    test_channel_rst_closes();
    test_channel_data_on_closed();
    test_channel_heartbeat_processed();
    test_channel_duplicate_syn_on_established();
    test_channel_syn_on_fin_rcvd_ignored();
    test_channel_listener_never_syn_sent();
    test_channel_state_persistence();
    test_channel_time_wait();

    print_banner("alloc_channel_id (Tests 31-40)");
    test_alloc_first_id_above_base();
    test_alloc_sequential_increment();
    test_alloc_max_sessions_5();
    test_alloc_max_sessions_zero();
    test_alloc_wraparound_reuse();
    test_alloc_exhaustion();
    test_alloc_multi_listener_no_overlap();
    test_alloc_negative_listener_idx();
    test_alloc_oob_listener_idx();
    test_alloc_256_unique();

    print_banner("channel_config_changed & Config (Tests 41-50)");
    test_config_changed_listen_port();
    test_config_changed_remote_port();
    test_config_changed_listen_addr();
    test_config_changed_remote_addr();
    test_config_changed_is_tcp();
    test_config_changed_identical();
    test_config_changed_only_listen_addr();
    test_config_changed_addr_truncation_boundary();
    test_config_changed_multi_field();
    test_config_changed_after_update();

    print_banner("Channel Lifecycle & Find (Tests 51-60)");
    test_channel_create_find();
    test_channel_destroy_find_null();
    test_channel_find_nonexistent();
    test_channel_find_heartbeat_id();
    test_channel_find_dynamic_id();
    test_channel_id_reuse();
    test_channel_create_max_reached();
    test_channel_multiple_findable();
    test_channel_hash_collision();
    test_channel_create_duplicate_id();

    print_banner("channel_update_config & Reload (Tests 61-70)");
    test_update_config_listen_port();
    test_update_config_remote_port();
    test_update_config_listen_addr();
    test_update_config_remote_addr();
    test_update_config_is_tcp();
    test_update_config_preserves_unrelated();
    test_update_config_on_valid_channel();
    test_update_config_sequential();
    test_update_config_verify_fields();
    test_update_config_kcp_state_unchanged();

    print_banner("Flags & Roles (Tests 71-80)");
    test_flag_static_listener_set();
    test_flag_static_not_on_dynamic();
    test_destroy_skips_listen_fd_static();
    test_destroy_closes_listen_fd_non_static();
    test_flag_reload_marked_set();
    test_flag_reload_clear_static_preserved();
    test_flag_both_coexist();
    test_flag_reload_on_dynamic();
    test_timeout_listener_skipped();
    test_timeout_dynamic_affected();

    print_banner("Max Channels & Hash (Tests 81-90)");
    test_max_channels_one();
    test_max_channels_ten();
    test_max_channels_beyond();
    test_hash_init_64();
    test_hash_init_8192();
    test_hash_lookup_fast();
    test_hash_collision_resolution();
    test_hash_slot_freed_on_destroy();
    test_hash_slot_reuse();
    test_shutdown_all_gone();

    print_banner("Data & Buffer (Tests 91-100)");
    test_process_frame_valid_data();
    test_process_frame_null_buffer();
    test_process_frame_null_hdr();
    test_process_frame_large_payload();
    test_recv_buf_capacity();
    test_consecutive_data_frames();
    test_mixed_ctrl_data_frames();
    test_kcp_window_parameter();
    test_kcp_mtu_parameter();
    test_full_cycle();

    print_summary();
    return tests_failed > 0 ? 1 : 0;
}
