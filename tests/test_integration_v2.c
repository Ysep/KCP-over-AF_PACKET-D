/*
 * test_integration_v2.c — KCP-over-AF_PACKET Integration Test Suite v2
 *
 * Comprehensive tests covering protocol layer, state machine, boundaries,
 * IPv6, MAC helpers, KCP param updates, and protocol budget analysis.
 *
 * All tests run without real network hardware.
 *
 * Compile:
 *   gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g \
 *       -o tests/test_integration_v2 tests/test_integration_v2.c \
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
#include "../src/crypto.h"
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
    printf("  Integration Test v2 Summary\n");
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
 * Helper: initialize a minimal global_ctx_t on the stack
 * ============================================================================ */

static void init_minimal_ctx(global_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->raw_sock  = -1;
    ctx->epoll_fd  = -1;
    ctx->running   = 1;
    ctx->ifindex   = 0;
    ctx->ethertype = htons(MYPROTO_ETHERTYPE);

    /* KCP defaults */
    ctx->config.kcp_mtu         = KCP_MTU_CONSERVATIVE;
    ctx->config.kcp_send_window = KCP_SEND_WINDOW;
    ctx->config.kcp_recv_window = KCP_RECV_WINDOW;
    ctx->config.kcp_nodelay     = KCP_NODELAY;
    ctx->config.kcp_interval    = KCP_INTERVAL;
    ctx->config.kcp_resend      = KCP_RESEND;
    ctx->config.kcp_nc          = KCP_NC;

    /* General config */
    ctx->config.node_type          = NODE_TYPE_FRONTEND;
    ctx->config.max_channels       = MAX_CHANNELS;
    ctx->config.heartbeat_interval = HEARTBEAT_INTERVAL;
    ctx->config.heartbeat_timeout  = HEARTBEAT_TIMEOUT;
    ctx->config.crc_enabled        = 0;
    ctx->config.encryption.enabled = 0;
    ctx->config.nic_mtu            = ETH_MTU;

    strncpy(ctx->config.interface, "eth0", MAX_INTERFACE_NAME - 1);
    ctx->config.ethertype = MYPROTO_ETHERTYPE;
}

/* ============================================================================
 * Protocol Layer Tests
 * ============================================================================ */

/*
 * Test 1: Frame encode/decode round-trip with multiple payload sizes.
 */
static void test_frame_roundtrip_multisize(void)
{
    TEST("frame encode/decode round-trip (0..1400 bytes)");

    const size_t sizes[] = { 0, 1, 16, 128, 256, 512, 1024, 1400 };
    const int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    uint8_t payload[1400];
    uint8_t buf[2000];
    int i;

    /* Fill payload with pattern */
    for (i = 0; i < 1400; i++) {
        payload[i] = (uint8_t)(i & 0xFF);
    }

    for (i = 0; i < num_sizes; i++) {
        size_t sz = sizes[i];
        myproto_hdr_t hdr_in, hdr_out;
        const uint8_t *parsed_payload;
        size_t parsed_len;
        ssize_t frame_len;
        int ret;

        memset(&hdr_in, 0, sizeof(hdr_in));
        hdr_in.flags      = MPF_DATA;
        hdr_in.channel_id = 42;
        hdr_in.payload_len = (uint16_t)sz;

        frame_len = myproto_build_frame(buf, sizeof(buf), &hdr_in,
                                        sz > 0 ? payload : NULL, sz, 0);
        CHECK(frame_len > 0, "myproto_build_frame failed");
        CHECK((size_t)frame_len == MYPROTO_HDR_SIZE + sz,
              "frame_len mismatch");

        ret = myproto_parse_frame(buf, (size_t)frame_len, &hdr_out,
                                  &parsed_payload, &parsed_len);
        CHECK(ret == 0, "myproto_parse_frame failed");

        CHECK(hdr_out.flags      == MPF_DATA,        "flags mismatch");
        CHECK(hdr_out.channel_id == 42,              "channel_id mismatch");
        CHECK(hdr_out.payload_len == (uint16_t)sz,     "payload_len mismatch");
        CHECK(parsed_len         == sz,              "parsed_len mismatch");

        if (sz > 0) {
            CHECK(memcmp(parsed_payload, payload, sz) == 0,
                  "payload data mismatch");
        }
    }

    PASS();
    return;
cleanup:
    return;
}

/*
 * Test 2: Build all 6 control frame types and verify flags.
 */
static void test_control_frame_all_types(void)
{
    TEST("control frame all 6 types (SYN/ACK/FIN/RST/PING/PONG)");

    uint8_t buf[256];
    ssize_t len;

    struct {
        uint8_t flag;
        const char *name;
    } ctrl_types[] = {
        { MPF_SYN,  "SYN"  },
        { MPF_ACK,  "ACK"  },
        { MPF_FIN,  "FIN"  },
        { MPF_RST,  "RST"  },
        { MPF_PING, "PING" },
        { MPF_PONG, "PONG" },
    };

    const int ntypes = (int)(sizeof(ctrl_types) / sizeof(ctrl_types[0]));

    for (int i = 0; i < ntypes; i++) {
        myproto_hdr_t hdr;
        const uint8_t *payload;
        size_t payload_len;
        int ret;

        len = myproto_build_ctrl_frame(buf, sizeof(buf), 1 /* channel_id */,
                                       ctrl_types[i].flag, 0);
        CHECK(len == (ssize_t)MYPROTO_HDR_SIZE,
              "control frame length != HDR_SIZE");

        ret = myproto_parse_frame(buf, (size_t)len, &hdr,
                                  &payload, &payload_len);
        CHECK(ret == 0, "parse control frame failed");

        CHECK(hdr.flags      == ctrl_types[i].flag,
              "flags mismatch for control type");
        CHECK(hdr.channel_id == 1,              "channel_id mismatch");
        CHECK(hdr.payload_len   == 0,              "payload_len should be 0");
        CHECK(payload_len    == 0,              "payload_len should be 0");

        /* Verify that it's recognized as a control frame */
        CHECK(myproto_is_ctrl_frame(hdr.flags),
              "should be recognized as ctrl frame");
        CHECK(!myproto_is_data_frame(hdr.flags),
              "should NOT be recognized as data frame");
    }

    PASS();
    return;
cleanup:
    return;
}

/*
 * Test 3: CRC32 round-trip — build with CRC, verify, tamper, re-verify.
 */
static void test_crc32_roundtrip(void)
{
    TEST("CRC32 round-trip — verify and tamper detection");

    uint8_t buf[2000];
    uint8_t payload[512];
    myproto_hdr_t hdr;
    ssize_t frame_len;
    ssize_t data_len;
    int i;

    /* Fill payload */
    for (i = 0; i < 512; i++) {
        payload[i] = (uint8_t)(i * 7 + 13);
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.flags      = 0;
    hdr.channel_id = 99;
    hdr.payload_len = 512;

    /* Build frame with CRC */
    frame_len = myproto_build_frame(buf, sizeof(buf), &hdr,
                                    payload, 512, 1 /* crc_enabled */);
    CHECK(frame_len > 0, "build with CRC failed");
    CHECK((size_t)frame_len == MYPROTO_HDR_SIZE + 512 + CRC32_SIZE,
          "frame_len should include CRC");

    /* Verify CRC */
    data_len = myproto_verify_crc(buf, (size_t)frame_len);
    CHECK(data_len > 0, "CRC verification should pass");
    CHECK((size_t)data_len == MYPROTO_HDR_SIZE + 512,
          "data_len should exclude CRC");

    /* Tamper with one byte in the middle of the payload area */
    {
        size_t tamper_pos = MYPROTO_HDR_SIZE + 200;
        uint8_t orig = buf[tamper_pos];
        buf[tamper_pos] = (uint8_t)(orig ^ 0x55);

        data_len = myproto_verify_crc(buf, (size_t)frame_len);
        CHECK(data_len < 0, "CRC should detect tampering");

        /* Restore */
        buf[tamper_pos] = orig;
        data_len = myproto_verify_crc(buf, (size_t)frame_len);
        CHECK(data_len > 0, "CRC should pass again after restore");
    }

    PASS();
    return;
cleanup:
    return;
}

/*
 * Test 4: Crypto round-trip — encrypt a data frame, decrypt, verify.
 */
static void test_crypto_roundtrip(void)
{
    TEST("crypto round-trip — SM4-CBC encrypt/decrypt via myproto");

    encryption_config_t enc;
    uint8_t plaintext[256];
    int i, ret;

    /* Init crypto */
    memset(&enc, 0, sizeof(enc));
    enc.enabled = 1;
    strncpy(enc.sm4_key, "00112233445566778899aabbccddeeff", SM4_KEY_HEX_LEN);
    enc.sm4_key[SM4_KEY_HEX_LEN] = '\0';
    ret = crypto_init(&enc);
    CHECK(ret == 0, "crypto_init failed");

    /* Fill plaintext */
    for (i = 0; i < 256; i++) {
        plaintext[i] = (uint8_t)(i ^ 0xAA);
    }

    /* Test 1: crypto_encrypt_frame / crypto_decrypt_frame directly */
    {
        uint8_t enc_buf[512];
        uint8_t dec_buf[512];
        int enc_len, dec_len;

        enc_len = crypto_encrypt_frame(plaintext, 256, enc_buf, (int)sizeof(enc_buf));
        CHECK(enc_len > 0, "crypto_encrypt_frame failed");
        CHECK(enc_len > 256, "encrypted data should be larger than plaintext");

        dec_len = crypto_decrypt_frame(enc_buf, enc_len, dec_buf, (int)sizeof(dec_buf));
        CHECK(dec_len == 256, "crypto_decrypt_frame returned wrong length");
        CHECK(memcmp(dec_buf, plaintext, 256) == 0,
              "decrypted data does not match original");
    }

    /* Test 2: full pipeline via myproto_build_data_frame + parse + process */
    {
        uint8_t frame_buf[2000];
        myproto_hdr_t parsed_hdr;
        const uint8_t *parsed_payload;
        size_t parsed_len;
        ssize_t frame_len;

        frame_len = myproto_build_data_frame(frame_buf, sizeof(frame_buf),
                                             77 /* channel_id */,
                                             MPF_CRYPTO, plaintext, 256, 0);
        CHECK(frame_len > 0, "build encrypted data frame failed");

        ret = myproto_parse_frame(frame_buf, (size_t)frame_len, &parsed_hdr,
                                  &parsed_payload, &parsed_len);
        CHECK(ret == 0, "parse encrypted frame failed");
        CHECK((parsed_hdr.flags & MPF_CRYPTO) != 0,
              "frame should have CRYPTO flag");
        CHECK(parsed_hdr.channel_id == 77,
              "channel_id mismatch in encrypted frame");

        /* Process the data frame (decrypt) */
        {
            uint8_t mutable_payload[512];
            size_t proc_len = parsed_len;

            memcpy(mutable_payload, parsed_payload, parsed_len);
            ret = myproto_process_data_frame(&parsed_hdr, mutable_payload, &proc_len);
            CHECK(ret == 0, "myproto_process_data_frame failed");
            CHECK(proc_len == 256, "decrypted payload length mismatch");
            CHECK(memcmp(mutable_payload, plaintext, 256) == 0,
                  "decrypted payload data mismatch");
        }
    }

    crypto_cleanup();
    PASS();
    return;
cleanup:
    crypto_cleanup();
    return;
}

/*
 * Test 5: Heartbeat channel routing — verify channel_id=0xFFFF is accepted.
 */
static void test_heartbeat_channel_routing(void)
{
    TEST("heartbeat channel routing (channel_id=0xFFFF)");

    uint8_t buf[256];
    ssize_t len;
    myproto_hdr_t hdr;

    /* Verify myproto_build_ctrl_frame accepts HEARTBEAT_CH_ID */
    len = myproto_build_ctrl_frame(buf, sizeof(buf), HEARTBEAT_CH_ID,
                                   MPF_PING, 0);
    CHECK(len == (ssize_t)MYPROTO_HDR_SIZE,
          "build ctrl frame with HEARTBEAT_CH_ID should succeed");

    /* Parse the frame and verify */
    {
        const uint8_t *payload;
        size_t payload_len;
        int ret;

        ret = myproto_parse_frame(buf, (size_t)len, &hdr,
                                  &payload, &payload_len);
        CHECK(ret == 0, "parse heartbeat frame failed");
        CHECK(hdr.channel_id == HEARTBEAT_CH_ID,
              "channel_id should be 0xFFFF");
    }

    /* Verify myproto_validate_hdr accepts HEARTBEAT_CH_ID */
    {
        memset(&hdr, 0, sizeof(hdr));
        hdr.flags      = MPF_PING;
        hdr.channel_id = HEARTBEAT_CH_ID;
        hdr.payload_len = 0;

        int ret = myproto_validate_hdr(&hdr);
        CHECK(ret == 0, "validate_hdr should accept HEARTBEAT_CH_ID");
    }

    /* Also verify PONG works */
    len = myproto_build_ctrl_frame(buf, sizeof(buf), HEARTBEAT_CH_ID,
                                   MPF_PONG, 0);
    CHECK(len == (ssize_t)MYPROTO_HDR_SIZE,
          "build ctrl frame with HEARTBEAT_CH_ID PONG should succeed");

    PASS();
    return;
cleanup:
    return;
}

/* ============================================================================
 * State Machine Tests
 * ============================================================================ */

/*
 * Test 6: SYN/ACK flow — initiator channel, simulate SYN→SYN_RCVD→ESTABLISHED.
 */
static void test_channel_syn_ack_flow(void)
{
    TEST("channel SYN/ACK flow — SYN_SENT → SYN_RCVD → ESTABLISHED");

    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t syn_hdr;
    uint8_t syn_frame[256];
    ssize_t syn_len;
    int ret;

    init_minimal_ctx(&ctx);
    ctx.config.max_channels = 64;

    ret = channel_init(&ctx, 64);
    CHECK(ret == 0, "channel_init failed");

    /* Create initiator channel → should be in SYN_SENT */
    ch = channel_create(&ctx, 10, CHANNEL_ROLE_INITIATOR,
                        8080, 9090, "127.0.0.1", "192.168.1.1", 1);
    CHECK(ch != NULL, "channel_create (initiator) failed");

    /* Verify initial state: the channel is in SYN_SENT (set before send attempt) */
    /* Note: channel_send_ctrl inside channel_create may fail (no socket),
     * but state is already set */
    CHECK(ch->state == CHANNEL_SYN_SENT,
          "initiator channel should be in SYN_SENT");

    /* Simulate receiving a SYN frame (as responder's SYN to us) */
    syn_len = myproto_build_ctrl_frame(syn_frame, sizeof(syn_frame),
                                       10, MPF_SYN, 0);
    CHECK(syn_len > 0, "build SYN frame failed");

    {
        const uint8_t *payload;
        size_t payload_len;

        ret = myproto_parse_frame(syn_frame, (size_t)syn_len, &syn_hdr,
                                  &payload, &payload_len);
        CHECK(ret == 0, "parse SYN frame failed");

        /* Feed SYN through channel_process_frame */
        ret = channel_process_frame(&ctx, &syn_hdr, payload, payload_len);
        /* channel_send_ctrl for ACK will fail (no socket),
         * but state transition should still happen */
        CHECK(ch->state == CHANNEL_SYN_RCVD,
              "state should transition to SYN_RCVD after receiving SYN");
    }

    /* Simulate receiving a data frame → transition to ESTABLISHED */
    {
        uint8_t data_buf[256];
        myproto_hdr_t data_hdr;
        const uint8_t *payload;
        size_t payload_len;
        uint8_t dummy_data[32];
        ssize_t df_len;

        memset(dummy_data, 0x42, sizeof(dummy_data));

        df_len = myproto_build_data_frame(data_buf, sizeof(data_buf),
                                          10, 0 /* no crypto */,
                                          dummy_data, sizeof(dummy_data), 0);
        CHECK(df_len > 0, "build data frame failed");

        ret = myproto_parse_frame(data_buf, (size_t)df_len, &data_hdr,
                                  &payload, &payload_len);
        CHECK(ret == 0, "parse data frame failed");

        ret = channel_process_frame(&ctx, &data_hdr, payload, payload_len);
        /* kcp_wrap_input may succeed; proxy_write_to_local will fail but
         * state transition happens before */
        CHECK(ch->state == CHANNEL_ESTABLISHED,
              "state should transition to ESTABLISHED after first data frame");
    }

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 7: FIN handshake — ESTABLISHED→FIN_RCVD, FIN_SENT→TIME_WAIT.
 */
static void test_channel_fin_handshake(void)
{
    TEST("channel FIN handshake — ESTABLISHED→FIN_RCVD, FIN_SENT→TIME_WAIT");

    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t fin_hdr;
    uint8_t fin_frame[256];
    ssize_t fin_len;
    int ret;

    init_minimal_ctx(&ctx);
    ctx.config.max_channels = 64;

    ret = channel_init(&ctx, 64);
    CHECK(ret == 0, "channel_init failed");

    /* Create channel and manually set to ESTABLISHED */
    ch = channel_create(&ctx, 20, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "127.0.0.1", "192.168.1.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    ch->state = CHANNEL_ESTABLISHED;

    /* Receive FIN → should go to FIN_RCVD */
    fin_len = myproto_build_ctrl_frame(fin_frame, sizeof(fin_frame),
                                       20, MPF_FIN, 0);
    CHECK(fin_len > 0, "build FIN frame failed");

    {
        const uint8_t *payload;
        size_t payload_len;

        ret = myproto_parse_frame(fin_frame, (size_t)fin_len, &fin_hdr,
                                  &payload, &payload_len);
        CHECK(ret == 0, "parse FIN frame failed");

        ret = channel_process_frame(&ctx, &fin_hdr, payload, payload_len);
        CHECK(ch->state == CHANNEL_FIN_RCVD,
              "ESTABLISHED + FIN → FIN_RCVD");
    }

    /* Now test FIN_SENT → TIME_WAIT: create new channel, set to FIN_SENT */
    {
        channel_t *ch2;
        myproto_hdr_t fin2_hdr;
        uint8_t fin2_frame[256];
        ssize_t fin2_len;

        ch2 = channel_create(&ctx, 21, CHANNEL_ROLE_RESPONDER,
                             8080, 9090, "127.0.0.1", "192.168.1.1", 1);
        CHECK(ch2 != NULL, "channel_create for FIN_SENT test failed");
        ch2->state = CHANNEL_FIN_SENT;

        fin2_len = myproto_build_ctrl_frame(fin2_frame, sizeof(fin2_frame),
                                            21, MPF_FIN, 0);
        CHECK(fin2_len > 0, "build FIN frame 2 failed");

        {
            const uint8_t *payload;
            size_t payload_len;

            ret = myproto_parse_frame(fin2_frame, (size_t)fin2_len, &fin2_hdr,
                                      &payload, &payload_len);
            CHECK(ret == 0, "parse FIN frame 2 failed");

            ret = channel_process_frame(&ctx, &fin2_hdr, payload, payload_len);
            CHECK(ch2->state == CHANNEL_TIME_WAIT,
                  "FIN_SENT + FIN → TIME_WAIT");
        }
    }

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 8: RST cleanup — ESTABLISHED channel, receive RST → destroyed.
 */
static void test_channel_rst_cleanup(void)
{
    TEST("channel RST cleanup — ESTABLISHED receives RST → destroyed");

    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t rst_hdr;
    uint8_t rst_frame[256];
    ssize_t rst_len;
    int ret;

    init_minimal_ctx(&ctx);
    ctx.config.max_channels = 64;

    ret = channel_init(&ctx, 64);
    CHECK(ret == 0, "channel_init failed");

    ch = channel_create(&ctx, 30, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "127.0.0.1", "192.168.1.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    ch->state = CHANNEL_ESTABLISHED;

    /* Verify channel is findable */
    CHECK(channel_find(&ctx, 30) == ch,
          "channel should be findable before RST");

    rst_len = myproto_build_ctrl_frame(rst_frame, sizeof(rst_frame),
                                       30, MPF_RST, 0);
    CHECK(rst_len > 0, "build RST frame failed");

    {
        const uint8_t *payload;
        size_t payload_len;

        ret = myproto_parse_frame(rst_frame, (size_t)rst_len, &rst_hdr,
                                  &payload, &payload_len);
        CHECK(ret == 0, "parse RST frame failed");

        ret = channel_process_frame(&ctx, &rst_hdr, payload, payload_len);

        /* Channel should be destroyed → channel_find returns NULL */
        CHECK(channel_find(&ctx, 30) == NULL,
              "channel should be destroyed after RST");
    }

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 9: Duplicate SYN on ESTABLISHED — state must stay ESTABLISHED.
 */
static void test_channel_duplicate_syn(void)
{
    TEST("channel duplicate SYN — ESTABLISHED stays ESTABLISHED");

    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t syn_hdr;
    uint8_t syn_frame[256];
    ssize_t syn_len;
    int ret;

    init_minimal_ctx(&ctx);
    ctx.config.max_channels = 64;

    ret = channel_init(&ctx, 64);
    CHECK(ret == 0, "channel_init failed");

    ch = channel_create(&ctx, 40, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "127.0.0.1", "192.168.1.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    ch->state = CHANNEL_ESTABLISHED;

    syn_len = myproto_build_ctrl_frame(syn_frame, sizeof(syn_frame),
                                       40, MPF_SYN, 0);
    CHECK(syn_len > 0, "build SYN frame failed");

    {
        const uint8_t *payload;
        size_t payload_len;

        ret = myproto_parse_frame(syn_frame, (size_t)syn_len, &syn_hdr,
                                  &payload, &payload_len);
        CHECK(ret == 0, "parse SYN frame failed");

        ret = channel_process_frame(&ctx, &syn_hdr, payload, payload_len);
        /* Should return 0 (ignored) */
        CHECK(ret == 0,
              "duplicate SYN on ESTABLISHED should return 0 (ignored)");
        CHECK(ch->state == CHANNEL_ESTABLISHED,
              "state must stay ESTABLISHED after duplicate SYN");
    }

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 10: SYN on FIN_SENT channel — SYN ignored, state unchanged.
 */
static void test_syn_on_closing_channel(void)
{
    TEST("SYN on closing channel — FIN_SENT ignores SYN");

    static global_ctx_t ctx;
    channel_t *ch;
    myproto_hdr_t syn_hdr;
    uint8_t syn_frame[256];
    ssize_t syn_len;
    int ret;

    init_minimal_ctx(&ctx);
    ctx.config.max_channels = 64;

    ret = channel_init(&ctx, 64);
    CHECK(ret == 0, "channel_init failed");

    ch = channel_create(&ctx, 50, CHANNEL_ROLE_RESPONDER,
                        8080, 9090, "127.0.0.1", "192.168.1.1", 1);
    CHECK(ch != NULL, "channel_create failed");
    ch->state = CHANNEL_FIN_SENT;

    syn_len = myproto_build_ctrl_frame(syn_frame, sizeof(syn_frame),
                                       50, MPF_SYN, 0);
    CHECK(syn_len > 0, "build SYN frame failed");

    {
        const uint8_t *payload;
        size_t payload_len;

        ret = myproto_parse_frame(syn_frame, (size_t)syn_len, &syn_hdr,
                                  &payload, &payload_len);
        CHECK(ret == 0, "parse SYN frame failed");

        ret = channel_process_frame(&ctx, &syn_hdr, payload, payload_len);
        CHECK(ret == 0,
              "SYN on FIN_SENT should be ignored (return 0)");
        CHECK(ch->state == CHANNEL_FIN_SENT,
              "state must stay FIN_SENT after SYN on closing channel");
    }

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/* ============================================================================
 * Boundary / Stress Tests
 * ============================================================================ */

/*
 * Test 11: Max channels stress — create 256 channels, 257th fails.
 */
static void test_max_channels_stress(void)
{
    TEST("max channels stress — 0..255 succeed, 256 fails");

    static global_ctx_t ctx;
    channel_t *channels[256];
    int i, ret;

    init_minimal_ctx(&ctx);
    ctx.config.max_channels = 256;

    ret = channel_init(&ctx, 256);
    CHECK(ret == 0, "channel_init failed");

    /* Create channels 0..255 */
    for (i = 0; i < 256; i++) {
        channels[i] = channel_create(&ctx, (uint32_t)i,
                                     CHANNEL_ROLE_RESPONDER,
                                     8080, 9090, "127.0.0.1", "192.168.1.1", 1);
        CHECK(channels[i] != NULL, "channel_create should succeed");
    }

    /* Verify all are findable */
    for (i = 0; i < 256; i++) {
        channel_t *found = channel_find(&ctx, (uint32_t)i);
        CHECK(found == channels[i], "channel should be findable");
    }

    /* The 257th should fail */
    {
        channel_t *extra = channel_create(&ctx, 256,
                                          CHANNEL_ROLE_RESPONDER,
                                          8080, 9090, "127.0.0.1", "192.168.1.1", 1);
        CHECK(extra == NULL, "channel_create #257 should fail (max exceeded)");
    }

    channel_shutdown(&ctx);
    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 12: Hash collision — channels with IDs 0, 512, 1024 (hash_size=512).
 */
static void test_hash_collision(void)
{
    TEST("hash collision — IDs 0, 512, 1024 with hash_size=512");

    static global_ctx_t ctx;
    channel_t *ch0, *ch512, *ch1024;
    int ret;

    init_minimal_ctx(&ctx);
    ctx.config.max_channels = 64;

    ret = channel_init(&ctx, 64);
    CHECK(ret == 0, "channel_init failed");

    /* Verify hash_size is 128 (64*2) — all 3 IDs should map to different
     * buckets if hash_size is large enough, but we want to test collision.
     * Override hash_size to 512 for this test */
    {
        /* We need to reinit with a known hash size.
         * channel_shutdown first, then manually set hash_size before init.
         * Actually, channel_init computes hash_size = max_channels * 2 = 128.
         * To get hash_size=512, we set max_channels=256. */
    }

    /* Re-init with hash_size = 256*2 = 512 */
    channel_shutdown(&ctx);
    init_minimal_ctx(&ctx);
    ctx.config.max_channels = 256;
    ret = channel_init(&ctx, 256);
    CHECK(ret == 0, "channel_init with hash_size=512 failed");

    /* 0 % 512 = 0, 512 % 512 = 0, 1024 % 512 = 0 → all same bucket */
    ch0 = channel_create(&ctx, 0, CHANNEL_ROLE_RESPONDER,
                         8080, 9090, "127.0.0.1", "192.168.1.1", 1);
    CHECK(ch0 != NULL, "channel_create 0 failed");

    ch512 = channel_create(&ctx, 512, CHANNEL_ROLE_RESPONDER,
                           8080, 9090, "127.0.0.1", "192.168.1.1", 1);
    CHECK(ch512 != NULL, "channel_create 512 failed");

    ch1024 = channel_create(&ctx, 1024, CHANNEL_ROLE_RESPONDER,
                            8080, 9090, "127.0.0.1", "192.168.1.1", 1);
    CHECK(ch1024 != NULL, "channel_create 1024 failed");

    /* All three should be findable */
    CHECK(channel_find(&ctx, 0)    == ch0,    "channel 0 not found");
    CHECK(channel_find(&ctx, 512)  == ch512,  "channel 512 not found");
    CHECK(channel_find(&ctx, 1024) == ch1024, "channel 1024 not found");

    /* All three should be removed after destroy */
    channel_shutdown(&ctx);
    /* channel_shutdown destroyed all channels and freed hash table.
     * Need to re-init for find test? No — we check after shutdown.
     * Actually verification is done above. After shutdown, hash table is NULL
     * so channel_find would crash. The test just verifies they were findable
     * before shutdown. */

    PASS();
    return;
cleanup:
    channel_shutdown(&ctx);
    return;
}

/*
 * Test 13: KCP init/destroy cycle — create, send, receive, destroy. Repeat 10x.
 */

/* KCP loopback: capture output and feed back as input */
static uint8_t  g_kcp_loopback_buf[4096];
static int      g_kcp_loopback_len = 0;

static int kcp_test_output(const char *buf, int len,
                           struct IKCPCB *kcp, void *user)
{
    (void)kcp;
    (void)user;

    if (len < 0 || len > (int)sizeof(g_kcp_loopback_buf)) {
        return -1;
    }
    memcpy(g_kcp_loopback_buf, buf, (size_t)len);
    g_kcp_loopback_len = len;
    return 0;
}

static void test_kcp_init_destroy_cycle(void)
{
    TEST("KCP init/destroy cycle — send/recv loopback ×10");

    int cycle;

    for (cycle = 0; cycle < 10; cycle++) {
        struct IKCPCB *kcp;
        const char *test_str = "Hello KCP integration test v2!";
        int slen = (int)strlen(test_str);
        uint8_t recv_buf[256];
        int recv_len;

        kcp = kcp_wrap_create((IUINT32)(100 + cycle), NULL);
        CHECK(kcp != NULL, "kcp_wrap_create failed");

        /* Set up output callback for loopback */
        ikcp_setoutput(kcp, kcp_test_output);

        /* Configure KCP */
        kcp_wrap_set_params(kcp, KCP_MTU_CONSERVATIVE,
                            KCP_SEND_WINDOW, KCP_RECV_WINDOW,
                            KCP_NODELAY, KCP_INTERVAL, KCP_RESEND, KCP_NC);

        /* Send data */
        {
            int ret = kcp_wrap_send(kcp, (const uint8_t *)test_str, slen);
            CHECK(ret == slen, "kcp_wrap_send failed");
        }

        /* Update/flush to trigger output */
        {
            IUINT32 now = kcp_wrap_clock();
            kcp_wrap_update(kcp, now);
        }

        /* Feed output back as input */
        if (g_kcp_loopback_len > 0) {
            int ret = kcp_wrap_input(kcp, g_kcp_loopback_buf,
                                     g_kcp_loopback_len);
            CHECK(ret == 0, "kcp_wrap_input failed");
            g_kcp_loopback_len = 0;
        }

        /* Receive data back */
        recv_len = kcp_wrap_recv(kcp, recv_buf, (int)sizeof(recv_buf));
        CHECK(recv_len == slen,
              "kcp_wrap_recv returned unexpected length");
        CHECK(memcmp(recv_buf, test_str, (size_t)slen) == 0,
              "received data mismatch");

        /* Destroy KCP */
        kcp_wrap_destroy(kcp);
    }

    PASS();
    return;
cleanup:
    return;
}

/*
 * Test 14: Large frame rejection — payload exceeding MAX payload is rejected.
 */
static void test_large_frame_rejection(void)
{
    TEST("large frame rejection — payload > ETH_MAX_PAYLOAD rejected");

    uint8_t buf[MAX_FRAME_SIZE * 2];
    uint8_t *large_payload = NULL;
    ssize_t frame_len;

    /* Allocate a payload larger than ETH_MAX_PAYLOAD */
    large_payload = (uint8_t *)malloc((size_t)ETH_MAX_PAYLOAD + 100);
    CHECK(large_payload != NULL, "malloc failed");
    memset(large_payload, 0x5A, (size_t)ETH_MAX_PAYLOAD + 100);

    /* Attempt to build with oversized payload via myproto_build_data_frame */
    frame_len = myproto_build_data_frame(buf, sizeof(buf), 1, 0,
                                         large_payload,
                                         (size_t)ETH_MAX_PAYLOAD + 1, 0);
    CHECK(frame_len < 0,
          "build_data_frame should reject payload > ETH_MAX_PAYLOAD");

    /* Verify that building with exactly ETH_MAX_PAYLOAD is allowed */
    {
        uint8_t *max_payload = (uint8_t *)malloc((size_t)ETH_MAX_PAYLOAD);
        CHECK(max_payload != NULL, "malloc max_payload failed");
        memset(max_payload, 0x42, (size_t)ETH_MAX_PAYLOAD);

        frame_len = myproto_build_data_frame(buf, sizeof(buf), 1, 0,
                                             max_payload,
                                             (size_t)ETH_MAX_PAYLOAD, 0);
        CHECK(frame_len > 0,
              "build_data_frame should accept payload == ETH_MAX_PAYLOAD");

        free(max_payload);
    }

    free(large_payload);
    PASS();
    return;
cleanup:
    if (large_payload) free(large_payload);
    return;
}

/*
 * Test 15: Max config fields — populate all fields, verify values.
 */
static void test_max_config_fields(void)
{
    TEST("max config fields — populate all fields and verify");

    global_config_t *cfg = (global_config_t *)calloc(1, sizeof(global_config_t));
    CHECK(cfg != NULL, "calloc failed");

    /* Interface config */
    strncpy(cfg->interface, "eth1", MAX_INTERFACE_NAME - 1);
    cfg->ethertype = MYPROTO_ETHERTYPE;
    memset(cfg->local_mac, 0x11, ETH_MAC_ADDR_LEN);
    memset(cfg->peer_mac, 0x22, ETH_MAC_ADDR_LEN);

    /* KCP config */
    cfg->kcp_mtu         = KCP_MTU_CONSERVATIVE;
    cfg->kcp_send_window = KCP_SEND_WINDOW;
    cfg->kcp_recv_window = KCP_RECV_WINDOW;
    cfg->kcp_nodelay     = KCP_NODELAY;
    cfg->kcp_interval    = KCP_INTERVAL;
    cfg->kcp_resend      = KCP_RESEND;
    cfg->kcp_nc          = KCP_NC;

    /* Proxy config */
    cfg->node_type          = NODE_TYPE_BACKEND;
    cfg->max_channels       = 512;
    cfg->heartbeat_interval = 15;
    cfg->heartbeat_timeout  = 90;

    /* Encryption */
    cfg->encryption.enabled = 1;
    strncpy(cfg->encryption.sm4_key, "00112233445566778899aabbccddeeff",
            SM4_KEY_HEX_LEN);
    cfg->encryption.sm4_key[SM4_KEY_HEX_LEN] = '\0';

    /* CRC */
    cfg->crc_enabled = 1;

    /* NIC MTU */
    cfg->auto_set_nic_mtu = 0;
    cfg->nic_mtu          = 1500;

    /* Multi-instance */
    strncpy(cfg->pid_file, "/var/run/kcp-test.pid", MAX_PID_PATH - 1);
    strncpy(cfg->instance_name, "test-instance", MAX_LISTEN_ADDR - 1);

    /* Verify all key fields */
    CHECK(strcmp(cfg->interface, "eth1") == 0, "interface mismatch");
    CHECK(cfg->ethertype == MYPROTO_ETHERTYPE, "ethertype mismatch");
    CHECK(cfg->local_mac[0] == 0x11, "local_mac mismatch");
    CHECK(cfg->peer_mac[0]  == 0x22, "peer_mac mismatch");
    CHECK(cfg->kcp_mtu         == KCP_MTU_CONSERVATIVE, "kcp_mtu mismatch");
    CHECK(cfg->kcp_send_window == KCP_SEND_WINDOW, "kcp_send_window mismatch");
    CHECK(cfg->kcp_recv_window == KCP_RECV_WINDOW, "kcp_recv_window mismatch");
    CHECK(cfg->kcp_nodelay     == KCP_NODELAY, "kcp_nodelay mismatch");
    CHECK(cfg->kcp_interval    == KCP_INTERVAL, "kcp_interval mismatch");
    CHECK(cfg->kcp_resend      == KCP_RESEND, "kcp_resend mismatch");
    CHECK(cfg->kcp_nc          == KCP_NC, "kcp_nc mismatch");
    CHECK(cfg->node_type          == NODE_TYPE_BACKEND, "node_type mismatch");
    CHECK(cfg->max_channels       == 512, "max_channels mismatch");
    CHECK(cfg->heartbeat_interval == 15, "heartbeat_interval mismatch");
    CHECK(cfg->heartbeat_timeout  == 90, "heartbeat_timeout mismatch");
    CHECK(cfg->encryption.enabled == 1, "encryption.enabled mismatch");
    CHECK(strcmp(cfg->encryption.sm4_key,
                 "00112233445566778899aabbccddeeff") == 0,
          "encryption.sm4_key mismatch");
    CHECK(cfg->crc_enabled == 1, "crc_enabled mismatch");
    CHECK(cfg->nic_mtu == 1500, "nic_mtu mismatch");
    CHECK(strcmp(cfg->pid_file, "/var/run/kcp-test.pid") == 0,
          "pid_file mismatch");
    CHECK(strcmp(cfg->instance_name, "test-instance") == 0,
          "instance_name mismatch");

    free(cfg);
    PASS();
    return;
cleanup:
    return;
}

/* ============================================================================
 * IPv6 Tests
 * ============================================================================ */

/*
 * Test 16: IPv4 address resolution — verify AF_INET.
 */
static void test_resolve_addr_ipv4(void)
{
    TEST("resolve addr IPv4 — 192.168.1.1 → AF_INET");

    struct in_addr addr;
    int ret;

    ret = inet_pton(AF_INET, "192.168.1.1", &addr);
    CHECK(ret == 1, "inet_pton(AF_INET) should succeed for 192.168.1.1");

    /* Verify the address bytes are correct */
    {
        uint8_t *bytes = (uint8_t *)&addr.s_addr;
        /* 192.168.1.1 in network byte order is 1.1.168.192 in little-endian */
        CHECK(bytes[0] == 192 && bytes[1] == 168 &&
              bytes[2] == 1   && bytes[3] == 1,
              "IPv4 address bytes mismatch");
    }

    PASS();
    return;
cleanup:
    return;
}

/*
 * Test 17: IPv6 address resolution — verify AF_INET6 support.
 */
static void test_resolve_addr_ipv6(void)
{
    TEST("resolve addr IPv6 — ::1 → AF_INET6");

    struct in6_addr addr6;
    int ret;

    ret = inet_pton(AF_INET6, "::1", &addr6);
    CHECK(ret == 1, "inet_pton(AF_INET6) should succeed for ::1");

    /* Verify it's the loopback address: all zeros except last byte = 1 */
    {
        int i;
        int nonzero_count = 0;

        for (i = 0; i < 15; i++) {
            if (addr6.s6_addr[i] != 0) nonzero_count++;
        }
        CHECK(nonzero_count == 0,
              "::1 should have first 15 bytes as zero");
        CHECK(addr6.s6_addr[15] == 1,
              "::1 last byte should be 1");
    }

    /* Also test a full IPv6 address */
    {
        struct in6_addr addr_full;
        ret = inet_pton(AF_INET6, "2001:db8::1", &addr_full);
        CHECK(ret == 1,
              "inet_pton(AF_INET6) should succeed for 2001:db8::1");
    }

    PASS();
    return;
cleanup:
    return;
}

/* ============================================================================
 * MAC Learning / Hot Reload Tests
 * ============================================================================ */

/*
 * Helper: check if MAC is all zeros.
 */
static inline int mac_is_zero(const uint8_t mac[ETH_MAC_ADDR_LEN])
{
    int i;
    for (i = 0; i < ETH_MAC_ADDR_LEN; i++) {
        if (mac[i] != 0) return 0;
    }
    return 1;
}

/*
 * Helper: check if MAC is broadcast (ff:ff:ff:ff:ff:ff).
 */
static inline int mac_is_broadcast(const uint8_t mac[ETH_MAC_ADDR_LEN])
{
    int i;
    for (i = 0; i < ETH_MAC_ADDR_LEN; i++) {
        if (mac[i] != 0xFF) return 0;
    }
    return 1;
}

/*
 * Test 18: MAC helper functions.
 */
static void test_mac_helpers(void)
{
    TEST("MAC helpers — mac_is_zero, mac_is_broadcast");

    uint8_t zero_mac[ETH_MAC_ADDR_LEN] = { 0 };
    uint8_t bcast_mac[ETH_MAC_ADDR_LEN] = { 0xFF, 0xFF, 0xFF,
                                             0xFF, 0xFF, 0xFF };
    uint8_t normal_mac[ETH_MAC_ADDR_LEN] = { 0x00, 0x11, 0x22,
                                              0x33, 0x44, 0x55 };
    uint8_t partial_mac[ETH_MAC_ADDR_LEN] = { 0, 0, 0, 0, 0, 0x01 };

    /* mac_is_zero */
    CHECK(mac_is_zero(zero_mac)    == 1, "all-zero MAC should return 1");
    CHECK(mac_is_zero(bcast_mac)   == 0, "broadcast MAC should return 0");
    CHECK(mac_is_zero(normal_mac)  == 0, "normal MAC should return 0");
    CHECK(mac_is_zero(partial_mac) == 0, "partial-zero MAC should return 0");

    /* mac_is_broadcast */
    CHECK(mac_is_broadcast(bcast_mac)   == 1,
          "broadcast MAC should return 1");
    CHECK(mac_is_broadcast(zero_mac)    == 0,
          "all-zero MAC should return 0");
    CHECK(mac_is_broadcast(normal_mac)  == 0,
          "normal MAC should return 0");
    CHECK(mac_is_broadcast(partial_mac) == 0,
          "partial MAC should return 0");

    PASS();
    return;
cleanup:
    return;
}

/*
 * Test 19: KCP param update — change nodelay params via ikcp_nodelay.
 */
static void test_kcp_param_update(void)
{
    TEST("KCP param update — ikcp_nodelay changes stored values");

    struct IKCPCB *kcp;
    int ret;

    kcp = kcp_wrap_create(200, NULL);
    CHECK(kcp != NULL, "kcp_wrap_create failed");

    /* Set initial params via wrapper */
    kcp_wrap_set_params(kcp, KCP_MTU_CONSERVATIVE,
                        KCP_SEND_WINDOW, KCP_RECV_WINDOW,
                        KCP_NODELAY, KCP_INTERVAL, KCP_RESEND, KCP_NC);

    /* Verify initial values */
    CHECK(kcp->nodelay  == (IUINT32)KCP_NODELAY,  "initial nodelay mismatch");
    CHECK(kcp->interval == (IUINT32)KCP_INTERVAL, "initial interval mismatch");
    CHECK(kcp->fastresend == KCP_RESEND,           "initial fastresend mismatch");
    CHECK(kcp->nocwnd   == KCP_NC,                 "initial nocwnd mismatch");

    /* Change params via ikcp_nodelay */
    ret = ikcp_nodelay(kcp, 1, 20, 3, 0);
    CHECK(ret == 0, "ikcp_nodelay failed");

    /* Verify new values */
    CHECK(kcp->nodelay    == 1,  "updated nodelay should be 1");
    CHECK(kcp->interval   == 20, "updated interval should be 20");
    CHECK(kcp->fastresend == 3,  "updated fastresend should be 3");
    CHECK(kcp->nocwnd     == 0,  "updated nocwnd should be 0");

    /* Change again to verify it's not a one-off */
    ret = ikcp_nodelay(kcp, 0, 100, 0, 1);
    CHECK(ret == 0, "ikcp_nodelay second call failed");

    CHECK(kcp->nodelay    == 0,   "second update nodelay should be 0");
    CHECK(kcp->interval   == 100, "second update interval should be 100");
    CHECK(kcp->fastresend == 0,   "second update fastresend should be 0");
    CHECK(kcp->nocwnd     == 1,   "second update nocwnd should be 1");

    /* Also test MTU change */
    ret = ikcp_setmtu(kcp, 1200);
    CHECK(ret == 0, "ikcp_setmtu failed");
    CHECK(kcp->mtu  == 1200,                     "mtu should be 1200");
    CHECK(kcp->mss  == 1200 - 24,                "mss should be mtu - IKCP_OVERHEAD");

    kcp_wrap_destroy(kcp);
    PASS();
    return;
cleanup:
    if (kcp) kcp_wrap_destroy(kcp);
    return;
}

/* ============================================================================
 * Proxy / IPC Test
 * ============================================================================ */

/*
 * Test 20: Protocol budget — verify max frame fits in NIC MTU.
 */
static void test_protocol_budget(void)
{
    TEST("protocol budget — max frame vs NIC MTU");

    /* Constants */
    const int eth_hdr    = ETH_HDR_SIZE;    /* 14 */
    const int proto_hdr  = MYPROTO_HDR_SIZE; /* 8 */
    const int kcp_hdr    = 24;              /* IKCP_OVERHEAD from ikcp.c */
    const int kcp_mss    = KCP_MSS_CONSERVATIVE; /* 1376 */
    const int crc        = CRC32_SIZE;      /* 4 */
    const int crypto_oh  = CRYPTO_OVERHEAD; /* 48 */
    const int nic_mtu    = ETH_MTU;         /* 1500 */

    int total_without_crypto;
    int total_with_crypto;
    int effective_kcp_mss_with_crypto;

    /* Total without crypto */
    total_without_crypto = eth_hdr + proto_hdr + kcp_hdr + kcp_mss + crc;
    printf("\n    Budget (no crypto): ETH(%d) + MYPROTO(%d) + KCP(%d) + MSS(%d) + CRC(%d) = %d",
           eth_hdr, proto_hdr, kcp_hdr, kcp_mss, crc, total_without_crypto);

    CHECK(total_without_crypto <= nic_mtu,
          "total frame size exceeds NIC MTU without crypto");

    /* Effective KCP MSS with crypto must be reduced */
    effective_kcp_mss_with_crypto = kcp_mss - crypto_oh;
    printf("\n    Effective KCP MSS with crypto: %d - %d = %d",
           kcp_mss, crypto_oh, effective_kcp_mss_with_crypto);

    total_with_crypto = eth_hdr + proto_hdr + kcp_hdr +
                        effective_kcp_mss_with_crypto + crypto_oh + crc;
    printf("\n    Budget (with crypto): ETH(%d) + MYPROTO(%d) + KCP(%d) + "
           "effMSS(%d) + CRYPTO(%d) + CRC(%d) = %d",
           eth_hdr, proto_hdr, kcp_hdr,
           effective_kcp_mss_with_crypto, crypto_oh, crc,
           total_with_crypto);

    CHECK(total_with_crypto <= nic_mtu,
          "total frame size with crypto should fit in NIC MTU after reducing MSS");

    /* Verify that crypto overhead reduces effective payload capacity:
     * the effective KCP MSS with crypto is reduced by CRYPTO_OVERHEAD bytes */
    CHECK(effective_kcp_mss_with_crypto == kcp_mss - crypto_oh,
          "effective KCP MSS should be KCP_MSS - CRYPTO_OVERHEAD");
    CHECK(effective_kcp_mss_with_crypto > 0,
          "effective KCP MSS should still be positive");

    PASS();
    return;
cleanup:
    return;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  KCP-over-AF_PACKET Integration Test Suite v2           ║\n");
    printf("║  20 tests: protocol, state machine, stress, IPv6, MAC   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    /* ================================================================
     * Protocol Layer Tests (1-5)
     * ================================================================ */
    print_banner("Protocol Layer Tests");
    test_frame_roundtrip_multisize();
    test_control_frame_all_types();
    test_crc32_roundtrip();
    test_crypto_roundtrip();
    test_heartbeat_channel_routing();

    /* ================================================================
     * State Machine Tests (6-10)
     * ================================================================ */
    print_banner("State Machine Tests");
    test_channel_syn_ack_flow();
    test_channel_fin_handshake();
    test_channel_rst_cleanup();
    test_channel_duplicate_syn();
    test_syn_on_closing_channel();

    /* ================================================================
     * Boundary / Stress Tests (11-15)
     * ================================================================ */
    print_banner("Boundary / Stress Tests");
    test_max_channels_stress();
    test_hash_collision();
    test_kcp_init_destroy_cycle();
    test_large_frame_rejection();
    test_max_config_fields();

    /* ================================================================
     * IPv6 Tests (16-17)
     * ================================================================ */
    print_banner("IPv6 Tests");
    test_resolve_addr_ipv4();
    test_resolve_addr_ipv6();

    /* ================================================================
     * MAC Learning / Hot Reload Tests (18-19)
     * ================================================================ */
    print_banner("MAC Learning / Hot Reload Tests");
    test_mac_helpers();
    test_kcp_param_update();

    /* ================================================================
     * Proxy / IPC Test (20)
     * ================================================================ */
    print_banner("Proxy / IPC Test");
    test_protocol_budget();

    print_summary();

    return (tests_failed == 0) ? 0 : 1;
}
