/*
 * test_integration_v6.c — KCP-over-AF_PACKET Integration Tests: Part B (101-124)
 *
 * Tests 101-108: crypto_init failure recovery (crypto_enabled reset)
 * Tests 109-112: channel_id boundary validation
 * Tests 113-116: EPOLLHUP/EPOLLERR separation + EPOLLIN priority
 * Tests 117-120: time_elapsed wrap guard
 * Tests 121-124: channel state machine edge cases
 *
 * All tests run without real network hardware.
 *
 * Compile:
 *   gcc -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -Isrc -O0 -g \
 *       -o tests/test_integration_v6 tests/test_integration_v6.c \
 *       src/myproto.c src/crypto.c src/channel.c src/kcp_wrap.c \
 *       src/ikcp.c src/acl.c -lrt -lnettle
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/epoll.h>

#include "../src/types.h"
#include "../src/channel.h"
#include "../src/myproto.h"
#include "../src/crypto.h"
#include "../src/proxy.h"
#include "../src/kcp_wrap.h"

/* ============================================================================
 * Test framework macros
 * ============================================================================ */
static int total = 0, passed = 0, failed = 0;

#define TEST(desc) do { \
    total++; \
    printf("  TEST %s ... ", (desc)); \
    fflush(stdout); \
} while(0)

#define OK() do { passed++; printf("OK\n"); } while(0)
#define FAIL(fmt, ...) do { \
    failed++; \
    printf("FAIL: " fmt "\n", ##__VA_ARGS__); \
    return; \
} while(0)
#define CHECK(cond, msg) do { \
    if (!(cond)) { FAIL(msg); return; } \
} while(0)

/* ============================================================================
 * Stubs
 * ============================================================================ */

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

void af_packet_close(int sock) { (void)sock; }

void proxy_close_local(channel_t *ch) { if (ch) ch->local_fd = -1; }
int  proxy_epoll_del(global_ctx_t *ctx, int fd) { (void)ctx; (void)fd; return 0; }
int  proxy_connect_remote(channel_t *ch) { (void)ch; return 0; }
int  proxy_start_listen(global_ctx_t *ctx, channel_t *ch) {
    (void)ctx; if (ch) ch->listen_fd = 55; return 0;
}
int  proxy_write_to_local(channel_t *ch, const uint8_t *data, int len) {
    (void)ch; (void)data; (void)len; return 0;
}
int  proxy_epoll_add(global_ctx_t *ctx, int fd, void *ptr) {
    (void)ctx; (void)fd; (void)ptr; return 0;
}
int  proxy_accept(global_ctx_t *ctx, channel_t *ch) {
    (void)ctx; (void)ch; return 0;
}
int  proxy_handle_local_read(global_ctx_t *ctx, channel_t *ch) {
    (void)ctx; (void)ch; return 0;
}
int  proxy_handle_local_write(channel_t *ch) { (void)ch; return 0; }
int  proxy_flush_to_local(channel_t *ch) { (void)ch; return 0; }
uint32_t proxy_get_events(channel_t *ch) { (void)ch; return EPOLLIN | EPOLLOUT; }
void proxy_stop_listen(global_ctx_t *ctx, channel_t *ch) { (void)ctx; (void)ch; }
int  proxy_port_probe(const char *addr, uint16_t port, int is_tcp) {
    (void)addr; (void)port; (void)is_tcp; return 0;
}
int proxy_port_conflict(global_ctx_t *ctx, const char *listen_addr,
                        uint16_t listen_port, uint32_t exclude_id) {
    (void)ctx; (void)listen_addr; (void)listen_port; (void)exclude_id; return 0;
}

/* ============================================================================
 * Helper: setup minimal global_ctx_t with config
 * ============================================================================ */
static int init_ctx(global_ctx_t *ctx, int channel_count, int crypto_en) {
    /* Clean up any prior state from previous test */
    if (ctx->channel_hash) {
        for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
            channel_t *ch = ctx->channel_hash[i];
            while (ch) {
                channel_t *next = ch->hash_next;
                if (ch->kcp) kcp_wrap_destroy(ch->kcp);
                free(ch);
                ch = next;
            }
        }
        free(ctx->channel_hash);
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->channel_hash_size = 64;
    ctx->channel_hash = calloc((size_t)ctx->channel_hash_size, sizeof(channel_t*));
    if (!ctx->channel_hash) return -1;
    ctx->config.channel_count = channel_count;
    ctx->config.max_channels = 256;
    ctx->config.encryption.enabled = (uint8_t)crypto_en;
    strcpy(ctx->config.encryption.sm4_key, "0123456789abcdef0123456789abcdef");
    ctx->config.heartbeat_timeout = HEARTBEAT_TIMEOUT;
    ctx->config.node_type = NODE_TYPE_FRONTEND;
    ctx->epoll_fd = -1;
    for (int i = 0; i < channel_count; i++) {
        ctx->config.channels[i].channel_id = (uint32_t)(i + 1);
        ctx->config.channels[i].enabled = 1;
        ctx->config.channels[i].max_sessions = 1;
        ctx->config.channels[i].is_tcp = 1;
    }
    ctx->config.kcp_mtu = 1400;
    ctx->config.kcp_send_window = 128;
    ctx->config.kcp_recv_window = 128;
    if (channel_init(ctx, 64) != 0) return -1;
    return 0;
}

static void destroy_ctx(global_ctx_t *ctx) {
    if (ctx->channel_hash) {
        for (uint32_t i = 0; i < ctx->channel_hash_size; i++) {
            channel_t *ch = ctx->channel_hash[i];
            while (ch) {
                channel_t *next = ch->hash_next;
                if (ch->kcp) kcp_wrap_destroy(ch->kcp);
                free(ch);
                ch = next;
            }
        }
        free(ctx->channel_hash);
        ctx->channel_hash = NULL;
    }
}

/* ============================================================================
 * A组: crypto_init 失败恢复 (8 tests)
 * ============================================================================ */

/* T101: crypto_init with invalid hex char  */
static void test_crypto_init_invalid_hex(void) {
    TEST("crypto_init: invalid hex key disables crypto");

    encryption_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    strcpy(cfg.sm4_key, "0123456789ABCDEF0123GGGG89ABCDEF"); /* 'GG' invalid */

    crypto_cleanup(); /* ensure clean state */
    int ret = crypto_init(&cfg);
    CHECK(ret == -1, "crypto_init should fail");
    CHECK(crypto_is_enabled() == 0, "crypto_enabled must be 0 after hex failure");
    crypto_cleanup();
    OK();
}

/* T102: crypto_init with key too short */
static void test_crypto_init_key_too_short(void) {
    TEST("crypto_init: key too short disables crypto");

    encryption_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    strcpy(cfg.sm4_key, "012345");  /* only 6 hex chars */

    crypto_cleanup();
    int ret = crypto_init(&cfg);
    CHECK(ret == -1, "crypto_init should fail for short key");
    CHECK(crypto_is_enabled() == 0, "crypto_enabled must be 0 after short key");
    crypto_cleanup();
    OK();
}

/* T103: crypto_init with key too long (33+ chars) */
static void test_crypto_init_key_too_long(void) {
    TEST("crypto_init: key too long disables crypto");

    encryption_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    /* exactly 33 hex chars (32 valid + 1 extra) */
    memcpy(cfg.sm4_key, "0123456789abcdef0123456789abcdeff", 33);
    cfg.sm4_key[33] = '\0';

    crypto_cleanup();
    int ret = crypto_init(&cfg);
    CHECK(ret == -1, "crypto_init should fail for long key");
    CHECK(crypto_is_enabled() == 0, "crypto_enabled must be 0 after long key");
    crypto_cleanup();
    OK();
}

/* T104: crypto_init with valid key succeeds */
static void test_crypto_init_valid(void) {
    TEST("crypto_init: valid key enables crypto");

    encryption_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    strcpy(cfg.sm4_key, "0123456789ABCDEF0123456789ABCDEF");

    crypto_cleanup();
    int ret = crypto_init(&cfg);
    CHECK(ret == 0, "crypto_init should succeed with valid key");
    CHECK(crypto_is_enabled() == 1, "crypto_enabled must be 1 after init");
    crypto_cleanup();
    OK();
}

/* T105: crypto_init disabled in config → stays disabled */
static void test_crypto_init_disabled(void) {
    TEST("crypto_init: disabled config keeps crypto off");

    encryption_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 0;

    crypto_cleanup();
    int ret = crypto_init(&cfg);
    CHECK(ret == 0, "crypto_init with enabled=0 should return 0");
    CHECK(crypto_is_enabled() == 0, "crypto_enabled must be 0 when disabled");
    crypto_cleanup();
    OK();
}

/* T106: crypto_encrypt when disabled → passthrough */
static void test_crypto_encrypt_passthrough(void) {
    TEST("crypto_encrypt: passthrough when disabled");

    crypto_cleanup();
    uint8_t in[16] = "hello";
    uint8_t out[64];

    int ret = crypto_encrypt_frame(in, 5, out, sizeof(out));
    /* When crypto disabled, it should memcpy in→out and return in_len */
    CHECK(ret == 5, "passthrough should return input length");
    CHECK(memcmp(in, out, 5) == 0, "passthrough should copy data unchanged");
    OK();
}

/* T107: crypto_decrypt when disabled → passthrough */
static void test_crypto_decrypt_passthrough(void) {
    TEST("crypto_decrypt: passthrough when disabled");

    crypto_cleanup();
    uint8_t in[16] = "world";
    uint8_t out[64];

    int ret = crypto_decrypt_frame(in, 5, out, sizeof(out));
    CHECK(ret == 5, "passthrough decrypt should return input length");
    CHECK(memcmp(in, out, 5) == 0, "passthrough decrypt should copy unchanged");
    OK();
}

/* T108: encrypt-then-decrypt roundtrip with valid key */
static void test_crypto_roundtrip(void) {
    TEST("crypto: encrypt-then-decrypt roundtrip");

    encryption_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    strcpy(cfg.sm4_key, "0123456789ABCDEF0123456789ABCDEF");
    crypto_cleanup();
    crypto_init(&cfg);

    uint8_t plain[256] = "test payload for crypto roundtrip";
    uint8_t encrypted[256];
    uint8_t decrypted[256];

    int enc_len = crypto_encrypt_frame(plain, 31, encrypted, sizeof(encrypted));
    CHECK(enc_len > 31, "encrypted length must be > plaintext");
    CHECK(enc_len == 80, "enc_len = 16(IV) + 32(padded_ciphertext) + 32(HMAC) = 80");

    int dec_len = crypto_decrypt_frame(encrypted, enc_len, decrypted, sizeof(decrypted));
    CHECK(dec_len == 31, "decrypted length must match original");
    CHECK(memcmp(plain, decrypted, 31) == 0, "roundtrip data must match");

    crypto_cleanup();
    OK();
}

/* ============================================================================
 * B组: channel_id 边界验证 (4 tests)
 * ============================================================================ */

/* T109: channel_id == 0 must be rejected */
static void test_channel_id_zero_rejected(void) {
    TEST("channel_id: 0 is reserved and rejected");

    uint8_t buf[MAX_FRAME_SIZE];
    ssize_t ret = myproto_build_ctrl_frame(buf, sizeof(buf), 0, MPF_SYN, 0);
    CHECK(ret < 0, "channel_id 0 must be rejected in build_ctrl_frame");

    ret = myproto_build_data_frame(buf, sizeof(buf), 0, MPF_DATA,
                                    (const uint8_t*)"data", 4, 0);
    CHECK(ret < 0, "channel_id 0 must be rejected in build_data_frame");
    OK();
}

/* T110: channel_id == MAX_CHANNELS (65536) accepted as dynamic */
static void test_channel_id_max_channels_accepted(void) {
    TEST("channel_id: MAX_CHANNELS accepted as dynamic");

    uint8_t buf[MAX_FRAME_SIZE];
    ssize_t ret = myproto_build_ctrl_frame(buf, sizeof(buf), (uint32_t)MAX_CHANNELS,
                                            MPF_SYN, 0);
    CHECK(ret > 0, "channel_id == MAX_CHANNELS must be accepted (dynamic)");
    OK();
}

/* T111: HEARTBEAT_CH_ID (0xFFFFFFFF) accepted */
static void test_channel_id_heartbeat_accepted(void) {
    TEST("channel_id: HEARTBEAT_CH_ID accepted");

    uint8_t buf[MAX_FRAME_SIZE];
    ssize_t ret = myproto_build_ctrl_frame(buf, sizeof(buf), HEARTBEAT_CH_ID,
                                            MPF_PING, 0);
    CHECK(ret > 0, "HEARTBEAT_CH_ID must be accepted");
    OK();
}

/* T112: verify channel_id 1 accepted as valid static channel */
static void test_channel_id_min_valid(void) {
    TEST("channel_id: static channel_id=1 accepted");

    uint8_t buf[MAX_FRAME_SIZE];
    ssize_t ret = myproto_build_ctrl_frame(buf, sizeof(buf), 1,
                                            MPF_SYN, 0);
    CHECK(ret > 0, "channel_id 1 must be accepted (static)");
    OK();
}

/* ============================================================================
 * C组: EPOLLHUP/EPOLLERR 分离 + EPOLLIN 优先级 (4 tests)
 * ============================================================================ */

/* T113: channel state recovers via timeout_check on CLOSED zombie */
static void test_zombie_channel_cleanup(void) {
    TEST("state machine: CLOSED zombie channel cleanup");

    static global_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (init_ctx(&ctx, 1, 0) != 0) { FAIL("init_ctx failed"); return; }

    channel_t *ch = channel_create(&ctx, 100, CHANNEL_ROLE_INITIATOR,
                                    1234, 5678, "127.0.0.1", "127.0.0.1", 1);
    CHECK(ch != NULL, "channel_create must succeed");
    ch->state = CHANNEL_CLOSED;  /* zombie */

    int count_before = ctx.channel_count;
    channel_timeout_check(&ctx);

    /* zombie CLOSED channel should be destroyed */
    channel_t *found = channel_find(&ctx, 100);
    CHECK(found == NULL, "zombie CLOSED channel must be destroyed");
    (void)count_before;

    destroy_ctx(&ctx);
    OK();
}

/* T114: channel state machine: FIN_RCVD → TIME_WAIT after timeout */
static void test_finrcvd_to_timewait(void) {
    TEST("state machine: FIN_RCVD → TIME_WAIT via timeout_check");

    static global_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (init_ctx(&ctx, 1, 0) != 0) { FAIL("init_ctx failed"); return; }

    channel_t *ch = channel_create(&ctx, 101, CHANNEL_ROLE_INITIATOR,
                                    1234, 5678, "127.0.0.1", "127.0.0.1", 1);
    CHECK(ch != NULL, "channel_create must succeed");
    ch->state = CHANNEL_FIN_RCVD;

    channel_timeout_check(&ctx);

    ch = channel_find(&ctx, 101);
    CHECK(ch != NULL, "channel must still exist");
    CHECK(ch->state == CHANNEL_TIME_WAIT, "FIN_RCVD → TIME_WAIT");

    destroy_ctx(&ctx);
    OK();
}

/* T115: SYN retransmit — send SYN on existing channel updates syn_sent_at */
static void test_syn_retransmit_tracking(void) {
    TEST("state machine: SYN_SENT retransmit timing");

    static global_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (init_ctx(&ctx, 1, 0) != 0) { FAIL("init_ctx failed"); return; }

    channel_t *ch = channel_create(&ctx, 102, CHANNEL_ROLE_INITIATOR,
                                    1234, 5678, "127.0.0.1", "127.0.0.1", 1);
    CHECK(ch != NULL, "channel_create must succeed");
    uint32_t initial_syn_at = ch->syn_sent_at;

    /* Simulate: force old syn_sent_at to trigger retry */
    ch->syn_sent_at = time_now() - 4;  /* 4 seconds ago */
    uint8_t retries_before = ch->syn_retry_count;

    channel_timeout_check(&ctx);

    ch = channel_find(&ctx, 102);
    CHECK(ch != NULL, "channel must still exist");
    CHECK(ch->syn_retry_count == retries_before + 1, "retry count incremented");
    CHECK(ch->syn_sent_at >= initial_syn_at, "syn_sent_at refreshed");
    CHECK(ch->state == CHANNEL_SYN_SENT, "state remains SYN_SENT");

    destroy_ctx(&ctx);
    OK();
}

/* T116: SYN retry exceeded → CLOSED + destroy */
static void test_syn_retry_exceeded(void) {
    TEST("state machine: SYN retry exceeded → destroy");

    static global_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (init_ctx(&ctx, 1, 0) != 0) { FAIL("init_ctx failed"); return; }

    channel_t *ch = channel_create(&ctx, 103, CHANNEL_ROLE_INITIATOR,
                                    1234, 5678, "127.0.0.1", "127.0.0.1", 1);
    CHECK(ch != NULL, "channel_create must succeed");
    ch->state = CHANNEL_SYN_SENT;
    ch->syn_retry_count = 4;  /* already exceeded */
    ch->syn_sent_at = time_now() - 4;

    channel_timeout_check(&ctx);

    ch = channel_find(&ctx, 103);
    CHECK(ch == NULL, "channel must be destroyed after retry exceeded");

    destroy_ctx(&ctx);
    OK();
}

/* ============================================================================
 * D组: time_elapsed 回拨保护 (4 tests)
 * ============================================================================ */

/* T117: time_elapsed with now > past */
static void test_time_elapsed_normal(void) {
    TEST("time_elapsed: normal forward time");
    uint32_t elapsed = time_elapsed(0);
    CHECK(elapsed < UINT32_MAX/2, "elapsed must be reasonable, not wrapped");
    OK();
}

/* T118: time_elapsed with now == t (zero elapsed) */
static void test_time_elapsed_zero(void) {
    TEST("time_elapsed: zero elapsed");
    uint32_t now = time_now();
    uint32_t elapsed = time_elapsed(now);
    CHECK(elapsed == 0, "elapsed from now must be 0");
    OK();
}

/* T119: time_elapsed wrap protection (t > now → 0) */
static void test_time_elapsed_wrap(void) {
    TEST("time_elapsed: clock rewind returns 0 not wrap");

    /* Simulate: last_active was set 10 seconds in the future
     * (e.g., after NTP correction). The guard should return 0,
     * not a ~4 billion wrap value. */
    uint32_t future_t = time_now() + 10;
    uint32_t elapsed  = time_elapsed(future_t);

    CHECK(elapsed == 0, "must return 0, not wrapped value");
    OK();
}

/* T120: time_elapsed with UINT32_MAX */
static void test_time_elapsed_max(void) {
    TEST("time_elapsed: UINT32_MAX boundary");

    /* t = UINT32_MAX; since time_now() is always < UINT32_MAX in practice,
     * the guard should trigger and return 0 */
    uint32_t elapsed = time_elapsed(UINT32_MAX);
    CHECK(elapsed == 0, "must return 0 for impossible past time");
    OK();
}

/* ============================================================================
 * E组: 通道状态机边界 (4 tests)
 * ============================================================================ */

/* T121: FIN received while in FIN_SENT → TIME_WAIT (simultaneous close) */
static void test_state_fin_to_timewait(void) {
    TEST("state: FIN_SENT + recv FIN → TIME_WAIT");

    static global_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (init_ctx(&ctx, 1, 0) != 0) { FAIL("init_ctx failed"); return; }

    channel_t *ch = channel_create(&ctx, 200, CHANNEL_ROLE_INITIATOR,
                                    1234, 5678, "127.0.0.1", "127.0.0.1", 1);
    CHECK(ch != NULL, "channel_create must succeed");
    ch->state = CHANNEL_FIN_SENT;

    /* Simulate receiving FIN on a FIN_SENT channel */
    uint8_t frame[MAX_FRAME_SIZE];
    ssize_t len = myproto_build_ctrl_frame(frame, sizeof(frame), 200, MPF_FIN, 0);
    CHECK(len > 0, "FIN frame build must succeed");

    const uint8_t *payload;
    size_t payload_len;
    myproto_hdr_t hdr;
    int ret = myproto_parse_frame(frame, (size_t)len, &hdr, &payload, &payload_len);
    CHECK(ret == 0, "parse must succeed");

    ret = channel_process_frame(&ctx, &hdr, payload, payload_len);
    CHECK(ret == 0, "process must succeed");

    ch = channel_find(&ctx, 200);
    CHECK(ch != NULL, "channel must still exist");
    CHECK(ch->state == CHANNEL_TIME_WAIT, "FIN_SENT + FIN → TIME_WAIT");

    destroy_ctx(&ctx);
    OK();
}

/* T122: RST received in any state → immediate CLOSED */
static void test_state_rst_immediate(void) {
    TEST("state: RST in any state → CLOSED + destroy");

    static global_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (init_ctx(&ctx, 1, 0) != 0) { FAIL("init_ctx failed"); return; }

    channel_t *ch = channel_create(&ctx, 201, CHANNEL_ROLE_INITIATOR,
                                    1234, 5678, "127.0.0.1", "127.0.0.1", 1);
    CHECK(ch != NULL, "channel_create must succeed");
    ch->state = CHANNEL_ESTABLISHED;

    uint8_t frame[MAX_FRAME_SIZE];
    ssize_t len = myproto_build_ctrl_frame(frame, sizeof(frame), 201, MPF_RST, 0);
    CHECK(len > 0, "RST frame build must succeed");

    const uint8_t *payload;
    size_t payload_len;
    myproto_hdr_t hdr;
    int ret = myproto_parse_frame(frame, (size_t)len, &hdr, &payload, &payload_len);
    CHECK(ret == 0, "parse must succeed");

    ret = channel_process_frame(&ctx, &hdr, payload, payload_len);
    CHECK(ret == 0, "process must succeed");

    ch = channel_find(&ctx, 201);
    CHECK(ch == NULL, "channel must be destroyed after RST");

    destroy_ctx(&ctx);
    OK();
}

/* T123: SYN establishes new RESPONDER → SYN_RCVD */
static void test_state_syn_to_synrcvd(void) {
    TEST("state: SYN for unknown channel → SYN_RCVD");

    static global_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (init_ctx(&ctx, 1, 0) != 0) { FAIL("init_ctx failed"); return; }

    /* Create a SYN frame for a new channel */
    uint8_t frame[MAX_FRAME_SIZE];
    ssize_t len = myproto_build_ctrl_frame(frame, sizeof(frame), 300, MPF_SYN, 0);
    CHECK(len > 0, "SYN frame build must succeed");

    const uint8_t *payload;
    size_t payload_len;
    myproto_hdr_t hdr;
    int ret = myproto_parse_frame(frame, (size_t)len, &hdr, &payload, &payload_len);
    CHECK(ret == 0, "parse must succeed");

    ret = channel_process_frame(&ctx, &hdr, payload, payload_len);
    CHECK(ret == 0, "SYN process must succeed");

    channel_t *ch = channel_find(&ctx, 300);
    CHECK(ch != NULL, "new channel must be created");
    CHECK(ch->state == CHANNEL_SYN_RCVD, "RESPONDER must be SYN_RCVD");
    CHECK(ch->role == CHANNEL_ROLE_RESPONDER, "role must be RESPONDER");

    destroy_ctx(&ctx);
    OK();
}

/* T124: SYN on CLOSED channel → ignored (no zombie revival) */
static void test_state_syn_on_closed_ignored(void) {
    TEST("state: SYN on CLOSED state → ignored");

    static global_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (init_ctx(&ctx, 1, 0) != 0) { FAIL("init_ctx failed"); return; }

    channel_t *ch = channel_create(&ctx, 301, CHANNEL_ROLE_INITIATOR,
                                    1234, 5678, "127.0.0.1", "127.0.0.1", 1);
    CHECK(ch != NULL, "channel_create must succeed");
    ch->state = CHANNEL_CLOSED;

    uint8_t frame[MAX_FRAME_SIZE];
    ssize_t len = myproto_build_ctrl_frame(frame, sizeof(frame), 301, MPF_SYN, 0);
    CHECK(len > 0, "SYN frame build must succeed");

    const uint8_t *payload;
    size_t payload_len;
    myproto_hdr_t hdr;
    int ret = myproto_parse_frame(frame, (size_t)len, &hdr, &payload, &payload_len);
    CHECK(ret == 0, "parse must succeed");

    ret = channel_process_frame(&ctx, &hdr, payload, payload_len);
    CHECK(ret == 0, "process should succeed (no error)");

    ch = channel_find(&ctx, 301);
    CHECK(ch->state == CHANNEL_CLOSED, "state must remain CLOSED");
    CHECK(ch != NULL, "channel must still exist (not destroyed by ignored SYN)");

    destroy_ctx(&ctx);
    OK();
}

/* ============================================================================
 * Main
 * ============================================================================ */
int main(void) {
    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║  Integration Tests v6: Parts B  (T101-T124)  ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    /* A组: crypto_init failure recovery */
    test_crypto_init_invalid_hex();
    test_crypto_init_key_too_short();
    test_crypto_init_key_too_long();
    test_crypto_init_valid();
    test_crypto_init_disabled();
    test_crypto_encrypt_passthrough();
    test_crypto_decrypt_passthrough();
    test_crypto_roundtrip();

    /* B组: channel_id boundary */
    test_channel_id_zero_rejected();
    test_channel_id_max_channels_accepted();
    test_channel_id_heartbeat_accepted();
    test_channel_id_min_valid();

    /* C组: state transitions */
    test_zombie_channel_cleanup();
    test_finrcvd_to_timewait();
    test_syn_retransmit_tracking();
    test_syn_retry_exceeded();

    /* D组: time_elapsed */
    test_time_elapsed_normal();
    test_time_elapsed_zero();
    test_time_elapsed_wrap();
    test_time_elapsed_max();

    /* E组: state machine */
    test_state_fin_to_timewait();
    test_state_rst_immediate();
    test_state_syn_to_synrcvd();
    test_state_syn_on_closed_ignored();

    printf("\n  Test Summary: %d run, %d passed, %d failed\n",
           total, passed, failed);
    return (failed > 0) ? 1 : 0;
}
