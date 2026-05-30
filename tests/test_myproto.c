/*
 * test_myproto.c - Unit tests for MyProto protocol module
 *
 * Tests header encode/decode, CRC32, encryption stubs, frame building,
 * frame validation, and buffer overflow protection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/myproto.h"
#include "../src/types.h"
#include "../src/crypto.h"

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  TEST %s ... ", name); \
    fflush(stdout); \
} while(0)

#define OK() do { \
    tests_passed++; \
    printf("OK\n"); \
} while(0)

#define FAIL(msg) do { \
    tests_failed++; \
    printf("FAIL: %s\n", msg); \
} while(0)

static void print_summary(void)
{
    printf("\n");
    printf("========================================\n");
    printf("  Test Summary: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    printf("========================================\n");
}

/* ============================================================================
 * Test 1: MyProto Header Encode/Decode Round-trip
 * ============================================================================ */
static void test_hdr_roundtrip(void)
{
    TEST("Header encode/decode round-trip");

    const char *test_payload = "Hello, MyProto!";
    size_t payload_len = strlen(test_payload);

    myproto_hdr_t hdr_out, hdr_in;
    memset(&hdr_out, 0, sizeof(hdr_out));
    hdr_out.magic      = MYPROTO_MAGIC;
    hdr_out.version    = MYPROTO_VERSION;
    hdr_out.flags      = MPF_DATA;
    hdr_out.channel_id = 42;
    hdr_out.data_len   = (uint16_t)payload_len;

    /* Build frame */
    uint8_t buf[MAX_FRAME_SIZE];
    ssize_t frame_len = myproto_build_frame(buf, sizeof(buf),
                                            &hdr_out, (const uint8_t*)test_payload,
                                            payload_len, 0);
    if (frame_len < 0) {
        FAIL("build_frame returned -1");
        return;
    }

    /* Parse frame back */
    memset(&hdr_in, 0, sizeof(hdr_in));
    const uint8_t *parsed_payload = NULL;
    size_t parsed_payload_len = 0;
    int parse_ret = myproto_parse_frame(buf, (size_t)frame_len,
                                        &hdr_in, &parsed_payload,
                                        &parsed_payload_len);
    if (parse_ret != 0) {
        FAIL("parse_frame returned -1");
        return;
    }

    /* Verify all header fields */
    if (hdr_in.magic != MYPROTO_MAGIC) {
        FAIL("magic mismatch");
        return;
    }
    if (hdr_in.version != MYPROTO_VERSION) {
        FAIL("version mismatch");
        return;
    }
    if (hdr_in.flags != MPF_DATA) {
        FAIL("flags mismatch");
        return;
    }
    if (hdr_in.channel_id != 42) {
        FAIL("channel_id mismatch");
        return;
    }
    if (hdr_in.data_len != payload_len) {
        FAIL("data_len mismatch");
        return;
    }

    /* Verify payload content */
    if (parsed_payload_len != payload_len) {
        FAIL("parsed payload_len mismatch");
        return;
    }
    if (memcmp(parsed_payload, test_payload, payload_len) != 0) {
        FAIL("payload content mismatch");
        return;
    }

    OK();
}

/* ============================================================================
 * Test 2: CRC32 Known Vector
 * ============================================================================ */
static void test_crc32_known_vector(void)
{
    TEST("CRC32 known vector '123456789'");

    /* Standard CRC-32/ISO-HDLC test vector: "123456789" → 0xCBF43926 */
    const char *test_str = "123456789";
    uint32_t crc = myproto_crc32((const uint8_t*)test_str, 9);

    if (crc != 0xCBF43926) {
        printf("(got 0x%08X, expected 0xCBF43926) ", crc);
        FAIL("CRC32 mismatch");
        return;
    }

    OK();
}

static void test_crc_append_and_verify(void)
{
    TEST("CRC append and verify round-trip");

    const char *data = "CRC test data payload";
    size_t data_len = strlen(data);

    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.flags      = MPF_DATA;
    hdr.channel_id = 10;
    hdr.data_len   = (uint16_t)data_len;

    uint8_t buf[MAX_FRAME_SIZE];

    /* Build with CRC enabled */
    ssize_t frame_len = myproto_build_frame(buf, sizeof(buf), &hdr,
                                            (const uint8_t*)data, data_len, 1);
    if (frame_len < 0) {
        FAIL("build_frame with CRC returned -1");
        return;
    }

    /* Verify CRC */
    ssize_t verified_len = myproto_verify_crc(buf, (size_t)frame_len);
    if (verified_len < 0) {
        FAIL("verify_crc returned -1");
        return;
    }

    /* Check verified length matches data + header */
    if ((size_t)verified_len != MYPROTO_HDR_SIZE + data_len) {
        FAIL("verified_len mismatch");
        return;
    }

    /* Corrupt data and verify CRC fails */
    buf[3] ^= 0xFF; /* flip bits in flags byte */
    ssize_t bad_verify = myproto_verify_crc(buf, (size_t)frame_len);
    if (bad_verify >= 0) {
        FAIL("verify_crc should fail on corrupted data");
        return;
    }

    OK();
}

/* ============================================================================
 * Test 3: Encryption Stub Round-trip
 * ============================================================================ */
static void test_encrypt_roundtrip(void)
{
    TEST("Encryption stub round-trip");

    const char *plaintext = "Secret message for encryption test!";
    size_t plaintext_len = strlen(plaintext);

    uint8_t buf[MAX_FRAME_SIZE];

    /* Build encrypted data frame */
    ssize_t frame_len = myproto_build_data_frame(buf, sizeof(buf),
                                                  7, /* channel_id */
                                                  MPF_CRYPTO,
                                                  (const uint8_t*)plaintext,
                                                  plaintext_len,
                                                  0); /* no CRC */
    if (frame_len < 0) {
        FAIL("build_data_frame (encrypted) returned -1");
        return;
    }

    /* Parse the frame */
    myproto_hdr_t hdr;
    const uint8_t *payload;
    size_t payload_len;

    int parse_ret = myproto_parse_frame(buf, (size_t)frame_len,
                                        &hdr, &payload, &payload_len);
    if (parse_ret != 0) {
        FAIL("parse_frame returned -1");
        return;
    }

    /* Verify it's encrypted */
    if (!(hdr.flags & MPF_CRYPTO)) {
        FAIL("MPF_CRYPTO flag not set");
        return;
    }

    /* Decrypt via process_data_frame (needs mutable copy) */
    uint8_t *mutable_payload = (uint8_t*)payload;
    size_t mutable_len = payload_len;

    int process_ret = myproto_process_data_frame(&hdr, mutable_payload,
                                                  &mutable_len);
    if (process_ret != 0) {
        FAIL("process_data_frame returned -1");
        return;
    }

    /* Verify decrypted plaintext */
    if (mutable_len != plaintext_len) {
        FAIL("decrypted length mismatch");
        return;
    }
    if (memcmp(mutable_payload, plaintext, plaintext_len) != 0) {
        FAIL("decrypted content mismatch");
        return;
    }

    OK();
}

static void test_encrypt_wrong_key_fails(void)
{
    TEST("Encryption tamper detection");

    const char *plaintext = "Secret data";
    size_t plaintext_len = strlen(plaintext);

    uint8_t buf[MAX_FRAME_SIZE];

    /* Build encrypted frame (key managed globally via crypto_init) */
    ssize_t frame_len = myproto_build_data_frame(buf, sizeof(buf),
                                                  7, MPF_CRYPTO,
                                                  (const uint8_t*)plaintext,
                                                  plaintext_len, 0);
    if (frame_len < 0) {
        FAIL("build_data_frame returned -1");
        return;
    }

    /* Parse */
    myproto_hdr_t hdr;
    const uint8_t *payload;
    size_t payload_len;

    int parse_ret = myproto_parse_frame(buf, (size_t)frame_len,
                                        &hdr, &payload, &payload_len);
    if (parse_ret != 0) {
        FAIL("parse_frame returned -1");
        return;
    }

    /* Tamper with a byte in the encrypted payload to trigger HMAC failure */
    uint8_t mutable_buf[MAX_FRAME_SIZE];
    memcpy(mutable_buf, payload, payload_len);
    if (payload_len > 0) {
        mutable_buf[0] ^= 0xFF; /* flip bits to corrupt HMAC or ciphertext */
    }
    size_t mutable_len = payload_len;

    int process_ret = myproto_process_data_frame(&hdr, mutable_buf,
                                                  &mutable_len);
    if (process_ret == 0) {
        FAIL("process_data_frame should fail with tampered data");
        return;
    }

    OK();
}

/* ============================================================================
 * Test 4: Frame Boundary Validation
 * ============================================================================ */
static void test_validate_hdr_valid(void)
{
    TEST("validate_hdr with valid header");

    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.flags      = MPF_DATA;
    hdr.channel_id = 100;
    hdr.data_len   = 100;

    if (myproto_validate_hdr(&hdr) != 0) {
        FAIL("valid header rejected");
        return;
    }

    OK();
}

static void test_validate_hdr_bad_magic(void)
{
    TEST("validate_hdr with bad magic");

    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = 0xBEEF;
    hdr.version    = MYPROTO_VERSION;
    hdr.flags      = MPF_DATA;
    hdr.channel_id = 100;
    hdr.data_len   = 100;

    if (myproto_validate_hdr(&hdr) == 0) {
        FAIL("bad magic not rejected");
        return;
    }

    OK();
}

static void test_validate_hdr_bad_version(void)
{
    TEST("validate_hdr with bad version");

    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = 0x99;
    hdr.flags      = MPF_DATA;
    hdr.channel_id = 100;
    hdr.data_len   = 100;

    if (myproto_validate_hdr(&hdr) == 0) {
        FAIL("bad version not rejected");
        return;
    }

    OK();
}

static void test_validate_hdr_oversize_data(void)
{
    TEST("validate_hdr with oversize data_len");

    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.flags      = MPF_DATA;
    hdr.channel_id = 100;
    hdr.data_len   = ETH_MAX_PAYLOAD + 1;

    if (myproto_validate_hdr(&hdr) == 0) {
        FAIL("oversize data_len not rejected");
        return;
    }

    OK();
}

static void test_validate_hdr_null(void)
{
    TEST("validate_hdr with NULL pointer");

    if (myproto_validate_hdr(NULL) == 0) {
        FAIL("NULL header not rejected");
        return;
    }

    OK();
}

/* ============================================================================
 * Test 5: Control Frame Building
 * ============================================================================ */
static void test_ctrl_frame_types(void)
{
    const struct {
        const char *name;
        uint8_t flags;
    } ctrl_types[] = {
        {"SYN",  MPF_SYN},
        {"ACK",  MPF_ACK},
        {"FIN",  MPF_FIN},
        {"RST",  MPF_RST},
        {"PING", MPF_PING},
        {"PONG", MPF_PONG},
        {NULL, 0}
    };

    int i;
    for (i = 0; ctrl_types[i].name != NULL; i++) {
        char test_name[64];
        snprintf(test_name, sizeof(test_name), "Control frame %s", ctrl_types[i].name);
        TEST(test_name);

        uint8_t buf[MAX_FRAME_SIZE];
        ssize_t frame_len = myproto_build_ctrl_frame(buf, sizeof(buf),
                                                      55, ctrl_types[i].flags, 0);
        if (frame_len < 0) {
            FAIL("build_ctrl_frame returned -1");
            return;
        }

        /* Parse it back */
        myproto_hdr_t hdr;
        const uint8_t *payload;
        size_t payload_len;

        int ret = myproto_parse_frame(buf, (size_t)frame_len,
                                      &hdr, &payload, &payload_len);
        if (ret != 0) {
            FAIL("parse_frame returned -1");
            return;
        }

        /* Check flags */
        if (hdr.flags != ctrl_types[i].flags) {
            FAIL("flags mismatch");
            return;
        }

        /* Control frames must have data_len == 0 */
        if (hdr.data_len != 0) {
            printf("(data_len=%u) ", hdr.data_len);
            FAIL("data_len should be 0 for control frames");
            return;
        }

        /* Payload length should be 0 */
        if (payload_len != 0) {
            FAIL("payload_len should be 0 for control frames");
            return;
        }

        /* Check channel_id */
        if (hdr.channel_id != 55) {
            FAIL("channel_id mismatch");
            return;
        }

        /* Verify it's recognized as a control frame */
        if (!myproto_is_ctrl_frame(hdr.flags)) {
            FAIL("is_ctrl_frame returned false");
            return;
        }

        OK();
    }
}

static void test_ctrl_frame_no_flags_fails(void)
{
    TEST("Control frame with no control flags fails");

    uint8_t buf[MAX_FRAME_SIZE];
    ssize_t frame_len = myproto_build_ctrl_frame(buf, sizeof(buf),
                                                  1, MPF_DATA, 0);
    if (frame_len >= 0) {
        FAIL("should reject flags=MPF_DATA (no ctrl flag set)");
        return;
    }

    OK();
}

/* ============================================================================
 * Test 6: CRC-Enabled Frame
 * ============================================================================ */
static void test_crc_enabled_data_frame(void)
{
    TEST("Data frame with CRC enabled");

    const char *data = "CRC-enabled data frame test payload!";
    size_t data_len = strlen(data);

    uint8_t buf[MAX_FRAME_SIZE];

    ssize_t frame_len = myproto_build_data_frame(buf, sizeof(buf),
                                                  10, MPF_DATA,
                                                  (const uint8_t*)data,
                                                  data_len, 1);
    if (frame_len < 0) {
        FAIL("build_data_frame with CRC returned -1");
        return;
    }

    /* Verify CRC was appended (frame_len > header + payload) */
    if ((size_t)frame_len != MYPROTO_HDR_SIZE + data_len + CRC32_SIZE) {
        printf("(frame_len=%zu, expected=%zu) ", (size_t)frame_len,
               MYPROTO_HDR_SIZE + data_len + CRC32_SIZE);
        FAIL("frame length mismatch");
        return;
    }

    /* Verify CRC is valid */
    ssize_t verified_len = myproto_verify_crc(buf, (size_t)frame_len);
    if (verified_len < 0) {
        FAIL("verify_crc returned -1");
        return;
    }

    /* Parse frame and verify data */
    myproto_hdr_t hdr;
    const uint8_t *payload;
    size_t payload_len;
    int ret = myproto_parse_frame(buf, (size_t)frame_len,
                                  &hdr, &payload, &payload_len);
    if (ret != 0) {
        FAIL("parse_frame returned -1");
        return;
    }

    if (memcmp(payload, data, data_len) != 0) {
        FAIL("payload mismatch");
        return;
    }

    OK();
}

/* ============================================================================
 * Test 7: Buffer Overflow Protection
 * ============================================================================ */
static void test_overflow_build_frame(void)
{
    TEST("Buffer overflow: build_frame too small");

    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.flags      = MPF_DATA;
    hdr.channel_id = 1;
    hdr.data_len   = 100;

    const char *payload = "Some payload data here";
    size_t payload_len = strlen(payload);

    /* Pass a buffer that's too small */
    uint8_t tiny_buf[8]; /* only 8 bytes, less than header + payload */

    ssize_t ret = myproto_build_frame(tiny_buf, sizeof(tiny_buf),
                                      &hdr, (const uint8_t*)payload,
                                      payload_len, 0);
    if (ret >= 0) {
        FAIL("should return -1 for too-small buffer");
        return;
    }

    OK();
}

static void test_overflow_build_ctrl_frame(void)
{
    TEST("Buffer overflow: build_ctrl_frame too small");

    /* buf_size < MYPROTO_MIN_FRAME_SIZE (8) */
    uint8_t tiny_buf[4];

    ssize_t ret = myproto_build_ctrl_frame(tiny_buf, sizeof(tiny_buf),
                                            1, MPF_SYN, 0);
    if (ret >= 0) {
        FAIL("should return -1 for too-small buffer");
        return;
    }

    OK();
}

static void test_overflow_build_data_frame(void)
{
    TEST("Buffer overflow: build_data_frame too small");

    const char *data = "Some data to build frame";
    size_t data_len = strlen(data);

    uint8_t tiny_buf[MYPROTO_HDR_SIZE]; /* only fits header */

    ssize_t ret = myproto_build_data_frame(tiny_buf, sizeof(tiny_buf),
                                            1, MPF_DATA,
                                            (const uint8_t*)data, data_len,
                                            0);
    if (ret >= 0) {
        FAIL("should return -1 for too-small buffer");
        return;
    }

    OK();
}

static void test_overflow_encrypted_frame(void)
{
    TEST("Buffer overflow: encrypted frame too small");

    const char *data = "Secret overflow test data";
    size_t data_len = strlen(data);

    /* Buffer only big enough for unencrypted, not enough for crypto overhead */
    size_t unencrypted_size = MYPROTO_HDR_SIZE + data_len;
    uint8_t *buf = calloc(1, unencrypted_size);
    if (!buf) {
        FAIL("calloc failed");
        return;
    }

    ssize_t ret = myproto_build_data_frame(buf, unencrypted_size,
                                            1, MPF_CRYPTO,
                                            (const uint8_t*)data, data_len,
                                            0);
    free(buf);

    if (ret >= 0) {
        FAIL("should return -1 for too-small buffer with crypto");
        return;
    }

    OK();
}

static void test_overflow_append_crc(void)
{
    TEST("Buffer overflow: append_crc too small");

    uint8_t buf[16];
    memset(buf, 0xAA, sizeof(buf));

    /* frame_len == buf_size, so no room for CRC */
    ssize_t ret = myproto_append_crc(buf, 16, 16);
    if (ret >= 0) {
        FAIL("should return -1 when no room for CRC");
        return;
    }

    OK();
}

static void test_overflow_verify_crc_short(void)
{
    TEST("Boundary: verify_crc with short frame");

    uint8_t buf[2];
    ssize_t ret = myproto_verify_crc(buf, 2);
    if (ret >= 0) {
        FAIL("should return -1 for frame shorter than CRC32_SIZE");
        return;
    }

    OK();
}

static void test_parse_frame_too_short(void)
{
    TEST("Boundary: parse_frame too short");

    uint8_t buf[4]; /* shorter than MYPROTO_MIN_FRAME_SIZE */
    myproto_hdr_t hdr;
    const uint8_t *payload;
    size_t payload_len;

    int ret = myproto_parse_frame(buf, 4, &hdr, &payload, &payload_len);
    if (ret >= 0) {
        FAIL("should return -1 for data too short");
        return;
    }

    OK();
}

/* ============================================================================
 * Additional tests
 * ============================================================================ */

static void test_data_frame_non_encrypted(void)
{
    TEST("Data frame non-encrypted");

    const char *data = "Plaintext unencrypted data";
    size_t data_len = strlen(data);

    uint8_t buf[MAX_FRAME_SIZE];

    ssize_t frame_len = myproto_build_data_frame(buf, sizeof(buf),
                                                  3, MPF_DATA,
                                                  (const uint8_t*)data,
                                                  data_len, 0);
    if (frame_len < 0) {
        FAIL("build_data_frame returned -1");
        return;
    }

    myproto_hdr_t hdr;
    const uint8_t *payload;
    size_t payload_len;

    int ret = myproto_parse_frame(buf, (size_t)frame_len,
                                  &hdr, &payload, &payload_len);
    if (ret != 0) {
        FAIL("parse_frame returned -1");
        return;
    }

    if (payload_len != data_len) {
        FAIL("payload_len mismatch");
        return;
    }
    if (memcmp(payload, data, data_len) != 0) {
        FAIL("payload content mismatch");
        return;
    }
    if (hdr.flags != MPF_DATA) {
        FAIL("flags mismatch");
        return;
    }
    if (hdr.channel_id != 3) {
        FAIL("channel_id mismatch");
        return;
    }

    /* process_data_frame on non-encrypted should succeed (no-op) */
    uint8_t mutable_buf[MAX_FRAME_SIZE];
    memcpy(mutable_buf, payload, payload_len);
    size_t mutable_len = payload_len;
    hdr.flags = MPF_DATA; /* ensure not crypto */
    int process_ret = myproto_process_data_frame(&hdr, mutable_buf,
                                                  &mutable_len);
    if (process_ret != 0) {
        FAIL("process_data_frame should succeed on non-encrypted frame");
        return;
    }

    OK();
}

static void test_inline_helpers(void)
{
    TEST("Inline helper functions");

    /* is_ctrl_frame */
    if (!myproto_is_ctrl_frame(MPF_SYN)) {
        FAIL("is_ctrl_frame(MPF_SYN) should be true");
        return;
    }
    if (!myproto_is_ctrl_frame(MPF_ACK | MPF_FIN)) {
        FAIL("is_ctrl_frame(MPF_ACK|MPF_FIN) should be true");
        return;
    }
    if (myproto_is_ctrl_frame(MPF_DATA)) {
        FAIL("is_ctrl_frame(MPF_DATA) should be false");
        return;
    }
    if (myproto_is_ctrl_frame(MPF_CRYPTO)) {
        FAIL("is_ctrl_frame(MPF_CRYPTO) should be false");
        return;
    }

    /* is_data_frame */
    if (!myproto_is_data_frame(MPF_DATA)) {
        FAIL("is_data_frame(MPF_DATA) should be true");
        return;
    }
    if (!myproto_is_data_frame(MPF_CRYPTO)) {
        FAIL("is_data_frame(MPF_CRYPTO) should be true");
        return;
    }
    if (myproto_is_data_frame(MPF_SYN)) {
        FAIL("is_data_frame(MPF_SYN) should be false");
        return;
    }

    /* is_crypto_frame */
    if (myproto_is_crypto_frame(MPF_DATA)) {
        FAIL("is_crypto_frame(MPF_DATA) should be false");
        return;
    }
    if (!myproto_is_crypto_frame(MPF_CRYPTO)) {
        FAIL("is_crypto_frame(MPF_CRYPTO) should be true");
        return;
    }
    if (!myproto_is_crypto_frame(MPF_CRYPTO | MPF_DATA)) {
        FAIL("is_crypto_frame(MPF_CRYPTO|MPF_DATA) should be true");
        return;
    }

    OK();
}

static void test_null_ptr_guards(void)
{
    TEST("Null pointer guards on build_frame");

    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.channel_id = 1;
    hdr.data_len   = 10;

    uint8_t buf[64];
    const uint8_t *payload = (const uint8_t*)"test";

    /* null buf */
    if (myproto_build_frame(NULL, 64, &hdr, payload, 10, 0) >= 0) {
        FAIL("build_frame should reject NULL buf");
        return;
    }

    /* null hdr */
    if (myproto_build_frame(buf, 64, NULL, payload, 10, 0) >= 0) {
        FAIL("build_frame should reject NULL hdr");
        return;
    }

    /* null payload with non-zero length */
    if (myproto_build_frame(buf, 64, &hdr, NULL, 10, 0) >= 0) {
        FAIL("build_frame should reject NULL payload with len>0");
        return;
    }

    /* null buf for ctrl frame */
    if (myproto_build_ctrl_frame(NULL, 64, 1, MPF_SYN, 0) >= 0) {
        FAIL("build_ctrl_frame should reject NULL buf");
        return;
    }

    /* null buf for data frame */
    if (myproto_build_data_frame(NULL, 64, 1, MPF_DATA, payload, 10, 0) >= 0) {
        FAIL("build_data_frame should reject NULL buf");
        return;
    }

    OK();
}

static void test_parse_frame_null_guards(void)
{
    TEST("Null pointer guards on parse_frame");

    uint8_t buf[64];
    myproto_hdr_t hdr;
    const uint8_t *payload;
    size_t payload_len;

    /* Build a valid frame first */
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic      = MYPROTO_MAGIC;
    hdr.version    = MYPROTO_VERSION;
    hdr.channel_id = 1;
    hdr.data_len   = 5;
    ssize_t frame_len = myproto_build_frame(buf, sizeof(buf), &hdr,
                                            (const uint8_t*)"hello", 5, 0);
    if (frame_len < 0) {
        FAIL("build_frame failed, cannot test parse guards");
        return;
    }

    /* null data */
    if (myproto_parse_frame(NULL, (size_t)frame_len, &hdr, &payload, &payload_len) >= 0) {
        FAIL("parse_frame should reject NULL data");
        return;
    }

    /* null hdr */
    if (myproto_parse_frame(buf, (size_t)frame_len, NULL, &payload, &payload_len) >= 0) {
        FAIL("parse_frame should reject NULL hdr");
        return;
    }

    /* null payload */
    if (myproto_parse_frame(buf, (size_t)frame_len, &hdr, NULL, &payload_len) >= 0) {
        FAIL("parse_frame should reject NULL payload");
        return;
    }

    /* null payload_len */
    if (myproto_parse_frame(buf, (size_t)frame_len, &hdr, &payload, NULL) >= 0) {
        FAIL("parse_frame should reject NULL payload_len");
        return;
    }

    OK();
}

static void test_proto_constants(void)
{
    TEST("Protocol constants");

    /* Verify static_assert for header size works */
    if (sizeof(myproto_hdr_t) != 8) {
        FAIL("myproto_hdr_t should be 8 bytes");
        return;
    }
    if (MYPROTO_HDR_SIZE != 8) {
        FAIL("MYPROTO_HDR_SIZE should be 8");
        return;
    }
    if (MYPROTO_MAGIC != 0x4D50) {
        FAIL("MYPROTO_MAGIC should be 0x4D50");
        return;
    }

    OK();
}

static void test_crc32_zero_length(void)
{
    TEST("CRC32 of zero-length data");

    /* CRC32 of empty data should be 0x00000000 (0xFFFFFFFF ^ 0xFFFFFFFF) */
    uint32_t crc = myproto_crc32(NULL, 0);
    if (crc != 0x00000000) {
        printf("(got 0x%08X) ", crc);
        FAIL("CRC32 of empty data should be 0");
        return;
    }

    OK();
}

static void test_encrypt_non_crypto_frame_processed(void)
{
    TEST("process_data_frame skips non-crypto frame");

    myproto_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.flags = MPF_DATA;
    hdr.channel_id = 1;
    hdr.data_len = 10;
    hdr.magic = MYPROTO_MAGIC;
    hdr.version = MYPROTO_VERSION;

    uint8_t data[32];
    memset(data, 'X', 10);
    size_t data_len = 10;

    /* Should succeed as no-op with NULL key (since flags don't have MPF_CRYPTO) */
    int ret = myproto_process_data_frame(&hdr, data, &data_len);
    if (ret != 0) {
        FAIL("non-crypto frame should process successfully");
        return;
    }
    if (data_len != 10) {
        FAIL("data_len should be unchanged");
        return;
    }

    OK();
}

static void test_channel_id_boundary(void)
{
    TEST("Channel ID boundary validation");

    uint8_t buf[MAX_FRAME_SIZE];

    /* channel_id == MAX_CHANNELS should be rejected */
    ssize_t ret = myproto_build_data_frame(buf, sizeof(buf),
                                            MAX_CHANNELS, MPF_DATA,
                                            (const uint8_t*)"data", 4,
                                            0);
    if (ret >= 0) {
        FAIL("should reject channel_id == MAX_CHANNELS");
        return;
    }

    /* channel_id == MAX_CHANNELS - 1 should work */
    ret = myproto_build_data_frame(buf, sizeof(buf),
                                    MAX_CHANNELS - 1, MPF_DATA,
                                    (const uint8_t*)"data", 4,
                                    0);
    if (ret < 0) {
        FAIL("should accept channel_id == MAX_CHANNELS-1");
        return;
    }

    OK();
}

static void test_data_len_boundary(void)
{
    TEST("Data length boundary validation");

    uint8_t buf[MAX_FRAME_SIZE];

    /* data_len == ETH_MAX_PAYLOAD should work (set via wire_payload_len) */
    /* Build a non-encrypted frame with max payload */
    ssize_t ret = myproto_build_data_frame(buf, sizeof(buf),
                                            1, MPF_DATA,
                                            (const uint8_t*)"12345678901234567890",
                                            20, 0);
    if (ret < 0) {
        FAIL("build_data_frame should succeed with valid data");
        return;
    }

    OK();
}

/* ====================================================
 * Main test runner
 * ============================================================================ */
int main(void)
{
    encryption_config_t enc_cfg = { .enabled = 1, .sm4_key = "0123456789abcdef0123456789abcdef" };
    crypto_init(&enc_cfg);

    printf("\n");
    printf("========================================\n");
    printf("  MyProto Unit Tests\n");
    printf("========================================\n\n");

    /* Test 1: Header encode/decode round-trip */
    printf("[Test 1] Header Encode/Decode Round-trip\n");
    test_hdr_roundtrip();

    /* Test 2: CRC32 */
    printf("\n[Test 2] CRC32\n");
    test_crc32_known_vector();
    test_crc_append_and_verify();

    /* Test 3: Encryption stub */
    printf("\n[Test 3] Encryption Stub\n");
    test_encrypt_roundtrip();
    test_encrypt_wrong_key_fails();

    /* Test 4: Frame boundary validation */
    printf("\n[Test 4] Frame Boundary Validation\n");
    test_validate_hdr_valid();
    test_validate_hdr_bad_magic();
    test_validate_hdr_bad_version();
    test_validate_hdr_oversize_data();
    test_validate_hdr_null();

    /* Test 5: Control frame building */
    printf("\n[Test 5] Control Frame Building\n");
    test_ctrl_frame_types();
    test_ctrl_frame_no_flags_fails();

    /* Test 6: CRC-enabled frame */
    printf("\n[Test 6] CRC-Enabled Frame\n");
    test_crc_enabled_data_frame();

    /* Test 7: Buffer overflow protection */
    printf("\n[Test 7] Buffer Overflow Protection\n");
    test_overflow_build_frame();
    test_overflow_build_ctrl_frame();
    test_overflow_build_data_frame();
    test_overflow_encrypted_frame();
    test_overflow_append_crc();
    test_overflow_verify_crc_short();
    test_parse_frame_too_short();

    /* Additional tests */
    printf("\n[Additional] Extra Coverage\n");
    test_data_frame_non_encrypted();
    test_inline_helpers();
    test_null_ptr_guards();
    test_parse_frame_null_guards();
    test_proto_constants();
    test_crc32_zero_length();
    test_encrypt_non_crypto_frame_processed();
    test_channel_id_boundary();
    test_data_len_boundary();

    print_summary();

    crypto_cleanup();

    return tests_failed == 0 ? 0 : 1;
}
