// SPDX-License-Identifier: MIT
// Standalone test for RFC 9858 / SP 800-208 LMS parameter sets
// Tests our patched Cisco hash layer directly, bypassing liboqs wiring
//
// Build:
//   gcc test_lms_nist.c \
//     -I/home/mad/liboqs/src/sig_stfl/lms/external \
//     -I/home/mad/liboqs/build/include \
//     -L/home/mad/liboqs/build/lib \
//     -Wl,-rpath,/home/mad/liboqs/build/lib \
//     -loqs -lssl -lcrypto -o test_lms_nist
//
// Run:
//   ./test_lms_nist

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "hss.h"

// ── RNG ──────────────────────────────────────────────────────────────────────

static bool do_rand(void *output, size_t len) {
    uint8_t *p = output;
    // Use OpenSSL RAND_bytes via OQS
    for (size_t i = 0; i < len; i++) p[i] = (uint8_t)(rand() & 0xff);
    return true;
}

// ── Private key store (in-memory) ────────────────────────────────────────────

static uint8_t g_sk[128];  // Enough for any PRIVATE_KEY_LEN
static size_t  g_sk_len = 0;
#define PRIVATE_KEY_LEN_MAX 128

static bool store_sk(unsigned char *sk, size_t len, void *ctx) {
    (void)ctx;
    if (len > sizeof(g_sk)) return false;
    memcpy(g_sk, sk, len);
    g_sk_len = len;
    return true;
}

// ── Test one parameter set ───────────────────────────────────────────────────

static int test_param_set(const char *name,
                           param_set_t lm_type,
                           param_set_t lm_ots_type,
                           size_t expected_pk_len)
{
    printf("Testing %-30s ... ", name);
    fflush(stdout);

    struct hss_extra_info info = {0};

    // --- Compute expected sizes ---
    size_t pk_len  = hss_get_public_key_len(1, &lm_type, &lm_ots_type);
    size_t sig_len = hss_get_signature_len(1, &lm_type, &lm_ots_type);

    if (pk_len == 0 || sig_len == 0) {
        printf("FAIL (hss_get_*_len returned 0)\n");
        return 1;
    }
    if (pk_len != expected_pk_len) {
        printf("FAIL (pk_len=%zu expected %zu)\n", pk_len, expected_pk_len);
        return 1;
    }

    uint8_t *pk  = malloc(pk_len);
    uint8_t *sig = malloc(sig_len);
    if (!pk || !sig) { printf("FAIL (malloc)\n"); return 1; }

    // --- Keygen ---
    // Use in-memory path: pass NULL callback, g_sk as context buffer
    // hss_generate_private_key will memcpy the key into g_sk directly
    g_sk_len = PRIVATE_KEY_LEN_MAX;
    bool ok = hss_generate_private_key(
        do_rand, 1, &lm_type, &lm_ots_type,
        NULL, g_sk,   // NULL callback → uses g_sk as direct memory buffer
        pk, pk_len,
        NULL, 0,
        &info);

    if (!ok) {
        printf("FAIL (keygen error_code=%d)\n", info.error_code);
        free(pk); free(sig);
        return 1;
    }

    // --- Load working key ---
    struct hss_working_key *wk = hss_load_private_key(
        NULL, g_sk,   // NULL callback → reads from g_sk directly
        0, pk, pk_len,
        NULL);

    if (!wk) {
        printf("FAIL (load_private_key)\n");
        free(pk); free(sig);
        return 1;
    }

    // --- Sign ---
    const char *msg = "Hello RFC 9858 LMS!";
    size_t msg_len = strlen(msg);
    size_t actual_sig_len = sig_len;

    ok = hss_generate_signature(
        wk,
        store_sk, NULL,
        msg, msg_len,
        sig, actual_sig_len,
        NULL);

    if (!ok) {
        printf("FAIL (sign)\n");
        hss_free_working_key(wk);
        free(pk); free(sig);
        return 1;
    }

    // --- Verify ---
    ok = hss_validate_signature(
        pk,
        msg, msg_len,
        sig, actual_sig_len,
        NULL);

    if (!ok) {
        printf("FAIL (verify)\n");
        hss_free_working_key(wk);
        free(pk); free(sig);
        return 1;
    }

    // --- Verify rejects tampered message ---
    char bad_msg[] = "Hello RFC 9858 LMS!";
    bad_msg[0] ^= 0x01;
    bool reject = !hss_validate_signature(
        pk,
        bad_msg, msg_len,
        sig, actual_sig_len,
        NULL);

    hss_free_working_key(wk);
    free(pk); free(sig);

    if (!reject) {
        printf("FAIL (accepted tampered message!)\n");
        return 1;
    }

    printf("PASS  (pk=%zu sig=%zu)\n", pk_len, sig_len);
    return 0;
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main(void) {
    srand(42);

    printf("RFC 9858 / SP 800-208 LMS parameter set tests\n");
    printf("=============================================\n\n");

    int failures = 0;

    // RFC 8554 baseline (SHA-256/256) - should still work
    printf("--- RFC 8554 baseline ---\n");
    failures += test_param_set("LMS_SHA256_N32_H5 / W8",
        0x00000005, 0x00000004, 60);

    printf("\n--- RFC 9858: SHA-256/192 ---\n");
    failures += test_param_set("LMS_SHA256_N24_H5 / W1",
        0x0000000a, 0x00000005, 52);
    failures += test_param_set("LMS_SHA256_N24_H5 / W4",
        0x0000000a, 0x00000007, 52);
    failures += test_param_set("LMS_SHA256_N24_H5 / W8",
        0x0000000a, 0x00000008, 52);

    printf("\n--- RFC 9858: SHAKE256/256 ---\n");
    failures += test_param_set("LMS_SHAKE_N32_H5 / W1",
        0x0000000f, 0x00000009, 60);
    failures += test_param_set("LMS_SHAKE_N32_H5 / W4",
        0x0000000f, 0x0000000b, 60);
    failures += test_param_set("LMS_SHAKE_N32_H5 / W8",
        0x0000000f, 0x0000000c, 60);

    printf("\n--- RFC 9858: SHAKE256/192 ---\n");
    failures += test_param_set("LMS_SHAKE_N24_H5 / W1",
        0x00000014, 0x0000000d, 52);
    failures += test_param_set("LMS_SHAKE_N24_H5 / W4",
        0x00000014, 0x0000000f, 52);
    failures += test_param_set("LMS_SHAKE_N24_H5 / W8",
        0x00000014, 0x00000010, 52);

    printf("\n=============================================\n");
    if (failures == 0)
        printf("All tests PASSED\n");
    else
        printf("%d test(s) FAILED\n", failures);

    return failures ? 1 : 0;
}
