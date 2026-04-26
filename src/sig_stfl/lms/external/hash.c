// SPDX-License-Identifier: MIT
#include <string.h>
#include "hash.h"
#include "hss_zeroize.h"

#define ALLOW_VERBOSE 0  /* 1 -> we allow the dumping of intermediate */
                         /*      states.  Useful for debugging; horrid */
                         /*      for security */

/*
 * This is the file that implements the hashing APIs we use internally.
 * Parameter sets supported:
 *   HASH_SHA256      - SHA-256, full 32-byte output (RFC 8554)
 *   HASH_SHA256_N24  - SHA-256 truncated to 24 bytes (RFC 9858 / SP 800-208)
 *   HASH_SHAKE256_N32 - SHAKE256 squeezed to 32 bytes (RFC 9858 / SP 800-208)
 *   HASH_SHAKE256_N24 - SHAKE256 squeezed to 24 bytes (RFC 9858 / SP 800-208)
 */

#if ALLOW_VERBOSE
#include <stdio.h>
#include <stdbool.h>
bool hss_verbose = false;
#endif

/*
 * This will hash the message, given the hash type. It assumes that the result
 * buffer is large enough for the hash
 */
void hss_hash_ctx(void *result, int hash_type, union hash_context *ctx,
          const void *message, size_t message_len) {
#if ALLOW_VERBOSE
    if (hss_verbose) {
        int i; for (i=0; i< message_len; i++) printf( " %02x%s", ((unsigned char*)message)[i], (i%16 == 15) ? "\n" : "" );
    }
#endif

    switch (hash_type) {
    case HASH_SHA256: {
        OQS_SHA2_sha256_inc_init(&ctx->sha256);
        OQS_SHA2_sha256_inc(&ctx->sha256, message, message_len);
        SHA256_Final(result, &ctx->sha256);
#if ALLOW_VERBOSE
        if (hss_verbose) {
            printf( " ->" );
            int i; for (i=0; i<32; i++) printf( " %02x", ((unsigned char *)result)[i] ); printf( "\n" );
        }
#endif
        break;
    }
    case HASH_SHA256_N24: {
        /* SHA-256 truncated to 192 bits: compute full SHA-256, copy first 24 bytes */
        unsigned char tmp[32];
        OQS_SHA2_sha256_inc_init(&ctx->sha256);
        OQS_SHA2_sha256_inc(&ctx->sha256, message, message_len);
        SHA256_Final(tmp, &ctx->sha256);
        memcpy(result, tmp, 24);
        hss_zeroize(tmp, sizeof tmp);
        break;
    }
    case HASH_SHAKE256_N32: {
        /* SHAKE256/256: absorb message, squeeze 32 bytes */
        OQS_SHA3_shake256_inc_init(&ctx->shake256);
        OQS_SHA3_shake256_inc_absorb(&ctx->shake256, message, message_len);
        OQS_SHA3_shake256_inc_finalize(&ctx->shake256);
        OQS_SHA3_shake256_inc_squeeze(result, 32, &ctx->shake256);
        break;
    }
    case HASH_SHAKE256_N24: {
        /* SHAKE256/192: absorb message, squeeze 24 bytes */
        OQS_SHA3_shake256_inc_init(&ctx->shake256);
        OQS_SHA3_shake256_inc_absorb(&ctx->shake256, message, message_len);
        OQS_SHA3_shake256_inc_finalize(&ctx->shake256);
        OQS_SHA3_shake256_inc_squeeze(result, 24, &ctx->shake256);
        break;
    }
    }
}

void hss_hash(void *result, int hash_type,
          const void *message, size_t message_len) {
    union hash_context ctx;
    hss_hash_ctx(result, hash_type, &ctx, message, message_len);
    /* Release SHAKE context heap memory before zeroizing the struct */
    if (hash_type == HASH_SHAKE256_N32 || hash_type == HASH_SHAKE256_N24) {
        OQS_SHA3_shake256_inc_ctx_release(&ctx.shake256);
    }
    hss_zeroize(&ctx, sizeof ctx);
}


/*
 * Incremental hashing API - used when hashing the message in chunks
 */
void hss_init_hash_context(int h, union hash_context *ctx) {
    switch (h) {
    case HASH_SHA256:
    case HASH_SHA256_N24:
        OQS_SHA2_sha256_inc_init(&ctx->sha256);
        break;
    case HASH_SHAKE256_N32:
    case HASH_SHAKE256_N24:
        OQS_SHA3_shake256_inc_init(&ctx->shake256);
        break;
    }
}

void hss_update_hash_context(int h, union hash_context *ctx,
                         const void *msg, size_t len_msg) {
#if ALLOW_VERBOSE
    if (hss_verbose) {
        int i; for (i=0; i<len_msg; i++) printf( " %02x", ((unsigned char*)msg)[i] );
    }
#endif
    switch (h) {
    case HASH_SHA256:
    case HASH_SHA256_N24:
        OQS_SHA2_sha256_inc(&ctx->sha256, msg, len_msg);
        break;
    case HASH_SHAKE256_N32:
    case HASH_SHAKE256_N24:
        OQS_SHA3_shake256_inc_absorb(&ctx->shake256, msg, len_msg);
        break;
    }
}

void hss_finalize_hash_context(int h, union hash_context *ctx, void *buffer) {
    switch (h) {
    case HASH_SHA256: {
        SHA256_Final(buffer, &ctx->sha256);
#if ALLOW_VERBOSE
        if (hss_verbose) {
            printf( " -->" );
            int i; for (i=0; i<32; i++) printf( " %02x", ((unsigned char*)buffer)[i] );
            printf( "\n" );
        }
#endif
        break;
    }
    case HASH_SHA256_N24: {
        /* Full SHA-256, then truncate to 24 bytes */
        unsigned char tmp[32];
        SHA256_Final(tmp, &ctx->sha256);
        memcpy(buffer, tmp, 24);
        hss_zeroize(tmp, sizeof tmp);
        break;
    }
    case HASH_SHAKE256_N32:
        OQS_SHA3_shake256_inc_finalize(&ctx->shake256);
        OQS_SHA3_shake256_inc_squeeze(buffer, 32, &ctx->shake256);
        OQS_SHA3_shake256_inc_ctx_release(&ctx->shake256);
        break;
    case HASH_SHAKE256_N24:
        OQS_SHA3_shake256_inc_finalize(&ctx->shake256);
        OQS_SHA3_shake256_inc_squeeze(buffer, 24, &ctx->shake256);
        OQS_SHA3_shake256_inc_ctx_release(&ctx->shake256);
        break;
    }
}


unsigned hss_hash_length(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256:      return 32;
    case HASH_SHA256_N24:  return 24;
    case HASH_SHAKE256_N32: return 32;
    case HASH_SHAKE256_N24: return 24;
    }
    return 0;
}

unsigned hss_hash_blocksize(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256:      return 64;
    case HASH_SHA256_N24:  return 64;   /* Same underlying function as SHA-256 */
    case HASH_SHAKE256_N32: return 136; /* SHAKE256 rate = 1088 bits = 136 bytes */
    case HASH_SHAKE256_N24: return 136;
    }
    return 0;
}

void SHA256_Final(unsigned char *output, OQS_SHA2_sha256_ctx *ctx) {
    OQS_SHA2_sha256_inc_finalize(output, ctx, NULL, 0);
}
