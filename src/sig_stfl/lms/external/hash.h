// SPDX-License-Identifier: MIT
#if !defined( HASH_H__ )
#define HASH_H__
#include <oqs/sha2.h>
#include <oqs/sha3.h>
#include <stddef.h>
#include <stdbool.h>
#include "lms_namespace.h"

/*
 * This defines the hash interface used within HSS.
 * All globals are prefixed with hss_ to avoid name conflicts
 * Gee, C++ namespaces would be nice...
 */

/*
 * Hash types
 * SHA256_N24   : SHA-256 truncated to 192 bits (24 bytes)  -- RFC 9858 / SP 800-208
 * SHAKE256_N32 : SHAKE256 XOF squeezed to 256 bits (32 bytes) -- RFC 9858 / SP 800-208
 * SHAKE256_N24 : SHAKE256 XOF squeezed to 192 bits (24 bytes) -- RFC 9858 / SP 800-208
 */
enum {
    HASH_SHA256      = 1,   /* SHA-256, full 32-byte output (RFC 8554) */
    HASH_SHA256_N24  = 2,   /* SHA-256 truncated to 24 bytes           */
    HASH_SHAKE256_N32 = 3,  /* SHAKE256/256, 32-byte output            */
    HASH_SHAKE256_N24 = 4,  /* SHAKE256/192, 24-byte output            */
};

union hash_context {
    OQS_SHA2_sha256_ctx sha256;
    OQS_SHA3_shake256_inc_ctx shake256;
};

/* Hash the message */
void hss_hash(void *result, int hash_type,
          const void *message, size_t message_len);

/* Does the same, but with the passed hash context (which isn't zeroized) */
/* This is here to save time; let the caller use the same ctx for multiple */
/* hashes, and then finally zeroize it if necessary */
void hss_hash_ctx(void *result, int hash_type, union hash_context *ctx,
          const void *message, size_t message_len);

/*
 * This is a debugging flag; turning this on will cause the system to dump
 * the inputs and the outputs of all hash functions.  It only works if
 * debugging is allowed in hash.c (it's off by default), and it is *real*
 * chatty; however sometimes you really need it for debugging
 */
extern bool hss_verbose;

/*
 * This constant has migrated to common_defs.h
 */
/* #define MAX_HASH   32 */  /* Length of the largest hash we support */

unsigned hss_hash_length(int hash_type);
unsigned hss_hash_blocksize(int hash_type);

void hss_init_hash_context( int h, union hash_context *ctx );
void hss_update_hash_context( int h, union hash_context *ctx,
                          const void *msg, size_t len_msg );
void hss_finalize_hash_context( int h, union hash_context *ctx,
                          void *buffer);
void SHA256_Final(unsigned char *output, OQS_SHA2_sha256_ctx *ctx);

#endif /* HASH_H__  */
