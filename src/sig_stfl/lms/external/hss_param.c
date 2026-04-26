// SPDX-License-Identifier: MIT
#include <string.h>
#include "hss.h"
#include "hss_internal.h"
#include "endian.h"
#include "hss_zeroize.h"
#include "lm_common.h"
#include "lm_ots_common.h"

/*
 * Convert a parameter set into the compressed version we use within a private
 * key.  Extended format: 2 bytes per level (PARAM_SET_COMPRESS_LEN=2)
 *   byte 0: LMS type code  (0x05-0x18 for RFC 8554 + RFC 9858)
 *   byte 1: LMOTS type code (0x01-0x10 for RFC 8554 + RFC 9858)
 *   0xff 0xff: end-of-levels marker
 *
 * This replaces the original nibble-packed 1-byte format which only supported
 * codes up to 0x0e, incompatible with the RFC 9858 parameter sets.
 */
bool hss_compress_param_set( unsigned char *compressed,
                   int levels,
                   const param_set_t *lm_type,
                   const param_set_t *lm_ots_type,
                   size_t len_compressed ) {
    int i;

    for (i = 0; i < levels; i++) {
        if (len_compressed < 2) return false;
        param_set_t a = *lm_type++;
        param_set_t b = *lm_ots_type++;

        /* Validate LMS type code */
        unsigned h, n, height;
        if (!lm_look_up_parameter_set(a, &h, &n, &height)) return false;

        /* Validate LMOTS type code */
        unsigned oh, on, ow, op, ols;
        if (!lm_ots_look_up_parameter_set(b, &oh, &on, &ow, &op, &ols))
            return false;

        /* Store as two separate bytes */
        *compressed++ = (unsigned char)(a & 0xff);
        *compressed++ = (unsigned char)(b & 0xff);
        len_compressed -= 2;
    }

    /* Fill remainder with end markers */
    while (len_compressed) {
        *compressed++ = PARM_SET_END;
        len_compressed--;
    }

    return true;
}

/*
 * This returns the parameter set for a given private key.
 * Reads the 2-byte-per-level format written by hss_compress_param_set above.
 */
bool hss_get_parameter_set( unsigned *levels,
                           param_set_t lm_type[ MAX_HSS_LEVELS ],
                           param_set_t lm_ots_type[ MAX_HSS_LEVELS ],
                           bool (*read_private_key)(unsigned char *private_key,
                                       size_t len_private_key, void *context),
                           void *context) {
    unsigned char private_key[ PRIVATE_KEY_LEN ];
    bool success = false;

    if (read_private_key) {
        if (!read_private_key( private_key, PRIVATE_KEY_SEED, context )) {
            goto failed;
        }
    } else {
        if (!context) return false;
        memcpy( private_key, context, PRIVATE_KEY_SEED );
    }

    /* Scan through the private key to recover the parameter sets */
    unsigned total_height = 0;
    unsigned level;
    for (level = 0; level < MAX_HSS_LEVELS; level++) {
        /* Each level occupies 2 bytes: [LMS type, LMOTS type] */
        unsigned char a = private_key[PRIVATE_KEY_PARAM_SET + level * 2];
        unsigned char b = private_key[PRIVATE_KEY_PARAM_SET + level * 2 + 1];

        /* Both bytes must be end markers — reject malformed keys */
        if (a == PARM_SET_END && b == PARM_SET_END) break;
        if (a == PARM_SET_END || b == PARM_SET_END) goto failed;

        param_set_t lm  = (param_set_t)a;
        param_set_t ots = (param_set_t)b;

        /* Validate and get tree height */
        unsigned h, n, height;
        if (!lm_look_up_parameter_set(lm, &h, &n, &height)) goto failed;
        total_height += height;

        /* Validate LMOTS type */
        unsigned oh, on, ow, op, ols;
        if (!lm_ots_look_up_parameter_set(ots, &oh, &on, &ow, &op, &ols))
            goto failed;

        lm_type[level]     = lm;
        lm_ots_type[level] = ots;
    }

    if (level < MIN_HSS_LEVELS || level > MAX_HSS_LEVELS) goto failed;

    *levels = level;

    /* Make sure the rest of the private key has PARM_SET_END markers */
    unsigned i;
    for (i = level; i < MAX_HSS_LEVELS; i++) {
        unsigned char c0 = private_key[PRIVATE_KEY_PARAM_SET + i * 2];
        unsigned char c1 = private_key[PRIVATE_KEY_PARAM_SET + i * 2 + 1];
        if (c0 != PARM_SET_END || c1 != PARM_SET_END) goto failed;
    }

    /* Final check: sequence number in range */
    if (total_height > 64) total_height = 64;
    sequence_t max_count = ((sequence_t)2 << (total_height - 1)) - 1;
    if (total_height == 64) max_count--;
    sequence_t current_count = get_bigendian(
                 private_key + PRIVATE_KEY_INDEX, PRIVATE_KEY_INDEX_LEN );
    if (current_count > max_count) goto failed;

    success = true;
failed:
    hss_zeroize( private_key, sizeof private_key );
    return success;
}
