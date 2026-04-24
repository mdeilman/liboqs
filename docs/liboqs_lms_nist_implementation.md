# liboqs: RFC 9858 / SP 800-208 LMS Parameter Sets — Implementation Journal

**Date:** 2025-04-24  
**Branch:** `feature/lms-nist-800-208`  
**Base:** `open-quantum-safe/liboqs` v0.15.0 (commit `ef70dea`)  
**Author:** Marius Deilmann

---

## Background

NIST SP 800-208 approves LMS/HSS for use in hardware cryptographic modules (HSMs) but mandates parameter sets beyond what RFC 8554 defines. The additional sets — using SHA-256/192, SHAKE256/256, and SHAKE256/192 — are specified in RFC 9858 (formerly `draft-fluhrer-lms-more-parm-sets`). As of liboqs 0.15.0, only the RFC 8554 SHA-256 parameter sets were implemented.

**Goal:** Add all 60 new single-tree LMS parameter sets to liboqs on a private branch, enabling CNSA 2.0 compliant LMS signing in an HSM product.

---

## Ecosystem Survey

| Implementation | Language | RFC 9858 support | Notes |
|---|---|---|---|
| `cisco/hash-sigs` | C | ❌ | RFC 8554 only; vendored into liboqs |
| `open-quantum-safe/liboqs` | C | ❌ | Only exposes Cisco's RFC 8554 sets |
| `ashman-p/liboqs-lms` | C | Partial | Started wiring layer, didn't touch crypto |
| Botan | C++ | ✅ | Independent implementation, full support |
| Bouncy Castle | Java | ✅ | Full support including SHAKE variants |

**Key finding:** We were the first to add RFC 9858 support to the liboqs/Cisco C layer.

---

## Architecture Overview

```
liboqs test / Python API
        │
   sig_stfl.c          ← dispatch table (alg name → _new, is_enabled, SECRET_KEY_new)
        │
   sig_stfl_lms.c      ← LMS_ALG macro instantiations (one per variant)
        │
   sig_stfl_lms_functions.c  ← OID → {lm_type, lm_ots_type} mapping; keypair/sign/verify
        │
   external/           ← Vendored Cisco hash-sigs C library
   ├── hss_keygen.c    ← hss_generate_private_key
   ├── hss_generate.c  ← Merkle tree computation
   ├── hss_param.c     ← Private key serialization (MODIFIED)
   ├── hss_derive.c    ← Seed derivation (MODIFIED)
   ├── hss_alloc.c     ← Working key allocation
   ├── lm_common.c     ← LMS parameter set lookup (MODIFIED)
   ├── lm_ots_common.c ← LMOTS parameter set lookup (MODIFIED)
   ├── hash.c/h        ← Hash abstraction layer (MODIFIED)
   └── common_defs.h   ← Type codes and constants (MODIFIED)
```

---

## New Parameter Sets

From RFC 9858 / NIST SP 800-208:

### LM-OTS (LMOTS) additions

| Code | Name | Hash | n | w | p | ls |
|------|------|------|---|---|---|-----|
| 0x05 | LMOTS_SHA256_N24_W1 | SHA-256/192 | 24 | 1 | 200 | 8 |
| 0x06 | LMOTS_SHA256_N24_W2 | SHA-256/192 | 24 | 2 | 101 | 6 |
| 0x07 | LMOTS_SHA256_N24_W4 | SHA-256/192 | 24 | 4 | 51 | 4 |
| 0x08 | LMOTS_SHA256_N24_W8 | SHA-256/192 | 24 | 8 | 26 | 0 |
| 0x09 | LMOTS_SHAKE_N32_W1 | SHAKE256/256 | 32 | 1 | 265 | 7 |
| 0x0a | LMOTS_SHAKE_N32_W2 | SHAKE256/256 | 32 | 2 | 133 | 6 |
| 0x0b | LMOTS_SHAKE_N32_W4 | SHAKE256/256 | 32 | 4 | 67 | 4 |
| 0x0c | LMOTS_SHAKE_N32_W8 | SHAKE256/256 | 32 | 8 | 34 | 0 |
| 0x0d | LMOTS_SHAKE_N24_W1 | SHAKE256/192 | 24 | 1 | 200 | 8 |
| 0x0e | LMOTS_SHAKE_N24_W2 | SHAKE256/192 | 24 | 2 | 101 | 6 |
| 0x0f | LMOTS_SHAKE_N24_W4 | SHAKE256/192 | 24 | 4 | 51 | 4 |
| 0x10 | LMOTS_SHAKE_N24_W8 | SHAKE256/192 | 24 | 8 | 26 | 0 |

### LMS additions

| Code | Name | Hash | n | H |
|------|------|------|---|---|
| 0x0a–0x0e | LMS_SHA256_N24_H{5,10,15,20,25} | SHA-256/192 | 24 | 5–25 |
| 0x0f–0x13 | LMS_SHAKE_N32_H{5,10,15,20,25} | SHAKE256/256 | 32 | 5–25 |
| 0x14–0x18 | LMS_SHAKE_N24_H{5,10,15,20,25} | SHAKE256/192 | 24 | 5–25 |

---

## Files Modified

### 1. `src/sig_stfl/lms/external/hash.h`

**Change:** Added three new hash type enum values and added `OQS_SHA3_shake256_inc_ctx` to the `union hash_context`.

```c
enum {
    HASH_SHA256      = 1,   /* SHA-256, full 32-byte output (RFC 8554) */
    HASH_SHA256_N24  = 2,   /* SHA-256 truncated to 24 bytes           */
    HASH_SHAKE256_N32 = 3,  /* SHAKE256/256, 32-byte output            */
    HASH_SHAKE256_N24 = 4,  /* SHAKE256/192, 24-byte output            */
};

union hash_context {
    OQS_SHA2_sha256_ctx sha256;
    OQS_SHA3_shake256_inc_ctx shake256;  /* NEW */
};
```

Also added `#include <oqs/sha3.h>`.

---

### 2. `src/sig_stfl/lms/external/hash.c`

**Change:** Added cases for all 3 new hash types in all 5 switch blocks:
- `hss_hash_ctx` — one-shot hashing
- `hss_init_hash_context` — incremental init
- `hss_update_hash_context` — incremental update
- `hss_finalize_hash_context` — incremental finalize
- `hss_hash_length` — output length in bytes
- `hss_hash_blocksize` — block size in bytes

**Key implementation notes:**
- `HASH_SHA256_N24`: Computes full SHA-256, then `memcpy` first 24 bytes into a 32-byte temp to avoid writing 32 bytes into a 24-byte destination buffer.
- `HASH_SHAKE256_N32/N24`: Uses OQS incremental API: `init → absorb → finalize → squeeze(n bytes)` followed by `ctx_release`.
- Block sizes: SHA-256 variants = 64 bytes, SHAKE256 variants = 136 bytes (rate = 1088 bits).

---

### 3. `src/sig_stfl/lms/external/common_defs.h`

**Change:** Added all 12 new LMOTS typecodes and 15 new LMS typecodes with RFC 9858 IANA-assigned values.

---

### 4. `src/sig_stfl/lms/external/lm_ots_common.c`

**Change:** Extended `lm_ots_look_up_parameter_set()` switch with 12 new cases for SHA-256/192, SHAKE256/256, and SHAKE256/192 parameter sets.

---

### 5. `src/sig_stfl/lms/external/lm_common.c`

**Change:** Extended `lm_look_up_parameter_set()` switch with 15 new cases.

---

### 6. `src/sig_stfl/lms/external/hss_internal.h`

**Change:** Extended private key encoding from 1 byte to 2 bytes per level.

```c
// Before:
#define PARAM_SET_COMPRESS_LEN 1

// After:
#define PARAM_SET_COMPRESS_LEN 2
```

**Why:** The original Cisco code used a nibble-packed encoding: `(lms_code << 4) | lmots_code`, which fit both codes in one byte but only supported values ≤ 0x0e. RFC 9858 LMOTS codes go up to 0x10, breaking this assumption. The new 2-byte format stores LMS and LMOTS codes as separate bytes.

**Impact on key sizes:** `PRIVATE_KEY_LEN` grows from 48 to 56 bytes. The liboqs `length_secret_key = 64` still accommodates this.

---

### 7. `src/sig_stfl/lms/external/hss_param.c`

**Change:** Rewrote `hss_compress_param_set()` and `hss_get_parameter_set()` to use the new 2-byte-per-level format.

**New compress format:**
- 2 bytes per occupied level: `[lms_type_byte, lmots_type_byte]`
- Remaining bytes filled with `0xff` (PARM_SET_END)
- Validation via `lm_look_up_parameter_set` and `lm_ots_look_up_parameter_set`

**Old format (incompatible):**
- 1 byte per level: `(a << 4) | b` (nibble-packed, max code 0x0e)
- Hard whitelist: only original RFC 8554 codes accepted

---

### 8. `src/sig_stfl/lms/external/hss_derive.c`

**Change:** Removed the `m != SEED_LEN` guard that was killing all N24 variants.

```c
// Removed:
if (derive->m != SEED_LEN) {
    return false;
}

// Replaced with comment:
/* RFC 9858 / SP 800-208 adds 192-bit hash variants (m=24)
 * so we no longer restrict to m == SEED_LEN (32). */
```

**Why this was needed:** The Cisco `SECRET_METHOD == 2` path (which liboqs uses) looked up the hash function from the parameter set and stored it in `derive->m`. It then checked `m == SEED_LEN (32)` and returned false for N24 variants where `m = 24`. The seed itself is always 32 bytes; only the hash *output* varies.

---

### 9. `src/sig_stfl/lms/sig_stfl_lms.h`

**Changes:**
- Added `OQS_LMS_ID_*` OID defines for all 60 new variants
- Added `_length_signature`, `_length_pk`, `_length_sk` defines
- Added function declarations for `*_new()` and `SECRET_KEY_*_new()`
- Updated `OQS_SIG_STFL_alg_lms_length_public_key` is no longer used by macro (replaced with per-variant defines)
- Added `_length_pk` defines for 2-level HSS variants (required after macro change)

---

### 10. `src/sig_stfl/lms/sig_stfl_lms.c`

**Changes:**
- Forward declarations for all 60 new `*_keypair()` functions
- `LMS_ALG()` macro invocations for all 60 variants
- Changed `sig->length_public_key = OQS_SIG_STFL_alg_lms_length_public_key` (global constant 60) to `sig->length_public_key = OQS_SIG_STFL_alg_lms_##lms_variant##_length_pk` (per-variant) in the `LMS_ALG` macro

**Critical fix:** The global `OQS_SIG_STFL_alg_lms_length_public_key = 60` was being used for all variants. N24 variants have `pk_len = 52`. This was causing heap corruption (60 bytes being freed from a 52-byte allocation).

---

### 11. `src/sig_stfl/lms/sig_stfl_lms_functions.c`

**Changes:**
- `oqs_lms_key_data.public_key[60]` — internal buffer remains 60 bytes (safe for all variants since the Cisco library writes the correct size)
- Added 60 new `case OQS_LMS_ID_*:` entries mapping OIDs to `{lm_type, lm_ots_type}` pairs
- Changed hardcoded `size_t len_public_key = 60` to `size_t len_public_key = 0` with dynamic computation via `hss_get_public_key_len()` after the OID switch

---

### 12. `src/sig_stfl/sig_stfl.h`

**Changes:**
- Added 60 string constant `#define OQS_SIG_STFL_alg_lms_*` entries
- Updated `OQS_SIG_STFL_algs_length` from 70 to 130

---

### 13. `src/sig_stfl/sig_stfl.c`

**Changes — four sections:**
1. Algorithm name list array (lines ~90): added 60 new `OQS_SIG_STFL_alg_lms_*` entries
2. `OQS_SIG_STFL_alg_is_enabled()`: 60 new `#ifdef` dispatch blocks
3. `OQS_SIG_STFL_new()`: 60 new `_new()` dispatch blocks
4. `OQS_SIG_STFL_SECRET_KEY_new()`: 60 new `SECRET_KEY_*_new()` dispatch blocks

**Note:** Section 4 was the last bug found — the `SECRET_KEY_new` dispatch was missing, causing `OQS_SIG_STFL_SECRET_KEY_new()` to return NULL, which caused the test's `public_key` free to appear at an invalid pointer (31 bytes before the allocation due to the `magic_t` sentinel pattern).

---

### 14. `.CMake/alg_support.cmake`

**Change:** Added 60 `cmake_dependent_option(OQS_ENABLE_SIG_STFL_lms_* "" ON "OQS_ENABLE_SIG_STFL_LMS" OFF)` entries.

---

### 15. `src/oqsconfig.h.cmake`

**Change:** Added 60 `#cmakedefine OQS_ENABLE_SIG_STFL_lms_* 1` entries. This is the template that CMake uses to generate `build/include/oqs/oqsconfig.h`, which provides the preprocessor `#define`s that gate algorithm availability.

---

## Bug Hunt Log

The implementation required fixing 9 distinct bugs, discovered in this order:

| # | Symptom | Root Cause | Fix |
|---|---------|-----------|-----|
| 1 | `not enabled!` | Missing `is_enabled` dispatch in `sig_stfl.c` | Added 60 `strcasecmp` blocks to `OQS_SIG_STFL_alg_is_enabled()` |
| 2 | `not enabled!` | `oqsconfig.h` not regenerated from template | Copy `src/sig_stfl/sig_stfl.h` → `build/include/oqs/sig_stfl.h` |
| 3 | heap crash / bad-free | `sig->length_public_key = 60` for all variants | Changed `LMS_ALG` macro to use per-variant `_length_pk` define |
| 4 | heap crash / bad-free | Missing `SECRET_KEY_new` dispatch (section 4 of `sig_stfl.c`) | Added 60 `OQS_SECRET_KEY_LMS_*_new()` dispatch blocks |
| 5 | `keypair failed` | `len_public_key = 60` hardcoded in `sig_stfl_lms_functions.c` | Changed to dynamic `hss_get_public_key_len()` call |
| 6 | `bad_param_set` (error 7) | Nibble encoding `(a<<4)\|b` limited to codes ≤ 0x0e | Rewrote `hss_param.c` with 2-byte-per-level encoding |
| 7 | `bad_param_set` on N24 | `m != SEED_LEN` guard in `hss_derive.c` rejected 24-byte hashes | Removed the guard |
| 8 | Stale objects | CMake incremental build not recompiling changed files | `rm -rf build/*` + clean rebuild |
| 9 | `-O3` confusion | Assumed `grep "0xa"` on optimized objects would find switch cases | Jump table optimization hides literal constants; use `-E` preprocessor instead |

---

## Build Instructions

```bash
# Clone and set up branch
git clone https://github.com/mdeilman/liboqs.git
cd liboqs
git checkout feature/lms-nist-800-208
git submodule update --init --recursive  # if applicable

# Clean build (always do this after patching)
mkdir -p build && cd build
cmake .. \
  -DOQS_ENABLE_SIG_STFL_LMS=ON \
  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel

# Test baseline
./tests/test_sig_stfl LMS_SHA256_H5_W8

# Test new SHA-256/192 variants
./tests/test_sig_stfl LMS_SHA256_N24_H5_W8

# Test new SHAKE256/256 variants
./tests/test_sig_stfl LMS_SHAKE_N32_H5_W8

# Test new SHAKE256/192 variants
./tests/test_sig_stfl LMS_SHAKE_N24_H5_W8
```

---

## Standalone Crypto Test

A standalone test (`test_lms_nist.c`) bypasses all liboqs wiring and tests the Cisco crypto layer directly. This was invaluable for debugging:

```bash
gcc test_lms_nist.c \
    -I/path/to/liboqs/src/sig_stfl/lms/external \
    -I/path/to/liboqs/build/include \
    -L/path/to/liboqs/build/lib \
    -Wl,-rpath,/path/to/liboqs/build/lib \
    -loqs -lssl -lcrypto -o test_lms_nist && ./test_lms_nist
```

Expected output (all 10 tests passing):

```
RFC 9858 / SP 800-208 LMS parameter set tests
=============================================
--- RFC 8554 baseline ---
Testing LMS_SHA256_N32_H5 / W8         ... PASS  (pk=60 sig=1296)
--- RFC 9858: SHA-256/192 ---
Testing LMS_SHA256_N24_H5 / W1         ... PASS  (pk=52 sig=4960)
...
--- RFC 9858: SHAKE256/256 ---
Testing LMS_SHAKE_N32_H5 / W1          ... PASS  (pk=60 sig=8688)
...
--- RFC 9858: SHAKE256/192 ---
Testing LMS_SHAKE_N24_H5 / W1          ... PASS  (pk=52 sig=4960)
...
All tests PASSED
```

---

## Key Size Reference

| Variant family | n | pk_len | sk_len | sig_len (H5/W8) |
|---|---|---|---|---|
| SHA-256/256 (RFC 8554) | 32 | 60 | 64 | 1296 |
| SHA-256/192 (RFC 9858) | 24 | 52 | 64 | 784 |
| SHAKE256/256 (RFC 9858) | 32 | 60 | 64 | 1296 |
| SHAKE256/192 (RFC 9858) | 24 | 52 | 64 | 784 |

Public key formula: `4 (HSS levels) + 4 (LMS type) + 4 (LMOTS type) + 16 (I) + n (root hash)`

---

## HSM / CNSA 2.0 Relevance

For firmware signing in an HSM product, the most relevant parameter sets are:
- `LMS_SHA256_N24_H*` / `LMOTS_SHA256_N24_W*` — mandated by SP 800-208 for hardware modules
- `LMS_SHAKE_N32_H*` / `LMOTS_SHAKE_N32_W*` — required for CNSA 2.0 compliance
- SP 800-208 requires key generation and signing to be performed in hardware that does not allow secret key export

---

## Known Limitations / Future Work

- Two-level HSS combinations (e.g., `LMS_SHA256_N24_H10_W4_LMS_SHA256_N24_H5_W8`) are not yet wired — only single-tree variants are implemented
- The `apply_lms_nist_patches.py` script works but has fragile anchor patterns; it was used during development but the changes are now committed
- KAT (Known Answer Test) vectors from RFC 9858 / SP 800-208 have not yet been integrated into the test harness
- Code generator scripts (`scripts/copy_from_upstream/`) for downstream language bindings (Python, Go, Java, Rust) have not been run — do this before upstreaming

---

## References

- [NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final) — Recommendation for Stateful Hash-Based Signature Schemes
- [RFC 8554](https://www.rfc-editor.org/rfc/rfc8554) — Leighton-Micali Hash-Based Signatures
- [RFC 9858](https://www.rfc-editor.org/rfc/rfc9858) — Additional Parameter Sets for HSS/LMS
- [cisco/hash-sigs](https://github.com/cisco/hash-sigs) — Upstream LMS C implementation vendored into liboqs
- [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs) — Main liboqs repository
- [Botan HSS/LMS](https://github.com/randombit/botan/tree/master/src/lib/pubkey/hss_lms) — Reference C++ implementation with full RFC 9858 support
