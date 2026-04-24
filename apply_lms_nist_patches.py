#!/usr/bin/env python3
"""
Patch liboqs to wire up the NIST SP 800-208 / RFC 9858 LMS parameter sets.

Files patched:
  src/sig_stfl/sig_stfl.h              -- string constants
  src/sig_stfl/lms/sig_stfl_lms.h      -- OIDs, length macros, declarations
  src/sig_stfl/lms/sig_stfl_lms.c      -- forward decls + LMS_ALG calls
  src/sig_stfl/lms/sig_stfl_lms_functions.c -- switch(oid) cases

Run from the root of the liboqs repo:
  python3 apply_lms_nist_patches.py
"""

import os, sys, re

ROOT = os.path.dirname(os.path.abspath(__file__))
# If running from the patch dir, go one up to the repo root
if not os.path.isdir(os.path.join(ROOT, "src")):
    ROOT = os.path.abspath(os.path.join(ROOT, ".."))
if not os.path.isdir(os.path.join(ROOT, "src")):
    print("ERROR: Run this script from the liboqs repo root, or place it there.")
    sys.exit(1)

# ── Parameter definitions ─────────────────────────────────────────────────────

HEIGHTS   = [5, 10, 15, 20, 25]
WVALUES   = [1, 2, 4, 8]

# (prefix, lms_macro_prefix, lmots_macro_prefix, n, p_per_w, hash_enum)
# p_per_w: dict w -> p value (from RFC 9858)
HASH_FAMILIES = [
    {
        "prefix":       "sha256_n24",
        "LMS_PFX":      "LMS_SHA256_N24",   # in common_defs.h
        "LMOTS_PFX":    "LMOTS_SHA256_N24",
        "n":            24,
        "pk":           52,
        "p": {1: 200, 2: 101, 4: 51, 8: 26},
        # OID base: 0x01 | (LMS_ID byte) | (LMOTS_ID byte)
        # LMS_SHA256_N24_H5=0x0a, LMOTS_SHA256_N24_W1=0x05
        "lms_id_base":  0x0a,  # +0,+1,+2,+3,+4 for H5..H25
        "lmots_id_base":0x05,  # +0,+1,+2,+3 for W1..W8
        "label":        "SHA-256/192",
    },
    {
        "prefix":       "shake_n32",
        "LMS_PFX":      "LMS_SHAKE_N32",
        "LMOTS_PFX":    "LMOTS_SHAKE_N32",
        "n":            32,
        "pk":           60,
        "p": {1: 265, 2: 133, 4: 67, 8: 34},
        "lms_id_base":  0x0f,  # LMS_SHAKE_N32_H5=0x0f
        "lmots_id_base":0x09,  # LMOTS_SHAKE_N32_W1=0x09
        "label":        "SHAKE256/256",
    },
    {
        "prefix":       "shake_n24",
        "LMS_PFX":      "LMS_SHAKE_N24",
        "LMOTS_PFX":    "LMOTS_SHAKE_N24",
        "n":            24,
        "pk":           52,
        "p": {1: 200, 2: 101, 4: 51, 8: 26},
        "lms_id_base":  0x14,  # LMS_SHAKE_N24_H5=0x14
        "lmots_id_base":0x0d,  # LMOTS_SHAKE_N24_W1=0x0d
        "label":        "SHAKE256/192",
    },
]

W_INDEX = {1: 0, 2: 1, 4: 2, 8: 3}
H_INDEX = {5: 0, 10: 1, 15: 2, 20: 3, 25: 4}

def sig_len(n, p, h):
    """HSS single-level signature length."""
    return 4 + 4 + 4 + (4 + n + p * n) + n * h

def oid(fam, h, w):
    lms_id  = fam["lms_id_base"]  + H_INDEX[h]
    lmots_id= fam["lmots_id_base"]+ W_INDEX[w]
    return (0x01 << 16) | (lms_id << 8) | lmots_id

def variant_name(fam, h, w):
    return f"{fam['prefix']}_h{h}_w{w}"

def VARIANT_NAME(fam, h, w):
    return variant_name(fam, h, w).upper()

# ── Snippet generators ────────────────────────────────────────────────────────

def sig_stfl_h_snippet():
    lines = [
        "",
        "/* ----- RFC 9858 / SP 800-208 additions (auto-generated) ----- */",
    ]
    for fam in HASH_FAMILIES:
        lines.append(f"/* {fam['label']} */")
        for h in HEIGHTS:
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                lines.append(
                    f'#define OQS_SIG_STFL_alg_lms_{vn} '
                    f'"LMS_{VARIANT_NAME(fam,h,w)}" //{fam["label"]} H{h}/W{w}'
                )
    return "\n".join(lines) + "\n"


def sig_stfl_lms_h_snippet():
    lines = [
        "",
        "/* ----- RFC 9858 / SP 800-208 OIDs (auto-generated) ----- */",
    ]
    for fam in HASH_FAMILIES:
        lines.append(f"/* {fam['label']} */")
        for h in HEIGHTS:
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                VN = VARIANT_NAME(fam, h, w)
                o  = oid(fam, h, w)
                sl = sig_len(fam["n"], fam["p"][w], h)
                pk = fam["pk"]
                lines += [
                    f"#define OQS_LMS_ID_{vn} 0x{o:06x}",
                    f"#define OQS_SIG_STFL_alg_lms_{vn}_length_signature {sl}",
                    f"#define OQS_SIG_STFL_alg_lms_{vn}_length_pk {pk}",
                    f"#define OQS_SIG_STFL_alg_lms_{vn}_length_sk 64",
                    f"OQS_API OQS_SIG_STFL *OQS_SIG_STFL_alg_lms_{vn}_new(void);",
                    f"OQS_API OQS_SIG_STFL_SECRET_KEY *OQS_SECRET_KEY_LMS_{VN}_new(void);",
                    "",
                ]
    return "\n".join(lines) + "\n"


def sig_stfl_lms_c_fwd_snippet():
    """Forward declarations only — inserted after existing forward decls."""
    lines = [
        "",
        "/* ----- RFC 9858 / SP 800-208 forward declarations (auto-generated) ----- */",
    ]
    for fam in HASH_FAMILIES:
        lines.append(f"/* {fam['label']} */")
        for h in HEIGHTS:
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                lines.append(
                    f"OQS_STATUS OQS_SIG_STFL_alg_lms_{vn}_keypair"
                    f"(uint8_t *public_key, OQS_SIG_STFL_SECRET_KEY *secret_key);"
                )
    return "\n".join(lines) + "\n"


def sig_stfl_lms_c_alg_snippet():
    """LMS_ALG macro calls only — inserted after last existing LMS_ALG call.
    NOTE: OQS_SECRET_KEY_LMS_*_new() is already generated by the LMS_ALG macro;
    no separate definition is needed here."""
    lines = [
        "",
        "/* ----- RFC 9858 / SP 800-208 LMS_ALG instantiations (auto-generated) ----- */",
    ]
    for fam in HASH_FAMILIES:
        lines.append(f"/* {fam['label']} */")
        for h in HEIGHTS:
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                VN = VARIANT_NAME(fam, h, w)
                lines.append(f"LMS_ALG({vn}, {VN})")
                lines.append("")
    return "\n".join(lines) + "\n"


def alg_support_cmake_snippet():
    lines = [
        "",
        "# RFC 9858 / SP 800-208 additions (auto-generated)",
    ]
    for fam in HASH_FAMILIES:
        lines.append(f"# {fam['label']}")
        for h in HEIGHTS:
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                lines.append(
                    f'cmake_dependent_option(OQS_ENABLE_SIG_STFL_lms_{vn} "" ON "OQS_ENABLE_SIG_STFL_LMS" OFF)'
                )
    return "\n".join(lines) + "\n"


def sig_stfl_c_namelist_snippet():
    lines = ["", "                // RFC 9858 / SP 800-208 LMS additions"]
    for fam in HASH_FAMILIES:
        lines.append(f"                // {fam['label']}")
        for h in HEIGHTS:
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                lines.append(f"                OQS_SIG_STFL_alg_lms_{vn},")
    return "\n".join(lines) + "\n"


def sig_stfl_c_isenabled_snippet():
    lines = [""]
    for fam in HASH_FAMILIES:
        lines.append(f"        // {fam['label']}")
        for h in HEIGHTS:
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                lines += [
                    f"    }} else if (0 == strcasecmp(method_name, OQS_SIG_STFL_alg_lms_{vn})) {{",
                    f"#ifdef OQS_ENABLE_SIG_STFL_lms_{vn}",
                    f"                return 1;",
                    f"#else",
                    f"                return 0;",
                    f"#endif",
                ]
    return "\n".join(lines) + "\n"


def sig_stfl_c_new_snippet():
    lines = [""]
    for fam in HASH_FAMILIES:
        lines.append(f"        // {fam['label']}")
        for h in HEIGHTS:
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                lines += [
                    f"    }} else if (0 == strcasecmp(method_name, OQS_SIG_STFL_alg_lms_{vn})) {{",
                    f"#ifdef OQS_ENABLE_SIG_STFL_lms_{vn}",
                    f"                return OQS_SIG_STFL_alg_lms_{vn}_new();",
                    f"#else",
                    f"                return NULL;",
                    f"#endif",
                ]
    return "\n".join(lines) + "\n"


def sig_stfl_lms_functions_c_snippet():
    lines = [
        "",
        "        /* ----- RFC 9858 / SP 800-208 single-tree cases (auto-generated) ----- */",
    ]
    for fam in HASH_FAMILIES:
        lines.append(f"        /* {fam['label']} */")
        for h in HEIGHTS:
            lms_macro  = f"{fam['LMS_PFX']}_H{h}"
            for w in WVALUES:
                vn = variant_name(fam, h, w)
                lmots_macro = f"{fam['LMOTS_PFX']}_W{w}"
                lines += [
                    f"        case OQS_LMS_ID_{vn}:",
                    f"            oqs_key_data->lm_type[0]     = {lms_macro};",
                    f"            oqs_key_data->lm_ots_type[0] = {lmots_macro};",
                    f"            break;",
                ]
    return "\n".join(lines) + "\n"

# ── File patchers ─────────────────────────────────────────────────────────────

def patch_file(path, anchor_pattern, snippet, after=True, check_pattern=None, first_match=False):
    """Insert snippet after (or before) the first line matching anchor_pattern."""
    full_path = os.path.join(ROOT, path)
    with open(full_path, "r") as f:
        content = f.read()

    if check_pattern and re.search(check_pattern, content):
        print(f"  SKIP {path} (already patched)")
        return

    lines = content.splitlines(keepends=True)
    insert_at = None
    for i, line in enumerate(lines):
        if re.search(anchor_pattern, line):
            insert_at = i + 1 if after else i
            if first_match:
                break
    if insert_at is None:
        print(f"  ERROR: anchor not found in {path}: {anchor_pattern}")
        return

    lines.insert(insert_at, snippet)
    with open(full_path, "w") as f:
        f.writelines(lines)
    print(f"  PATCHED {path}")


def main():
    print("Patching liboqs for RFC 9858 / SP 800-208 LMS parameter sets...\n")

    # 1. sig_stfl.h — append string constants after last sha256 LMS line
    patch_file(
        "src/sig_stfl/sig_stfl.h",
        anchor_pattern=r'OQS_SIG_STFL_alg_lms_sha256_h25_w8\b.*"LMS_SHA256_H25_W8"',
        snippet=sig_stfl_h_snippet(),
        after=True,
        check_pattern=r'OQS_SIG_STFL_alg_lms_sha256_n24_h5_w1',
    )

    # 2. sig_stfl_lms.h — insert before final #endif
    patch_file(
        "src/sig_stfl/lms/sig_stfl_lms.h",
        anchor_pattern=r'#endif\s*/\*\s*OQS_SIG_STFL_LMS_H\s*\*/',
        snippet=sig_stfl_lms_h_snippet(),
        after=False,
        check_pattern=r'OQS_LMS_ID_sha256_n24_h5_w1',
    )

    # 3a. sig_stfl_lms.c — forward declarations after last existing forward decl
    patch_file(
        "src/sig_stfl/lms/sig_stfl_lms.c",
        anchor_pattern=r'OQS_SIG_STFL_alg_lms_sha256_h25_w8_keypair\b',
        snippet=sig_stfl_lms_c_fwd_snippet(),
        after=True,
        check_pattern=r'sha256_n24_h5_w1_keypair',
    )

    # 3b. sig_stfl_lms.c — LMS_ALG calls after last single-tree instantiation
    patch_file(
        "src/sig_stfl/lms/sig_stfl_lms.c",
        anchor_pattern=r'LMS_ALG\(sha256_h25_w8,\s*SHA256_H25_W8\)',
        snippet=sig_stfl_lms_c_alg_snippet(),
        after=True,
        check_pattern=r'LMS_ALG\(sha256_n24_h5_w1,',
    )

    # 4. sig_stfl_lms_functions.c — insert new cases before first 2-level case
    patch_file(
        "src/sig_stfl/lms/sig_stfl_lms_functions.c",
        anchor_pattern=r'case OQS_LMS_ID_sha256_h5_w8_h5_w8:',
        snippet=sig_stfl_lms_functions_c_snippet(),
        after=False,
        check_pattern=r'OQS_LMS_ID_sha256_n24_h5_w1',
    )

    # 5. alg_support.cmake — add cmake_dependent_option entries
    patch_file(
        ".CMake/alg_support.cmake",
        anchor_pattern=r'OQS_ENABLE_SIG_STFL_lms_sha256_h25_w8\b',
        snippet=alg_support_cmake_snippet(),
        after=True,
        check_pattern=r'OQS_ENABLE_SIG_STFL_lms_sha256_n24_h5_w1',
    )

    # 6a. sig_stfl.c — algorithm name list
    patch_file(
        "src/sig_stfl/sig_stfl.c",
        anchor_pattern=r'OQS_SIG_STFL_alg_lms_sha256_h25_w8,$',
        snippet=sig_stfl_c_namelist_snippet(),
        after=True,
        check_pattern=r'OQS_SIG_STFL_alg_lms_sha256_n24_h5_w1,',
    )

    # 6b. sig_stfl.c — is_enabled dispatch
    patch_file(
        "src/sig_stfl/sig_stfl.c",
        anchor_pattern=r'OQS_ENABLE_SIG_STFL_lms_sha256_h25_w8\b',
        snippet=sig_stfl_c_isenabled_snippet(),
        after=True,
        check_pattern=r'strcasecmp.*sha256_n24_h5_w1',
        first_match=True,
    )

    # 6c. sig_stfl.c — _new() dispatch
    patch_file(
        "src/sig_stfl/sig_stfl.c",
        anchor_pattern=r'OQS_SIG_STFL_alg_lms_sha256_h25_w8_new\(\)',
        snippet=sig_stfl_c_new_snippet(),
        after=True,
        check_pattern=r'OQS_SIG_STFL_alg_lms_sha256_n24_h5_w1_new',
    )

    # 7. sig_stfl.h — update algs_length (70 + 60 = 130)
    for path in [
        "src/sig_stfl/sig_stfl.h",
        "build/include/oqs/sig_stfl.h",
    ]:
        full = os.path.join(ROOT, path)
        if not os.path.exists(full):
            print(f"  SKIP {path} (not found)")
            continue
        with open(full, "r") as f:
            content = f.read()
        if "algs_length 130" in content:
            print(f"  SKIP {path} (already updated)")
            continue
        new_content = re.sub(
            r'(#define OQS_SIG_STFL_algs_length\s+)70\b',
            r'\g<1>130',
            content,
        )
        if new_content == content:
            print(f"  ERROR: algs_length pattern not found in {path}")
        else:
            with open(full, "w") as f:
                f.write(new_content)
            print(f"  PATCHED {path} (algs_length 70 -> 130)")

    # 8. oqsconfig.h.cmake — add #cmakedefine entries
    patch_file(
        "src/oqsconfig.h.cmake",
        anchor_pattern=r'#cmakedefine OQS_ENABLE_SIG_STFL_lms_sha256_h25_w8',
        snippet="\n".join(
            ["", "/* RFC 9858 / SP 800-208 additions (auto-generated) */"] +
            [f"#cmakedefine OQS_ENABLE_SIG_STFL_lms_{variant_name(fam,h,w)} 1"
             for fam in HASH_FAMILIES for h in HEIGHTS for w in WVALUES]
        ) + "\n",
        after=True,
        check_pattern=r'OQS_ENABLE_SIG_STFL_lms_sha256_n24_h5_w1',
    )
    print("  cd build && cmake --build . --parallel")


if __name__ == "__main__":
    main()
