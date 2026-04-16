#!/usr/bin/env python3
"""
patch_static_link.py - Patches OpenSSL C source files for Delphi static linking.

When OpenSSL is linked statically into a Delphi application (no DLL), certain
assumptions made by OpenSSL's build system break.  This patcher applies the
necessary source-level fixes before compilation and restores clean sources
afterwards, keeping the working tree close to upstream.

Usage:
  patch_static_link.py --apply      Apply patches (use .static cache when available)
  patch_static_link.py --restore    Cache patched files as .static, restore originals
  patch_static_link.py --status     Show which files are patched / clean / cached

Patches applied:
  1. crypto/init.c — disable OSSL_CLEANUP_USING_DESTRUCTOR
     On Windows, OPENSSL_cleanup() early-exits expecting DllMain to call the real
     destructor.  In static linking there is no DLL, so cleanup never runs.
     Guard: #if defined(OPENSSL_STATIC_LINK)

  2. crypto/o_fopen.c — replace _alloca with fixed stack buffer
     BCC32's ___alloca_helper intrinsic is incompatible with Delphi static linking
     (stack corruption prevents _wfopen from being called, BIO_new_file returns NULL).
     Replaces _alloca with WCHAR[MAX_PATH+1] stack buffer + fopen fallback for long paths.

Add new patches by:
  1. Adding the file to PATCHED_FILES
  2. Writing a patch_xxx() function that transforms file content
  3. Registering it in run_all_patches()

Conflict resolution (patch_c89.py vs patch_static_link.py):
  If the same file appears in both PATCHED_FILES lists, patch_c89.py is the SOLE
  owner of that file.  It applies BOTH C89 and static-link patches.
  patch_static_link.py SKIPS files owned by patch_c89.py (listed in C89_OWNED).

  Why: patch_c89.py runs only for BCC32 builds, which is the only compiler that
  needs C89 fixes.  If a file needs both C89 and static-link changes, only one
  patcher should manage its backup/restore cycle — otherwise .orig files conflict.

  For non-BCC32 builds (MSVC, BCC32C, BCC64) patch_c89.py is never called, so
  patch_static_link.py handles all static-link patches for files it owns.

  To add a shared file:
    1. Add the file to C89_OWNED in this script (it will be skipped here)
    2. Add the static-link patch logic to patch_c89.py for that file
    3. Keep the file in patch_c89.py's PATCHED_FILES
"""
import os
import shutil
import sys

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, '..'))
OPENSSL_BRANCH = os.environ.get('OPENSSL_BRANCH', '4')
BASE = os.environ.get('OPENSSL_SRC') or os.path.join(PROJECT_ROOT, 'c_src', 'openssl')

ORIG_SUFFIX = f'.orig_static_{OPENSSL_BRANCH}x'
CACHE_SUFFIX = f'.static_{OPENSSL_BRANCH}x'

# All source files managed by this patcher (relative to BASE).
PATCHED_FILES = [
    'crypto/init.c',
    'crypto/o_fopen.c',
    'ssl/methods.c',
    'include/openssl/err.h.in',
    'crypto/x509/v3_ac_tgt.c',
]

# Files that are ALSO in patch_c89.py PATCHED_FILES.
# patch_c89.py is the sole owner — it applies both C89 and static-link patches.
# This patcher SKIPS these files (they are handled by patch_c89.py for BCC32,
# and by this patcher for all other compilers only if NOT listed here).
C89_OWNED = [
    # Currently empty — no overlap.  If a file is added to both patchers,
    # move it here and add the static-link patch to patch_c89.py.
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_c89_owned(rel):
    """Return True if this file is owned by patch_c89.py (skip it here)."""
    return rel in C89_OWNED


def effective_files():
    """Return PATCHED_FILES minus C89_OWNED (files this patcher actually manages)."""
    return [f for f in PATCHED_FILES if not is_c89_owned(f)]

class Stats:
    def __init__(self):
        self.patched = 0
        self.skipped = 0
        self.errors = 0

    def report(self):
        print(f"\nDone: {self.patched} patched, "
              f"{self.skipped} already patched/cached, {self.errors} errors")


stats = Stats()

# ---------------------------------------------------------------------------
# File I/O helpers
# ---------------------------------------------------------------------------

def fpath(rel):
    """Convert a PATCHED_FILES relative path to an absolute path under BASE."""
    return os.path.join(BASE, rel.replace('/', os.sep))


def read_file(rel):
    with open(fpath(rel), 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def write_file(rel, content):
    with open(fpath(rel), 'w', encoding='utf-8', newline='') as f:
        f.write(content)

# ---------------------------------------------------------------------------
# Patch 1 — crypto/init.c: disable OSSL_CLEANUP_USING_DESTRUCTOR
# ---------------------------------------------------------------------------

INIT_C_MARKER = 'OPENSSL_STATIC_LINK'

INIT_C_BLOCK = r"""
/*
 * Static linking with Delphi -- no DllMain, no GCC destructor attribute.
 * On Windows, e_os.h defines OSSL_CLEANUP_USING_DESTRUCTOR which causes
 * OPENSSL_cleanup() to set a flag and return, expecting DllMain(DLL_PROCESS_DETACH)
 * to call ossl_cleanup_destructor(). In static linking there is no DLL, so the
 * destructor never fires. Force direct cleanup from OPENSSL_cleanup().
 * OPENSSL_STATIC_LINK is passed by all build scripts (BCC32, BCC32C, MSVC, BCC64).
 */
#if defined(OPENSSL_STATIC_LINK)
# undef OSSL_CLEANUP_USING_DESTRUCTOR
# define DO_NOT_SKIP_OPENSSL_CLEANUP
#endif
"""

# Anchor: we insert the block right before "static int stopped"
INIT_C_ANCHOR = 'static int stopped'


def patch_init_c(content):
    """Insert OPENSSL_STATIC_LINK guard into crypto/init.c."""
    if INIT_C_MARKER in content:
        return content  # already patched

    idx = content.find(INIT_C_ANCHOR)
    if idx == -1:
        print("  [ERROR] anchor not found in crypto/init.c: 'static int stopped'")
        stats.errors += 1
        return content

    return content[:idx] + INIT_C_BLOCK + content[idx:]

# ---------------------------------------------------------------------------
# Patch 2 — crypto/o_fopen.c: replace _alloca with fixed stack buffer
# ---------------------------------------------------------------------------

O_FOPEN_MARKER = 'wfilename_buf'

# BCC32's ___alloca_helper intrinsic is incompatible with Delphi static linking —
# causes stack corruption that prevents _wfopen from being reached (BIO_new_file
# returns NULL).  Replace with a fixed WCHAR[MAX_PATH+1] stack buffer and fall
# back to ANSI fopen() for paths longer than MAX_PATH.


def patch_o_fopen_c(content):
    """Replace _alloca with fixed stack buffer in crypto/o_fopen.c."""
    if O_FOPEN_MARKER in content:
        return content  # already patched

    # 1. Add wfilename_buf declaration to the variable block
    old_decl = '    DWORD flags;\n#endif'
    new_decl = ('    DWORD flags;\n'
                '    WCHAR wfilename_buf[MAX_PATH + 1];\n'
                '#endif')

    if old_decl not in content:
        print("  [ERROR] declaration anchor not found in crypto/o_fopen.c")
        stats.errors += 1
        return content

    content = content.replace(old_decl, new_decl, 1)

    # 2. Replace _alloca call with bounds check and stack buffer assignment
    old_alloca = '        WCHAR *wfilename = _alloca(sz * sizeof(WCHAR));'
    new_alloca = ('        WCHAR *wfilename;\n'
                  '\n'
                  '        if (sz > (int)OSSL_NELEM(wfilename_buf)) {\n'
                  '            file = fopen(filename, mode);\n'
                  '            return file;\n'
                  '        }\n'
                  '        wfilename = wfilename_buf;')

    if old_alloca not in content:
        print("  [ERROR] _alloca anchor not found in crypto/o_fopen.c")
        stats.errors += 1
        return content

    content = content.replace(old_alloca, new_alloca, 1)

    return content

# ---------------------------------------------------------------------------
# Patch 3 — ssl/methods.c: rename case-colliding TLS/DTLS internal functions
# ---------------------------------------------------------------------------

METHODS_MARKER = 'FIX_W1028_METHODS'

# The IMPLEMENT_tls_meth_func / IMPLEMENT_dtls1_meth_func macros in methods.c
# generate non-static internal functions (e.g. tlsv1_2_method) that collide
# case-insensitively with the public API wrappers (e.g. TLSv1_2_method).
# COFF compilers use /FI openssl_fix_case_collisions.h to rename these, but
# BCC32 classic has no forced-include mechanism.  Patching the source directly
# ensures all compilers benefit.  #ifndef guards prevent duplicate defines when
# the collision header is also active.

METHODS_RENAMES = [
    ('dtlsv1_2_client_method', 'dtlsv1_2_client_method_'),
    ('dtlsv1_2_method',        'dtlsv1_2_method_'),
    ('dtlsv1_2_server_method', 'dtlsv1_2_server_method_'),
    ('dtlsv1_client_method',   'dtlsv1_client_method_'),
    ('dtlsv1_method',          'dtlsv1_method_'),
    ('dtlsv1_server_method',   'dtlsv1_server_method_'),
    ('tlsv1_1_client_method',  'tlsv1_1_client_method_'),
    ('tlsv1_1_method',         'tlsv1_1_method_'),
    ('tlsv1_1_server_method',  'tlsv1_1_server_method_'),
    ('tlsv1_2_client_method',  'tlsv1_2_client_method_'),
    ('tlsv1_2_method',         'tlsv1_2_method_'),
    ('tlsv1_2_server_method',  'tlsv1_2_server_method_'),
    ('tlsv1_client_method',    'tlsv1_client_method_'),
    ('tlsv1_method',           'tlsv1_method_'),
    ('tlsv1_server_method',    'tlsv1_server_method_'),
]


def patch_methods_c(content):
    """Insert TLS/DTLS case-collision renames at top of ssl/methods.c."""
    if METHODS_MARKER in content:
        return content  # already patched

    lines = [f'/* {METHODS_MARKER}: rename case-colliding internal methods */']
    for old, new in METHODS_RENAMES:
        lines.append(f'#ifndef {old}')
        lines.append(f'#define {old} {new}')
        lines.append(f'#endif')
    block = '\n'.join(lines) + '\n'

    # Insert after the license comment block, before the first #include
    idx = content.find('#include')
    if idx == -1:
        print("  [ERROR] no #include found in ssl/methods.c")
        stats.errors += 1
        return content

    return content[:idx] + block + '\n' + content[idx:]

# ---------------------------------------------------------------------------
# Patch 4 — include/openssl/err.h.in: convert COMDAT-prone inline to macros
# ---------------------------------------------------------------------------
# We patch err.h.in (the template) rather than err.h because OpenSSL's build
# regenerates err.h from err.h.in via dofile.pl, which would overwrite patches.
# ---------------------------------------------------------------------------

ERR_H_MARKER = 'FIX_W1028_ERR_INLINE'

# MSVC emits static inline functions as COMDAT weak symbols in every .obj that
# includes err.h.  Delphi's linker doesn't understand COMDAT deduplication and
# warns W1028 for each duplicate.  Converting to preprocessor macros eliminates
# the symbols entirely — the code is expanded inline by the preprocessor.


def patch_err_h(content):
    """Replace ERR_GET_LIB and ERR_GET_REASON inline functions with macros."""
    if ERR_H_MARKER in content:
        return content  # already patched

    # Replace ERR_GET_LIB inline function
    old_get_lib = (
        'static ossl_unused ossl_inline int ERR_GET_LIB(unsigned long errcode)\n'
        '{\n'
        '    if (ERR_SYSTEM_ERROR(errcode))\n'
        '        return ERR_LIB_SYS;\n'
        '    return (errcode >> ERR_LIB_OFFSET) & ERR_LIB_MASK;\n'
        '}'
    )
    new_get_lib = (
        '/* ' + ERR_H_MARKER + ': macros instead of static inline to avoid COMDAT */\n'
        '#define ERR_GET_LIB(errcode) \\\n'
        '    (ERR_SYSTEM_ERROR(errcode) \\\n'
        '     ? ERR_LIB_SYS \\\n'
        '     : (int)(((errcode) >> ERR_LIB_OFFSET) & ERR_LIB_MASK))'
    )

    if old_get_lib not in content:
        print("  [ERROR] ERR_GET_LIB anchor not found in include/openssl/err.h")
        stats.errors += 1
        return content

    content = content.replace(old_get_lib, new_get_lib, 1)

    # Replace ERR_GET_REASON inline function
    old_get_reason = (
        'static ossl_unused ossl_inline int ERR_GET_REASON(unsigned long errcode)\n'
        '{\n'
        '    if (ERR_SYSTEM_ERROR(errcode))\n'
        '        return errcode & ERR_SYSTEM_MASK;\n'
        '    return errcode & ERR_REASON_MASK;\n'
        '}'
    )
    new_get_reason = (
        '#define ERR_GET_REASON(errcode) \\\n'
        '    (ERR_SYSTEM_ERROR(errcode) \\\n'
        '     ? (int)((errcode) & ERR_SYSTEM_MASK) \\\n'
        '     : (int)((errcode) & ERR_REASON_MASK))'
    )

    if old_get_reason not in content:
        print("  [ERROR] ERR_GET_REASON anchor not found in include/openssl/err.h")
        stats.errors += 1
        return content

    content = content.replace(old_get_reason, new_get_reason, 1)

    return content

# ---------------------------------------------------------------------------
# Patch 5 — crypto/x509/v3_ac_tgt.c: remove duplicate ASN.1 definitions
# ---------------------------------------------------------------------------
# v3_ac_tgt.c defines OSSL_ISSUER_SERIAL_it and OSSL_OBJECT_DIGEST_INFO_it
# with static_ASN1_SEQUENCE_END (static linkage).  These SAME symbols already
# have non-static (extern) definitions in x509_acert.c.  MSVC emits COMDAT
# sections for the string literals inside each definition; the Delphi linker
# cannot merge duplicate COMDAT data and warns W1028 for each.
#
# Fix: replace the static definitions with DECLARE_ASN1_ITEM() forward
# declarations, so v3_ac_tgt.c references x509_acert.c's extern definitions.
# This matches the pattern already used in v3_authattid.c (line 17).

V3_AC_TGT_MARKER = 'FIX_W1028_V3_AC_TGT'

# Exact text of the two static ASN1_SEQUENCE blocks (lines 43-55 of v3_ac_tgt.c)
_V3_AC_TGT_OLD = (
    'ASN1_SEQUENCE(OSSL_ISSUER_SERIAL) = {\n'
    '    ASN1_SEQUENCE_OF(OSSL_ISSUER_SERIAL, issuer, GENERAL_NAME),\n'
    '    ASN1_EMBED(OSSL_ISSUER_SERIAL, serial, ASN1_INTEGER),\n'
    '    ASN1_OPT(OSSL_ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING),\n'
    '} static_ASN1_SEQUENCE_END(OSSL_ISSUER_SERIAL)\n'
    '\n'
    '    ASN1_SEQUENCE(OSSL_OBJECT_DIGEST_INFO)\n'
    '    = {\n'
    '          ASN1_EMBED(OSSL_OBJECT_DIGEST_INFO, digestedObjectType, ASN1_ENUMERATED),\n'
    '          ASN1_OPT(OSSL_OBJECT_DIGEST_INFO, otherObjectTypeID, ASN1_OBJECT),\n'
    '          ASN1_EMBED(OSSL_OBJECT_DIGEST_INFO, digestAlgorithm, X509_ALGOR),\n'
    '          ASN1_EMBED(OSSL_OBJECT_DIGEST_INFO, objectDigest, ASN1_BIT_STRING),\n'
    '      } static_ASN1_SEQUENCE_END(OSSL_OBJECT_DIGEST_INFO)'
)

_V3_AC_TGT_NEW = (
    '/* ' + V3_AC_TGT_MARKER + ': use extern definitions from x509_acert.c\n'
    '   instead of local static copies — eliminates duplicate COMDAT symbols\n'
    '   that Delphi\'s linker cannot deduplicate (W1028). */\n'
    'DECLARE_ASN1_ITEM(OSSL_ISSUER_SERIAL)\n'
    'DECLARE_ASN1_ITEM(OSSL_OBJECT_DIGEST_INFO)'
)


def patch_v3_ac_tgt_c(content):
    """Remove duplicate static ASN1 definitions; use extern from x509_acert.c."""
    if V3_AC_TGT_MARKER in content:
        return content  # already patched

    if _V3_AC_TGT_OLD not in content:
        print("  [WARN] v3_ac_tgt.c anchor not found — source may have changed")
        # Don't increment errors — non-fatal (cosmetic W1028 only)
        return content

    content = content.replace(_V3_AC_TGT_OLD, _V3_AC_TGT_NEW, 1)
    return content

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def apply_single_patch(rel, desc, patch_fn):
    """Apply a single patch to a file. Idempotent. Skips C89-owned files."""
    if is_c89_owned(rel):
        print(f"=== {desc} — SKIPPED (owned by patch_c89.py) ===")
        return

    print(f"=== {desc} ===")
    try:
        content = read_file(rel)
    except FileNotFoundError:
        print(f"  [ERROR] not found: {rel}")
        stats.errors += 1
        return

    new = patch_fn(content)
    if new != content:
        write_file(rel, new)
        print(f"  [patched]   {rel}")
        stats.patched += 1
    else:
        print(f"  [skip]      {rel} (already patched)")
        stats.skipped += 1


def run_all_patches():
    """Run all patch categories. Idempotent. Skips C89-owned files."""
    apply_single_patch(
        'crypto/init.c',
        'Patch 1: crypto/init.c — disable OSSL_CLEANUP_USING_DESTRUCTOR',
        patch_init_c)
    apply_single_patch(
        'crypto/o_fopen.c',
        'Patch 2: crypto/o_fopen.c — replace _alloca with stack buffer',
        patch_o_fopen_c)
    apply_single_patch(
        'ssl/methods.c',
        'Patch 3: ssl/methods.c — rename case-colliding TLS/DTLS methods',
        patch_methods_c)
    apply_single_patch(
        'include/openssl/err.h.in',
        'Patch 4: include/openssl/err.h.in — ERR_GET_* inline to macro',
        patch_err_h)
    apply_single_patch(
        'crypto/x509/v3_ac_tgt.c',
        'Patch 5: crypto/x509/v3_ac_tgt.c — remove duplicate ASN1 COMDAT',
        patch_v3_ac_tgt_c)


def cmd_apply():
    """Apply static-link patches.

    For each managed file:
      1. If .orig_static does not exist — save current file as .orig_static (one-time backup).
      2. If .static cache exists — copy it over the source (fast path).
      3. Otherwise — ensure source is in original state (from .orig_static), then patch.
    """
    backed_up = 0
    cached = 0
    need_patch = False
    skipped_c89 = 0

    for rel in PATCHED_FILES:
        if is_c89_owned(rel):
            skipped_c89 += 1
            print(f"  [c89-owned] {rel} — skipped (managed by patch_c89.py)")
            continue

        src = fpath(rel)
        orig = src + ORIG_SUFFIX
        cache = src + CACHE_SUFFIX

        if not os.path.isfile(src):
            print(f"  [WARN] source not found: {rel}")
            continue

        # One-time: save original as .orig_static
        if not os.path.isfile(orig):
            shutil.copy2(src, orig)
            backed_up += 1

        if os.path.isfile(cache):
            # Fast path: use cached patched version
            shutil.copy2(cache, src)
            cached += 1
            print(f"  [cache]  {rel}")
        else:
            # Ensure file is in original state before patching
            shutil.copy2(orig, src)
            need_patch = True

    if skipped_c89:
        print(f"Skipped {skipped_c89} file(s) owned by patch_c89.py.")
    if backed_up:
        print(f"\nCreated {backed_up} .orig_static backup(s) (one-time).")
    if cached:
        print(f"Restored {cached} file(s) from .static cache.")

    if need_patch:
        uncached = len(effective_files()) - cached
        print(f"\nPatching {uncached} file(s) without cache...\n")
        run_all_patches()
    elif cached:
        print("All files served from cache — no patching needed.")


def cmd_restore():
    """Save patched files as .static cache, restore originals from .orig_static."""
    saved = 0
    restored = 0

    for rel in PATCHED_FILES:
        if is_c89_owned(rel):
            continue

        src = fpath(rel)
        orig = src + ORIG_SUFFIX
        cache = src + CACHE_SUFFIX

        if not os.path.isfile(src):
            continue

        # Save patched version to cache
        shutil.copy2(src, cache)
        saved += 1

        # Restore original from .orig_static
        if os.path.isfile(orig):
            shutil.copy2(orig, src)
            restored += 1
        else:
            print(f"  [WARN] no .orig_static for {rel} — cannot restore")

    print(f"Saved {saved} patched file(s) as .static cache.")
    print(f"Restored {restored} original(s) from .orig_static.")


# Per-file patch markers — used by cmd_status to detect patched state
MARKERS = {
    'crypto/init.c': INIT_C_MARKER,
    'crypto/o_fopen.c': O_FOPEN_MARKER,
    'ssl/methods.c': METHODS_MARKER,
    'include/openssl/err.h.in': ERR_H_MARKER,
    'crypto/x509/v3_ac_tgt.c': V3_AC_TGT_MARKER,
}


def cmd_status():
    """Show status of each managed file: clean / patched / cached / c89-owned."""
    print(f"{'File':<40} {'Owner':>12} {'Source':>10} {'Cache':>10} {'Backup':>10}")
    print("-" * 86)
    for rel in PATCHED_FILES:
        owner = 'c89' if is_c89_owned(rel) else 'static_link'

        src = fpath(rel)
        orig = src + ORIG_SUFFIX
        cache = src + CACHE_SUFFIX

        src_state = '—'
        if os.path.isfile(src):
            content = read_file(rel)
            marker = MARKERS.get(rel, '')
            src_state = 'PATCHED' if marker and marker in content else 'clean'

        cache_state = 'yes' if os.path.isfile(cache) else '—'
        orig_state = 'yes' if os.path.isfile(orig) else '—'

        print(f"{rel:<40} {owner:>12} {src_state:>10} {cache_state:>10} {orig_state:>10}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 64)
    print("patch_static_link.py: OpenSSL Static-Link Patcher for Delphi")
    print("=" * 64)
    print(f"Base: {BASE}")
    print(f"Branch: {OPENSSL_BRANCH} (OPENSSL_BRANCH env, default=4)\n")

    if not os.path.isdir(BASE):
        print(f"ERROR: Base directory not found: {BASE}")
        sys.exit(1)

    mode = sys.argv[1] if len(sys.argv) > 1 else None

    if mode == '--apply':
        cmd_apply()
    elif mode == '--restore':
        cmd_restore()
    elif mode == '--status':
        cmd_status()
    elif mode is None:
        print("Usage: patch_static_link.py [--apply | --restore | --status]")
        print()
        cmd_status()
    else:
        print(f"Unknown option: {mode}")
        print("Usage: patch_static_link.py [--apply | --restore | --status]")
        sys.exit(1)

    stats.report()


if __name__ == '__main__':
    main()
