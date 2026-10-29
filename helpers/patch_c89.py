#!/usr/bin/env python3
"""
patch_c89.py - Patches OpenSSL C source files for bcc32 (C89) compatibility.

Usage:
  patch_c89.py              Patch in-place (legacy, idempotent)
  patch_c89.py --apply      Apply patches: use .bcc32 cache if available,
                            otherwise patch from clean sources.
  patch_c89.py --restore    Save patched files as .bcc32 cache,
                            restore originals via git checkout.

Categories:
  1. C99 for-loop declarations -> pre-declared variables
  2. C99 mixed declarations -> moved to block start
  3. Designated initializers -> memset + field assignments or positional
  4. qsort/bsearch callback casts -> __cdecl cast (guarded by #ifdef __BORLANDC__)
  5. signal() type mismatch -> __cdecl cast (guarded by #ifdef __BORLANDC__)
  6. struct bignum_st -> add bn_local.h include
  7. OSSL_PARAM_construct arrays -> runtime assignment
  8. Function pointer typedef CC fix -> __cdecl for CRT fn ptrs (guarded by #ifdef __BORLANDC__)
"""
import os
import re
import shutil
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, '..'))
OPENSSL_BRANCH = os.environ.get('OPENSSL_BRANCH', '4')
BASE = os.environ.get('OPENSSL_SRC') or os.path.join(PROJECT_ROOT, 'c_src', 'openssl')

CDECL_QSORT = '(int (__cdecl *)(const void *, const void *))'
CDECL_SIGNAL = '(void (__cdecl *)(int))'

CACHE_SUFFIX = f'.bcc32_{OPENSSL_BRANCH}x'

# All source files that may be patched (relative to BASE).
# Keep in sync when adding new patch categories.
PATCHED_FILES = [
    'crypto/asn1/tasn_enc.c',
    'crypto/bio/bio_print.c',
    'crypto/bn/bn_const.c',
    'crypto/bn/bn_exp.c',
    'crypto/init.c',
    'crypto/mem_clr.c',
    'crypto/conf/conf_ssl.c',
    'crypto/dh/dh_rfc5114.c',
    'crypto/evp/enc_b64_scalar.c',
    'crypto/evp/encode.c',
    'crypto/evp/evp_lib.c',
    'crypto/ex_data.c',
    'crypto/ffc/ffc_dh.c',
    'crypto/objects/o_names.c',
    'crypto/params_dup.c',
    'crypto/property/property.c',
    'crypto/rsa/rsa_sp800_56b_check.c',
    'crypto/sha/sha512.c',
    'crypto/srp/srp_lib.c',
    'crypto/pkcs7/pk7_doit.c',
    'crypto/stack/stack.c',
    'crypto/threads_win.c',
    'crypto/ui/ui_openssl.c',
    'crypto/x509/v3_purp.c',
    'crypto/x509/x509_lu.c',
    'crypto/x509/x509_vfy.c',
    'crypto/x509/x509_vpm.c',
    'providers/implementations/digests/cshake_prov.c',
    'providers/implementations/encode_decode/ml_common_codecs.c',
    'providers/implementations/kdfs/ikev2kdf.c',
    'providers/implementations/keymgmt/dsa_kmgmt.c',
    'providers/implementations/keymgmt/ec_kmgmt.c',
    'providers/implementations/keymgmt/rsa_kmgmt.c',
    'ssl/quic/qlog.c',
    'ssl/quic/quic_txpim.c',
    'ssl/s3_lib.c',
    'ssl/ssl_ciph.c',
    'ssl/ssl_lib.c',
    'ssl/ssl_sess.c',
    'ssl/statem/extensions_srvr.c',
    'ssl/statem/statem_lib.c',
    'ssl/t1_enc.c',
    'ssl/t1_lib.c',
]


class Stats:
    def __init__(self):
        self.patched = 0
        self.skipped = 0
        self.errors = 0

    def report(self):
        print(f"\nDone: {self.patched} patched, "
              f"{self.skipped} already patched, {self.errors} errors")


stats = Stats()


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def fpath(rel):
    return os.path.join(BASE, rel.replace('/', os.sep))


def read_file(rel):
    with open(fpath(rel), 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def write_file(rel, content):
    with open(fpath(rel), 'w', encoding='utf-8', newline='') as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def apply_text(rel, patches):
    """Apply a list of (old, new) text replacements to *rel*.
    Returns number of replacements made."""
    try:
        content = read_file(rel)
    except FileNotFoundError:
        print(f"  [ERROR] not found: {rel}")
        stats.errors += 1
        return 0

    n = 0
    for old, new in patches:
        if old in content:
            content = content.replace(old, new, 1)
            n += 1

    if n > 0:
        write_file(rel, content)
        print(f"  [{n:2d} fix(es)] {rel}")
        stats.patched += 1
    else:
        print(f"  [skip]      {rel}")
        stats.skipped += 1
    return n


def find_block_start(lines, idx):
    """Return line number of the nearest enclosing '{' for *idx*."""
    depth = 0
    for i in range(idx - 1, -1, -1):
        for ch in reversed(lines[i]):
            if ch == '}':
                depth += 1
            elif ch == '{':
                if depth == 0:
                    return i
                depth -= 1
    return None


def fix_c99_for_loops(content):
    """Rewrite ``for (TYPE var = ...`` -> declare var before loop."""
    for_re = re.compile(
        r'^(\s*)for\s*\(\s*'
        r'((?:size_t|int)\s+|SSL_CIPHER\s*\*\s*)'
        r'(\w+)\s*=',
        re.MULTILINE,
    )

    lines = content.split('\n')
    # Track which variables have been declared per block start line
    declared_vars = {}  # block_start_line -> set of var names

    changed = True
    while changed:
        changed = False
        for i, line in enumerate(lines):
            m = for_re.match(line)
            if not m:
                continue
            indent = m.group(1)
            type_str = m.group(2).strip()
            var = m.group(3)

            # Rewrite the for-loop: remove type
            lines[i] = indent + 'for (' + var + ' =' + line[m.end():]

            # Insert declaration at enclosing block start (only if not yet declared)
            blk = find_block_start(lines, i)
            if blk is not None:
                if blk not in declared_vars:
                    declared_vars[blk] = set()
                if var not in declared_vars[blk]:
                    declared_vars[blk].add(var)
                    if '*' in type_str:
                        decl = f'{indent}{type_str}{var};'
                    else:
                        decl = f'{indent}{type_str} {var};'
                    lines.insert(blk + 1, decl)

            changed = True
            break  # restart: indices shifted

    return '\n'.join(lines)


def fix_qsort_calls(content):
    """Add __cdecl cast to the comparator arg of every qsort() call,
    guarded by #ifdef __BORLANDC__ so it only activates for BCC32."""
    result = content
    pos = 0
    while True:
        idx = result.find('qsort(', pos)
        if idx == -1:
            break

        # Find matching closing paren
        start = idx + 6
        depth = 1
        j = start
        while j < len(result) and depth > 0:
            if result[j] == '(':
                depth += 1
            elif result[j] == ')':
                depth -= 1
            j += 1

        if depth != 0:
            pos = idx + 1
            continue

        close = j - 1  # position of ')'

        # Find last comma at depth-0
        last_comma = None
        depth = 0
        for k in range(start, close):
            if result[k] == '(':
                depth += 1
            elif result[k] == ')':
                depth -= 1
            elif result[k] == ',' and depth == 0:
                last_comma = k

        if last_comma is None:
            pos = close + 1
            continue

        arg_text = result[last_comma + 1:close]
        stripped = arg_text.strip()

        if stripped.startswith('(') or '#ifdef __BORLANDC__' in arg_text:
            # already cast or guarded
            pos = close + 1
            continue

        guarded_cast = ('\n#ifdef __BORLANDC__\n'
                        + CDECL_QSORT + '\n'
                        + '#endif\n')
        new_arg = arg_text.replace(stripped, guarded_cast + stripped, 1)
        result = result[:last_comma + 1] + new_arg + result[close:]
        pos = last_comma + 1 + len(new_arg)

    return result


# ---------------------------------------------------------------------------
# Category 1 - C99 for-loop declarations
# ---------------------------------------------------------------------------

def patch_c99_for_loops():
    print("=== Category 1: C99 for-loop declarations ===")
    files = [
        'crypto/conf/conf_ssl.c',
        'crypto/property/property.c',
        'crypto/x509/v3_purp.c',
        'crypto/x509/x509_lu.c',
        'crypto/x509/x509_vfy.c',
        'ssl/t1_lib.c',
        'ssl/ssl_ciph.c',
        'ssl/s3_lib.c',
        'providers/implementations/digests/cshake_prov.c',
    ]
    for rel in files:
        try:
            content = read_file(rel)
        except FileNotFoundError:
            print(f"  [ERROR] not found: {rel}")
            stats.errors += 1
            continue

        new = fix_c99_for_loops(content)
        if new != content:
            write_file(rel, new)
            print(f"  [fixed]     {rel}")
            stats.patched += 1
        else:
            print(f"  [skip]      {rel}")
            stats.skipped += 1


# ---------------------------------------------------------------------------
# Category 2 - Mixed declarations (var after statement)
# ---------------------------------------------------------------------------

def patch_mixed_declarations():
    print("\n=== Category 2: C99 mixed declarations ===")

    # --- crypto/bio/bio_print.c ---
    # Move char buf[512] and char *abuf into the #if guard, remove from #else
    apply_text('crypto/bio/bio_print.c', [
        # Classic BCC32 has a pointer va_list but no va_copy macro. An
        # implicit function call cannot assign the caller's local va_list.
        ('va_copy(cp_args, args);', 'cp_args = args; /* BCC32 pointer va_list copy */'),
        (
            '#if !defined(_MSC_VER) || _MSC_VER >= 1900\n    int sz;\n#endif',
            '#if !defined(_MSC_VER) || _MSC_VER >= 1900\n'
            '    char buf[512];\n    char *abuf;\n    int sz;\n#endif',
        ),
        (
            '#else\n    char buf[512];\n    char *abuf;\n',
            '#else\n',
        ),
        # C89: struct pr_desc aggregate init uses runtime values (C99 feature)
        # Split into declaration + member assignments (after all declarations)
        (
            '    struct pr_desc desc = { *sbuffer, buffer, 0, *maxlen, 0 };\n'
            '    int ret = 0;\n'
            '\n'
            '    state = DP_S_DEFAULT;',
            '    struct pr_desc desc;\n'
            '    int ret = 0;\n'
            '\n'
            '    desc.sbuffer = *sbuffer;\n'
            '    desc.buffer = buffer;\n'
            '    desc.currlen = 0;\n'
            '    desc.maxlen = *maxlen;\n'
            '    desc.pos = 0;\n'
            '    state = DP_S_DEFAULT;',
        ),
    ])

    # --- crypto/evp/enc_b64_scalar.c ---
    # int wrap_cnt_nm3 = 0  after  i = 0  -> split decl/assignment
    apply_text('crypto/evp/enc_b64_scalar.c', [
        (
            '        i = 0;\n        int wrap_cnt_nm3 = 0;',
            '        int wrap_cnt_nm3;\n        i = 0;\n        wrap_cnt_nm3 = 0;',
        ),
    ])

    # --- crypto/evp/encode.c ---
    # Two wrap_cnt declarations after statements; hoist to function level.
    # 4.0.0 final: declarations are int i; size_t j; (not int i, j;)
    apply_text('crypto/evp/encode.c', [
        # Hoist wrap_cnt to function-level declarations (before size_t j)
        (
            '    int i;\n    size_t j;\n    size_t total = 0;',
            '    int i;\n    int wrap_cnt;\n    size_t j;\n    size_t total = 0;',
        ),
        # Inner block: strip type from mid-block declaration (now at function level)
        (
            '        inl -= i;\n'
            '        int wrap_cnt = 0;\n',
            '        inl -= i;\n'
            '        wrap_cnt = 0;\n',
        ),
        # Outer scope: strip type from post-if-block declaration
        (
            '    }\n    int wrap_cnt = 0;',
            '    }\n    wrap_cnt = 0;',
        ),
    ])

    # --- crypto/evp/evp_lib.c ---
    # int ret = -1, size_t outl = 0, size_t blocksize = ... after an if-return
    apply_text('crypto/evp/evp_lib.c', [
        (
            '{\n'
            '    if (ctx == NULL || ctx->cipher == NULL'
            ' || ctx->cipher->prov == NULL)\n'
            '        return 0;\n'
            '\n'
            '    /*\n'
            '     * If the provided implementation has a ccipher function, we use it,\n'
            '     * and translate its return value like this: 0 => -1, 1 => outlen\n'
            '     *\n'
            '     * Otherwise, we call the cupdate function if in != NULL, or cfinal\n'
            '     * if in == NULL.  Regardless of which, we return what we got.\n'
            '     */\n'
            '    int ret = -1;\n'
            '    size_t outl = 0;\n'
            '    size_t blocksize = EVP_CIPHER_CTX_get_block_size(ctx);',
            '{\n'
            '    int ret;\n'
            '    size_t outl;\n'
            '    size_t blocksize;\n'
            '    if (ctx == NULL || ctx->cipher == NULL'
            ' || ctx->cipher->prov == NULL)\n'
            '        return 0;\n'
            '\n'
            '    /*\n'
            '     * If the provided implementation has a ccipher function, we use it,\n'
            '     * and translate its return value like this: 0 => -1, 1 => outlen\n'
            '     *\n'
            '     * Otherwise, we call the cupdate function if in != NULL, or cfinal\n'
            '     * if in == NULL.  Regardless of which, we return what we got.\n'
            '     */\n'
            '    ret = -1;\n'
            '    outl = 0;\n'
            '    blocksize = EVP_CIPHER_CTX_get_block_size(ctx);',
        ),
    ])

    # --- crypto/sha/sha512.c ---
    # uint8_t *cu = ... after memset statements
    apply_text('crypto/sha/sha512.c', [
        (
            '    size_t n = c->num;\n\n    p[n]',
            '    size_t n = c->num;\n    uint8_t *cu;\n\n    p[n]',
        ),
        (
            '    uint8_t *cu = p + sizeof(c->u) - 16;',
            '    cu = p + sizeof(c->u) - 16;',
        ),
    ])

    # --- crypto/x509/v3_purp.c ---
    # NOTE: In OpenSSL 4.1.0 the tmp_rfc3779_addr / tmp_rfc3779_asid
    # declarations were hoisted to the top of ossl_x509v3_cache_extensions()
    # upstream (inside #ifndef OPENSSL_NO_RFC3779), so the C89 hoist patch
    # that was needed for 4.0.0 no longer applies — re-adding the
    # declarations produced E2238 "Multiple declaration".  The C99 for-loop
    # declarations in this file are still handled by category 1.

    # --- providers/implementations/keymgmt/dsa_kmgmt.c ---
    apply_text('providers/implementations/keymgmt/dsa_kmgmt.c', [
        (
            'static void *dsa_newdata_ex(void *provctx,'
            ' const OSSL_PARAM params[])\n'
            '{\n'
            '    DSA *dsa = NULL;',
            'static void *dsa_newdata_ex(void *provctx,'
            ' const OSSL_PARAM params[])\n'
            '{\n'
            '    const OSSL_PARAM * p;\n'
            '    DSA *dsa = NULL;',
        ),
        (
            '    const OSSL_PARAM *p = NULL;',
            '    p = NULL;',
        ),
    ])

    # --- providers/implementations/keymgmt/ec_kmgmt.c ---
    apply_text('providers/implementations/keymgmt/ec_kmgmt.c', [
        (
            'static void *ec_newdata_ex(void *provctx,'
            ' const OSSL_PARAM params[])\n'
            '{\n'
            '    EC_KEY *eckey = NULL;',
            'static void *ec_newdata_ex(void *provctx,'
            ' const OSSL_PARAM params[])\n'
            '{\n'
            '    const OSSL_PARAM * p;\n'
            '    EC_KEY *eckey = NULL;',
        ),
        (
            '    const OSSL_PARAM *p = NULL;',
            '    p = NULL;',
        ),
    ])

    # --- ssl/ssl_ciph.c ---
    # const EVP_MD *md = EVP_MD_fetch(...) after ERR_set_mark()
    apply_text('ssl/ssl_ciph.c', [
        (
            '    EVP_SIGNATURE *sig = NULL;\n\n    ctx->disabled_enc_mask',
            '    EVP_SIGNATURE *sig = NULL;\n'
            '    const EVP_MD *md;\n\n    ctx->disabled_enc_mask',
        ),
        (
            '        const EVP_MD *md = EVP_MD_fetch(',
            '        md = EVP_MD_fetch(',
        ),
    ])

    # --- crypto/threads_win.c ---
    # C99 mid-block declaration introduced in OpenSSL 4.1.0 RCU-lock code:
    #   ossl_unused int r = CRYPTO_THREAD_write_lock(lock->rw_lock);
    # The value of r is never read (only the side effect of acquiring the
    # lock is wanted).  Classic bcc32 (C89) rejects declarations after
    # statements.  Cast to (void) so it becomes a plain statement.
    apply_text('crypto/threads_win.c', [
        (
            '    /* This cannot fail, avoid unused result warning */\n'
            '    ossl_unused int r = CRYPTO_THREAD_write_lock(lock->rw_lock);',
            '    /* This cannot fail, avoid unused result warning */\n'
            '    (void)CRYPTO_THREAD_write_lock(lock->rw_lock);',
        ),
    ])

    # --- crypto/pkcs7/pk7_doit.c ---
    # OpenSSL 4.1.0 added C99 mid-block declarations in two PKCS7 functions.
    # Hoist them to the function-level declaration block (C89) and keep the
    # original assignments at the use site.
    apply_text('crypto/pkcs7/pk7_doit.c', [
        # PKCS7_dataInit: hoist os_data / os_len to function top
        (
            '    const PKCS7_CTX *p7_ctx;\n'
            '    OSSL_LIB_CTX *libctx;\n'
            '    const char *propq;\n'
            '\n'
            '    if (p7 == NULL) {',
            '    const PKCS7_CTX *p7_ctx;\n'
            '    OSSL_LIB_CTX *libctx;\n'
            '    const char *propq;\n'
            '    const unsigned char *os_data;\n'
            '    size_t os_len;\n'
            '\n'
            '    if (p7 == NULL) {',
        ),
        # PKCS7_dataInit: strip the mid-block types (now assigned, not declared)
        (
            '                BIO_set_mem_eof_return(bio, 0);\n'
            '                const unsigned char *os_data = ASN1_STRING_get0_data(os);\n'
            '                size_t os_len = ASN1_STRING_get_length(os);',
            '                BIO_set_mem_eof_return(bio, 0);\n'
            '                os_data = ASN1_STRING_get0_data(os);\n'
            '                os_len = ASN1_STRING_get_length(os);',
        ),
        # PKCS7_signatureVerify: hoist sig_data / sig_len to function top
        (
            '    const PKCS7_CTX *ctx = ossl_pkcs7_get0_ctx(p7);\n'
            '    OSSL_LIB_CTX *libctx = ossl_pkcs7_ctx_get0_libctx(ctx);\n'
            '    const char *propq = ossl_pkcs7_ctx_get0_propq(ctx);\n'
            '\n'
            '    mdc_tmp = EVP_MD_CTX_new();',
            '    const PKCS7_CTX *ctx = ossl_pkcs7_get0_ctx(p7);\n'
            '    OSSL_LIB_CTX *libctx = ossl_pkcs7_ctx_get0_libctx(ctx);\n'
            '    const char *propq = ossl_pkcs7_ctx_get0_propq(ctx);\n'
            '    const unsigned char *sig_data;\n'
            '    size_t sig_len;\n'
            '\n'
            '    mdc_tmp = EVP_MD_CTX_new();',
        ),
        # PKCS7_signatureVerify: strip the mid-block types (now assigned, not declared)
        (
            '    const unsigned char *sig_data = ASN1_STRING_get0_data(os);\n'
            '    size_t sig_len = ASN1_STRING_get_length(os);\n'
            '    if (sig_len > INT_MAX) {',
            '    sig_data = ASN1_STRING_get0_data(os);\n'
            '    sig_len = ASN1_STRING_get_length(os);\n'
            '    if (sig_len > INT_MAX) {',
        ),
    ])

    # --- ssl/ssl_lib.c ---
    # SSL_get_peer_addr (new in OpenSSL 4.1.0) declares SSL_CONNECTION *sc
    # after the QUIC early-return, which C89 rejects (E2140).  Hoist the
    # declaration to the function top and keep the assignment in place.
    # The type is always available (statem.h), so the unconditional top
    # declaration is safe even when the DTLS path is compiled out.
    apply_text('ssl/ssl_lib.c', [
        (
            'int SSL_get_peer_addr(SSL *ssl, BIO_ADDR *peer_addr)\n'
            '{\n'
            '#ifndef OPENSSL_NO_QUIC\n'
            '    if (IS_QUIC(ssl))\n'
            '        return ossl_quic_get_peer_addr(ssl, peer_addr);\n'
            '#endif\n'
            '\n'
            '#if !defined(OPENSSL_NO_DTLS) && !defined(OPENSSL_NO_SOCK)\n'
            '    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);\n',
            'int SSL_get_peer_addr(SSL *ssl, BIO_ADDR *peer_addr)\n'
            '{\n'
            '    SSL_CONNECTION *sc;\n'
            '#ifndef OPENSSL_NO_QUIC\n'
            '    if (IS_QUIC(ssl))\n'
            '        return ossl_quic_get_peer_addr(ssl, peer_addr);\n'
            '#endif\n'
            '\n'
            '#if !defined(OPENSSL_NO_DTLS) && !defined(OPENSSL_NO_SOCK)\n'
            '    sc = SSL_CONNECTION_FROM_SSL(ssl);\n',
        ),
    ])

    # --- ssl/ssl_sess.c ---
    # SSL_CTX_add_session (new in OpenSSL 4.1.0) declares evicted_head after a
    # statement, which C89 rejects (E2140).  Hoist the declaration to the
    # function top and keep the NULL assignment in place.
    apply_text('ssl/ssl_sess.c', [
        (
            'int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)\n'
            '{\n'
            '    int ret = 0;\n'
            '    SSL_SESSION *s;\n',
            'int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)\n'
            '{\n'
            '    int ret = 0;\n'
            '    SSL_SESSION *s;\n'
            '    SSL_SESSION *evicted_head;\n',
        ),
        (
            '     * once the lock is released.\n'
            '     */\n'
            '    SSL_SESSION *evicted_head = NULL;\n',
            '     * once the lock is released.\n'
            '     */\n'
            '    evicted_head = NULL;\n',
        ),
    ])

    # --- ssl/t1_enc.c ---
    # tls1_PRF (OpenSSL 4.1.0) declares mdname and params after a statement
    # inside #ifdef OPENSSL_HAVE_TLS1PRF, which C89 rejects (E2140).  Hoist
    # both to the function top and keep the assignments in place.
    apply_text('ssl/t1_enc.c', [
        (
            '    const EVP_MD *md = ssl_prf_md(s);\n'
            '    EVP_KDF_CTX *kctx = NULL;\n',
            '    const char *mdname;\n'
            '    OSSL_PARAM params[9], *p;\n'
            '    const EVP_MD *md = ssl_prf_md(s);\n'
            '    EVP_KDF_CTX *kctx = NULL;\n',
        ),
        (
            '    const char *mdname = EVP_MD_get0_name(md);\n'
            '    OSSL_PARAM params[9], *p = params;\n',
            '    mdname = EVP_MD_get0_name(md);\n'
            '    p = params;\n',
        ),
    ])

    # --- ssl/statem/statem_lib.c ---
    # tls_common_finish_mac declares srvhellorandom_offs after statements,
    # which C89 rejects (E2140).  Hoist to the function top.
    apply_text('ssl/statem/statem_lib.c', [
        (
            '    size_t hdr_len = 0;\n',
            '    size_t hdr_len = 0;\n'
            '    size_t srvhellorandom_offs;\n',
        ),
        (
            '    const size_t srvhellorandom_offs = hdr_len + 2;\n',
            '    srvhellorandom_offs = hdr_len + 2;\n',
        ),
    ])

    # --- ssl/statem/extensions_srvr.c ---
    # tls_parse_ctos_status_request declares sctx after statements, which
    # C89 rejects (E2140).  Hoist to the function top.
    apply_text('ssl/statem/extensions_srvr.c', [
        (
            '    PACKET responder_id_list, exts;\n',
            '    SSL_CTX *sctx;\n'
            '    PACKET responder_id_list, exts;\n',
        ),
        (
            '    SSL_CTX *sctx = SSL_CONNECTION_GET_CTX(s);\n'
            '    if (sctx == NULL || sctx->ext.status_cb == NULL)\n',
            '    sctx = SSL_CONNECTION_GET_CTX(s);\n'
            '    if (sctx == NULL || sctx->ext.status_cb == NULL)\n',
        ),
    ])

    # --- ssl/quic/qlog.c ---
    # ossl_qlog_new_from_env declares int n after statements, which C89
    # rejects (E2140).  Hoist to the function top.  (The int n at the top of
    # the for-loop body is a legal C89 declaration.)
    apply_text('ssl/quic/qlog.c', [
        (
            '    size_t i, l, strl;\n',
            '    size_t i, l, strl;\n'
            '    int n;\n',
        ),
        (
            '    int n = snprintf(filename + l, strl - l, "_%s.sqlog",\n',
            '    n = snprintf(filename + l, strl - l, "_%s.sqlog",\n',
        ),
    ])


# ---------------------------------------------------------------------------
# Category 3 - Designated initializers
# ---------------------------------------------------------------------------

def patch_designated_initializers():
    print("\n=== Category 3: Designated initializers ===")

    # --- crypto/property/property.c ---
    apply_text('crypto/property/property.c', [
        (
            '    HT_CONFIG ht_conf = {\n'
            '        .ctx = ctx,\n'
            '        .ht_free_fn = query_free,\n'
            '        .ht_hash_fn = NULL,\n'
            '        .init_neighborhoods = 1,\n'
            '        .collision_check = 1,\n'
            '        .lockless_reads = 0,\n'
            '        .no_rcu = 1\n'
            '    };',
            '    HT_CONFIG ht_conf;\n'
            '    memset(&ht_conf, 0, sizeof(ht_conf));\n'
            '    ht_conf.ctx = ctx;\n'
            '    ht_conf.ht_free_fn = query_free;\n'
            '    ht_conf.ht_hash_fn = NULL;\n'
            '    ht_conf.init_neighborhoods = 1;\n'
            '    ht_conf.collision_check = 1;\n'
            '    ht_conf.lockless_reads = 0;\n'
            '    ht_conf.no_rcu = 1;',
        ),
    ])

    # --- crypto/x509/x509_lu.c ---
    apply_text('crypto/x509/x509_lu.c', [
        (
            '    HT_CONFIG htconf = {\n'
            '        .ht_free_fn = objs_ht_free,\n'
            '        .ht_hash_fn = obj_ht_hash,\n'
            '        .init_neighborhoods = X509_OBJS_HT_BUCKETS,\n'
            '        .no_rcu = 1,\n'
            '    };',
            '    HT_CONFIG htconf;\n'
            '    memset(&htconf, 0, sizeof(htconf));\n'
            '    htconf.ht_free_fn = objs_ht_free;\n'
            '    htconf.ht_hash_fn = obj_ht_hash;\n'
            '    htconf.init_neighborhoods = X509_OBJS_HT_BUCKETS;\n'
            '    htconf.no_rcu = 1;',
        ),
    ])

    # --- crypto/x509/x509_vpm.c ---
    # Positional init for X509_VERIFY_PARAM (19 fields).
    # OpenSSL 4.1.0 table has 7 entries (a "smime_encrypt" entry was added
    # relative to 4.0.0).  TAIL supplies the 11 trailing fields (policies,
    # hosts, validate_host, ips, validate_ip, rfc822s, validate_rfc822,
    # smtputf8s, validate_smtputf8, hostflags, peername) = 9 NULLs + 0 + NULL.
    TAIL = (', NULL, NULL, NULL, NULL, NULL, NULL, '
            'NULL, NULL, NULL, 0, NULL }')
    apply_text('crypto/x509/x509_vpm.c', [
        (
            'static const X509_VERIFY_PARAM default_table[] = {\n'
            '    {\n'
            '        .name = "code_sign", /* Code sign parameters */\n'
            '        .purpose = X509_PURPOSE_CODE_SIGN,\n'
            '        .trust = X509_TRUST_OBJECT_SIGN,\n'
            '        .depth = -1,\n'
            '        .auth_level = -1,\n'
            '    },\n'
            '    {\n'
            '        .name = "default", /* X509 default parameters */\n'
            '        .flags = X509_V_FLAG_TRUSTED_FIRST,\n'
            '        .depth = 100,\n'
            '        .auth_level = -1,\n'
            '    },\n'
            '    {\n'
            '        .name = "pkcs7", /* S/MIME sign parameters */\n'
            '        .purpose = X509_PURPOSE_SMIME_SIGN,\n'
            '        .trust = X509_TRUST_EMAIL,\n'
            '        .depth = -1,\n'
            '        .auth_level = -1,\n'
            '    },\n'
            '    {\n'
            '        .name = "smime_encrypt", /* S/MIME encryption parameters */\n'
            '        .purpose = X509_PURPOSE_SMIME_ENCRYPT,\n'
            '        .trust = X509_TRUST_EMAIL,\n'
            '        .depth = -1,\n'
            '        .auth_level = -1,\n'
            '    },\n'
            '    {\n'
            '        .name = "smime_sign", /* S/MIME signature parameters */\n'
            '        .purpose = X509_PURPOSE_SMIME_SIGN,\n'
            '        .trust = X509_TRUST_EMAIL,\n'
            '        .depth = -1,\n'
            '        .auth_level = -1,\n'
            '    },\n'
            '    {\n'
            '        .name = "ssl_client", /* SSL/TLS client parameters */\n'
            '        .purpose = X509_PURPOSE_SSL_CLIENT,\n'
            '        .trust = X509_TRUST_SSL_CLIENT,\n'
            '        .depth = -1,\n'
            '        .auth_level = -1,\n'
            '    },\n'
            '    {\n'
            '        .name = "ssl_server", /* SSL/TLS server parameters */\n'
            '        .purpose = X509_PURPOSE_SSL_SERVER,\n'
            '        .trust = X509_TRUST_SSL_SERVER,\n'
            '        .depth = -1,\n'
            '        .auth_level = -1,\n'
            '    }\n'
            '};',

            'static const X509_VERIFY_PARAM default_table[] = {\n'
            '    /* Code sign parameters */\n'
            '    { "code_sign",'
            ' 0, 0, 0, X509_PURPOSE_CODE_SIGN,'
            ' X509_TRUST_OBJECT_SIGN, -1, -1' + TAIL + ',\n'
            '    /* X509 default parameters */\n'
            '    { "default",'
            ' 0, 0, X509_V_FLAG_TRUSTED_FIRST,'
            ' 0, 0, 100, -1' + TAIL + ',\n'
            '    /* S/MIME sign parameters */\n'
            '    { "pkcs7",'
            ' 0, 0, 0, X509_PURPOSE_SMIME_SIGN,'
            ' X509_TRUST_EMAIL, -1, -1' + TAIL + ',\n'
            '    /* S/MIME encryption parameters */\n'
            '    { "smime_encrypt",'
            ' 0, 0, 0, X509_PURPOSE_SMIME_ENCRYPT,'
            ' X509_TRUST_EMAIL, -1, -1' + TAIL + ',\n'
            '    /* S/MIME signature parameters */\n'
            '    { "smime_sign",'
            ' 0, 0, 0, X509_PURPOSE_SMIME_SIGN,'
            ' X509_TRUST_EMAIL, -1, -1' + TAIL + ',\n'
            '    /* SSL/TLS client parameters */\n'
            '    { "ssl_client",'
            ' 0, 0, 0, X509_PURPOSE_SSL_CLIENT,'
            ' X509_TRUST_SSL_CLIENT, -1, -1' + TAIL + ',\n'
            '    /* SSL/TLS server parameters */\n'
            '    { "ssl_server",'
            ' 0, 0, 0, X509_PURPOSE_SSL_SERVER,'
            ' X509_TRUST_SSL_SERVER, -1, -1' + TAIL + '\n'
            '};',
        ),
    ])

    # --- providers/implementations/keymgmt/rsa_kmgmt.c ---
    # Two const arrays use C99 indexed initializers ([RSA_IMEXPORT_TYPE_x] = { }).
    # Classic bcc32 rejects them (E2188/E2141).  The enum is NONE=0, OTHER=1,
    # KEY=2, ALL=3, so the positional aggregate below (index 0 left zero) is
    # value-identical.
    for sym, pre in [('rsa_imexport_types', 'rsa'),
                     ('rsapss_imexport_types', 'rsapss')]:
        old = (
            'static const struct rsa_imexport_types_st\n'
            f'    {sym}[RSA_IMEXPORT_TYPE_COUNT]\n'
            '    = {\n'
            '          [RSA_IMEXPORT_TYPE_OTHER] = {\n'
            f'              {pre}_other_import_types_list,\n'
            f'              {pre}_other_import_types_decoder,\n'
            f'              {pre}_other_export_types_list,\n'
            '          },\n'
            '          [RSA_IMEXPORT_TYPE_KEY] = {\n'
            f'              {pre}_key_import_types_list,\n'
            f'              {pre}_key_import_types_decoder,\n'
            f'              {pre}_key_export_types_list,\n'
            '          },\n'
            '          [RSA_IMEXPORT_TYPE_ALL] = {\n'
            f'              {pre}_all_import_types_list,\n'
            f'              {pre}_all_import_types_decoder,\n'
            f'              {pre}_all_export_types_list,\n'
            '          },\n'
            '      };')
        new = (
            'static const struct rsa_imexport_types_st\n'
            f'    {sym}[RSA_IMEXPORT_TYPE_COUNT] = {{\n'
            '      { 0, NULL, 0 },\n'
            f'      {{ {pre}_other_import_types_list, '
            f'{pre}_other_import_types_decoder, {pre}_other_export_types_list }},\n'
            f'      {{ {pre}_key_import_types_list, '
            f'{pre}_key_import_types_decoder, {pre}_key_export_types_list }},\n'
            f'      {{ {pre}_all_import_types_list, '
            f'{pre}_all_import_types_decoder, {pre}_all_export_types_list }}\n'
            '    };')
        apply_text('providers/implementations/keymgmt/rsa_kmgmt.c', [(old, new)])


# ---------------------------------------------------------------------------
# Category 4 - qsort / bsearch callback casts
# ---------------------------------------------------------------------------

def patch_qsort_casts():
    print("\n=== Category 4: qsort/bsearch __cdecl casts ===")
    files = [
        'crypto/asn1/tasn_enc.c',
        'crypto/ex_data.c',
        'crypto/objects/o_names.c',
        'crypto/params_dup.c',
        'crypto/stack/stack.c',
        'providers/implementations/encode_decode/ml_common_codecs.c',
        'ssl/quic/quic_txpim.c',
        'ssl/s3_lib.c',
    ]
    for rel in files:
        try:
            content = read_file(rel)
        except FileNotFoundError:
            print(f"  [ERROR] not found: {rel}")
            stats.errors += 1
            continue

        new = fix_qsort_calls(content)
        if new != content:
            write_file(rel, new)
            print(f"  [fixed]     {rel}")
            stats.patched += 1
        else:
            print(f"  [skip]      {rel}")
            stats.skipped += 1


# ---------------------------------------------------------------------------
# Category 5 - signal() type mismatch
# ---------------------------------------------------------------------------

def patch_signal_casts():
    print("\n=== Category 5: signal() __cdecl casts ===")
    rel = 'crypto/ui/ui_openssl.c'
    patches = []

    GUARD_SIGNAL = ('\n#ifdef __BORLANDC__\n'
                    + CDECL_SIGNAL + '\n'
                    + '#endif\n')

    # pushsig: signal(SIGxxx, recsig) -> guarded cast
    for sig in ['SIGABRT', 'SIGFPE', 'SIGILL', 'SIGINT', 'SIGSEGV', 'SIGTERM']:
        patches.append((
            f'signal({sig}, recsig)',
            f'signal({sig},{GUARD_SIGNAL}recsig)',
        ))

    # Unix path: signal(i, recsig)
    patches.append((
        'signal(i, recsig)',
        f'signal(i,{GUARD_SIGNAL}recsig)',
    ))

    # popsig: signal(SIGxxx, savsig[SIGxxx])
    for sig in ['SIGABRT', 'SIGFPE', 'SIGILL', 'SIGINT', 'SIGSEGV', 'SIGTERM']:
        patches.append((
            f'signal({sig}, savsig[{sig}])',
            f'signal({sig},{GUARD_SIGNAL}savsig[{sig}])',
        ))

    # Unix popsig: signal(i, savsig[i])
    patches.append((
        'signal(i, savsig[i])',
        f'signal(i,{GUARD_SIGNAL}savsig[i])',
    ))

    apply_text(rel, patches)


# ---------------------------------------------------------------------------
# Category 6 - struct bignum_st (add bn_local.h include)
# ---------------------------------------------------------------------------

def add_include_if_missing(rel, include_line, after_text):
    """Add an #include line after *after_text* if not already present."""
    try:
        content = read_file(rel)
    except FileNotFoundError:
        print(f"  [ERROR] not found: {rel}")
        stats.errors += 1
        return

    if include_line in content:
        print(f"  [skip]      {rel}")
        stats.skipped += 1
        return

    if after_text not in content:
        print(f"  [skip]      {rel}")
        stats.skipped += 1
        return

    content = content.replace(after_text, after_text + '\n' + include_line, 1)
    write_file(rel, content)
    print(f"  [ 1 fix(es)] {rel}")
    stats.patched += 1


def patch_bignum_includes():
    print("\n=== Category 6: struct bignum_st includes ===")

    add_include_if_missing(
        'crypto/bn/bn_const.c',
        '#include "bn_local.h"',
        '#include "crypto/bn_dh.h"',
    )
    add_include_if_missing(
        'crypto/dh/dh_rfc5114.c',
        '#include "crypto/bn/bn_local.h"',
        '#include "crypto/bn_dh.h"',
    )
    add_include_if_missing(
        'crypto/ffc/ffc_dh.c',
        '#include "crypto/bn/bn_local.h"',
        '#include "crypto/bn_dh.h"',
    )
    add_include_if_missing(
        'crypto/rsa/rsa_sp800_56b_check.c',
        '#include "crypto/bn/bn_local.h"',
        '#include "rsa_local.h"',
    )
    add_include_if_missing(
        'crypto/srp/srp_lib.c',
        '#include "crypto/bn/bn_local.h"',
        '#include "crypto/bn_srp.h"',
    )


# ---------------------------------------------------------------------------
# Category 7 - OSSL_PARAM_construct array initializers
# ---------------------------------------------------------------------------

def patch_ossl_param_arrays():
    print("\n=== Category 7: OSSL_PARAM_construct array initializers ===")
    # ikev2kdf.c: three OSSL_PARAM arrays are initialized with
    # OSSL_PARAM_construct_*() function calls (C99).  Classic bcc32 rejects
    # non-constant array initializers (E2110 "Incompatible type conversion").
    # Convert each to a plain sized declaration plus runtime element
    # assignments (C89).  The two "md_name" sites are byte-identical, so all
    # occurrences are replaced.
    rel = 'providers/implementations/kdfs/ikev2kdf.c'
    try:
        content = read_file(rel)
    except FileNotFoundError:
        print(f"  [ERROR] not found: {rel}")
        stats.errors += 1
        return

    md_name_old = (
        '    OSSL_PARAM params[] = {\n'
        '        OSSL_PARAM_construct_utf8_string("digest", md_name, 0),\n'
        '        OSSL_PARAM_construct_end()\n'
        '    };')
    md_name_new = (
        '    OSSL_PARAM params[2];\n'
        '    params[0] = OSSL_PARAM_construct_utf8_string("digest", md_name, 0);\n'
        '    params[1] = OSSL_PARAM_construct_end();')

    evp_md_old = (
        '    OSSL_PARAM params[] = {\n'
        '        OSSL_PARAM_construct_utf8_string("digest", (char *)EVP_MD_name(evp_md), 0),\n'
        '        OSSL_PARAM_construct_end()\n'
        '    };')
    evp_md_new = (
        '    OSSL_PARAM params[2];\n'
        '    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)EVP_MD_name(evp_md), 0);\n'
        '    params[1] = OSSL_PARAM_construct_end();')

    n = 0
    if md_name_old in content:
        n += content.count(md_name_old)
        content = content.replace(md_name_old, md_name_new)
    if evp_md_old in content:
        n += content.count(evp_md_old)
        content = content.replace(evp_md_old, evp_md_new)

    if n:
        write_file(rel, content)
        print(f"  [{n:2d} fix(es)] {rel}")
        stats.patched += 1
    else:
        print(f"  [skip]      {rel}")
        stats.skipped += 1
def patch_funcptr_cdecl():
    print("\n=== Category 8: function pointer typedef __cdecl fix ===")

    # crypto/mem_clr.c: memset_t stores &memset (cdecl) but typedef is register
    apply_text('crypto/mem_clr.c', [
        (
            'typedef void *(*memset_t)(void *, int, size_t);',
            '#ifdef __BORLANDC__\n'
            'typedef void *(__cdecl *memset_t)(void *, int, size_t);\n'
            '#else\n'
            'typedef void *(*memset_t)(void *, int, size_t);\n'
            '#endif',
        ),
    ])


# ---------------------------------------------------------------------------
# Category 9 - Disable alloca for BCC32 (forces OPENSSL_malloc fallback)
# ---------------------------------------------------------------------------

ALLOCA_UNDEF_BLOCK = """\
/*
 * BCC32 _alloca compiles to ___alloca_helper which manipulates ESP and
 * probes guard pages - incompatible with Delphi linker stack layout when
 * statically linking.  Disable alloca so the code falls through to the
 * OPENSSL_malloc path which is properly NULL-checked.
 */
#if defined(__BORLANDC__)
# undef alloca
#endif
"""

ALLOCA_FILES = {
    'crypto/bn/bn_exp.c': '#include "rsaz_exp.h"',
}


def patch_alloca_undef():
    print("\n=== Category 9: disable alloca for BCC32 ===")

    for rel, anchor in ALLOCA_FILES.items():
        try:
            content = read_file(rel)
        except FileNotFoundError:
            print(f"  [ERROR] not found: {rel}")
            stats.errors += 1
            continue

        if '__BORLANDC__' in content and 'undef alloca' in content:
            print(f"  [skip]      {rel}")
            stats.skipped += 1
            continue

        if anchor not in content:
            print(f"  [ERROR] anchor not found in {rel}: {anchor}")
            stats.errors += 1
            continue

        content = content.replace(anchor, ALLOCA_UNDEF_BLOCK + '\n' + anchor, 1)
        write_file(rel, content)
        print(f"  [fixed]     {rel}")
        stats.patched += 1


# ---------------------------------------------------------------------------
# Category 10 — crypto/init.c: calling convention fix for BCC32 -pr
# ---------------------------------------------------------------------------
# BCC32 with -pr (register/fastcall) compiles all functions as __fastcall
# by default.  atexit() expects void (__cdecl *)(void), but OPENSSL_cleanup
# is __fastcall.  Fix: route BCC32 through the _onexit path (like MSVC)
# and mark the callback __cdecl so _onexit_t matches.

def patch_init_c_atexit():
    """Fix atexit calling convention for BCC32 -pr in crypto/init.c."""
    print("\n=== Category 10: crypto/init.c — atexit cdecl fix for BCC32 ===")
    rel = 'crypto/init.c'
    try:
        content = read_file(rel)
    except FileNotFoundError:
        print(f"  [ERROR] not found: {rel}")
        stats.errors += 1
        return

    if 'win32atexit_cdecl' in content:
        print(f"  [skip]      {rel}")
        stats.skipped += 1
        return

    # 1. Add __cdecl to win32atexit and include BCC32 in the _onexit path
    old_func = 'static int win32atexit(void)\n{'
    new_func = 'static int __cdecl win32atexit(void)\n{'
    if old_func not in content:
        # win32atexit was removed in OpenSSL 4.0.0 — patch not needed
        print(f"  [skip]      {rel} (win32atexit pattern not present in this version)")
        stats.skipped += 1
        return
    content = content.replace(old_func, new_func, 1)

    # 2. Include BCC32 in the _onexit path (remove !defined(__BORLANDC__))
    old_guard = '#if defined(_WIN32) && !defined(__BORLANDC__)'
    new_guard = '#if defined(_WIN32)'
    if old_guard not in content:
        print(f"  [ERROR] __BORLANDC__ guard not found in {rel}")
        stats.errors += 1
        return
    content = content.replace(old_guard, new_guard, 1)

    write_file(rel, content)
    print(f"  [fixed]     {rel}")
    stats.patched += 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_all_patches():
    """Run all patch categories. Idempotent."""
    patch_c99_for_loops()
    patch_mixed_declarations()
    patch_designated_initializers()
    patch_qsort_casts()
    patch_signal_casts()
    patch_bignum_includes()
    patch_ossl_param_arrays()
    patch_funcptr_cdecl()
    patch_alloca_undef()
    patch_init_c_atexit()


ORIG_SUFFIX = f'.orig_{OPENSSL_BRANCH}x'


def cmd_apply():
    """Apply C89 patches.

    For each known file:
      1. If .orig does not exist — save current file as .orig (one-time backup).
      2. If .bcc32 cache exists — copy it over the source (fast path).
      3. Otherwise — ensure source is in original state (from .orig), then patch.
    """
    backed_up = 0
    cached = 0
    need_patch = False

    for rel in PATCHED_FILES:
        src = fpath(rel)
        orig = src + ORIG_SUFFIX
        cache = src + CACHE_SUFFIX

        if not os.path.isfile(src):
            continue

        # One-time: save original as .orig
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

    if backed_up:
        print(f"\nCreated {backed_up} .orig backup(s) (one-time).")
    if cached:
        print(f"Restored {cached} file(s) from {CACHE_SUFFIX} cache.")

    if need_patch:
        uncached = len(PATCHED_FILES) - cached
        print(f"\nPatching {uncached} file(s) without cache...\n")
        run_all_patches()
    elif cached:
        print("All files served from cache — no patching needed.")

    # Apply this repair even when an older C89 cache supplied bio_print.c.
    apply_text('crypto/bio/bio_print.c', [
        ('va_copy(cp_args, args);', 'cp_args = args; /* BCC32 pointer va_list copy */'),
    ])


def cmd_restore():
    """Save patched files as .bcc32, restore originals from local .orig copies."""
    saved = 0
    restored = 0

    for rel in PATCHED_FILES:
        src = fpath(rel)
        orig = src + ORIG_SUFFIX
        cache = src + CACHE_SUFFIX

        if not os.path.isfile(src):
            continue

        # Save patched version to cache
        shutil.copy2(src, cache)
        saved += 1

        # Restore original from local .orig
        if os.path.isfile(orig):
            shutil.copy2(orig, src)
            restored += 1
        else:
            print(f"  [WARN] no .orig for {rel} — cannot restore")

    print(f"Saved {saved} patched file(s) as {CACHE_SUFFIX} cache.")
    print(f"Restored {restored} original(s) from {ORIG_SUFFIX}.")


def main():
    print("=" * 60)
    print("patch_c89.py: OpenSSL C89 Compatibility Patcher for bcc32")
    print("=" * 60)
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
    elif mode is None:
        # Legacy mode: patch in-place (idempotent)
        run_all_patches()
    else:
        print(f"Unknown option: {mode}")
        print("Usage: patch_c89.py [--apply | --restore]")
        sys.exit(1)

    stats.report()


if __name__ == '__main__':
    main()
