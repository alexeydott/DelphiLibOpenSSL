#!/usr/bin/env python3
"""
patch_makefile_borland.py
Patches the OpenSSL-generated Makefile to be compatible with Embarcadero
(Borland) make instead of Microsoft nmake.

Conversions:
  1. @<< ... <<  →  @&&| ... |    (inline response files)
  2. /$(MAKEFLAGS)  →  removed     (Borland auto-propagates)
  3. $(MAKE) depend  →  no-op      (depend target is empty; sub-make breaks MAKEFLAGS)
  4. !IF/!ELSE/!ENDIF  →  !if/!else/!endif  (conditional directives)
  5. -O1 → -Od for ICE-triggering files  (bcc32 ICE workaround)
  6. TLIB: add + prefix before .obj files in AR response blocks
  7. CC=bcc32c → CC=cmd /c bcc32c  (workaround for spaces in executable path)

Usage:
  python helpers/patch_makefile_borland.py [path/to/makefile]

Default path: c_src/openssl/makefile (relative to project root).
Idempotent — skips if already patched.
"""

import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..')
_OPENSSL_SRC = os.environ.get('OPENSSL_SRC') or os.path.join(PROJECT_ROOT, 'c_src', 'openssl')
DEFAULT_MAKEFILE = os.path.join(_OPENSSL_SRC, 'makefile')

MARKER = '# [patched by patch_makefile_borland.py]'


def patch(path):
    with open(path, 'r') as f:
        content = f.read()

    if MARKER in content:
        print(f'Makefile already patched — nothing to do.')
        return 0

    original = content
    fixes = 0

    # 1. Inline response files:  @<<  →  @&&|  and  ^<<$  →  |
    #    nmake:   $(AR) ... @<<\n obj1 &\n obj2\n <<
    #    bmake:   $(AR) ... @&&|\n obj1 &\n obj2\n |
    count_start = content.count('@<<')
    content = content.replace('@<<', '@&&|')
    # Standalone << as line terminator → |
    content = re.sub(r'^<<$', '|', content, flags=re.MULTILINE)
    fixes += count_start
    if count_start:
        print(f'  [{count_start}] Inline response files: @<< → @&&|')

    # 2. Submake flag prefix:  /$(MAKEFLAGS)  →  remove entirely
    #    Borland make auto-propagates MAKEFLAGS to sub-makes.
    #    Its MAKEFLAGS already contains dash-prefixed flags (e.g. "K -N -l -o"),
    #    so "$(MAKE) -$(MAKEFLAGS) target" would produce broken double-dashed
    #    flags and the -o flag would swallow the target as its argument.
    count_flags = content.count('/$(MAKEFLAGS)')
    content = content.replace(' /$(MAKEFLAGS)', '')
    content = content.replace(' -$(MAKEFLAGS)', '')  # in case of re-run
    fixes += count_flags
    if count_flags:
        print(f'  [{count_flags}] Submake flags: removed /$(MAKEFLAGS) (auto-propagated)')

    # 3. Sub-make depend calls:  $(MAKE) depend  →  @ @rem (no-op)
    #    The depend target is a no-op (@ @rem), but invoking $(MAKE) depend
    #    spawns a sub-make that inherits MAKEFLAGS from the environment.
    #    Borland make's MAKEFLAGS (e.g. "K -N -l -o") contains -o which
    #    consumes "depend" as its filename arg → "RAD does not exist" error.
    count_depend = len(re.findall(r'^\t\$\(MAKE\)\s+depend\s*$', content, re.MULTILINE))
    content = re.sub(r'^\t\$\(MAKE\)\s+depend\s*$', '\t@ @rem depend (no-op)', content, flags=re.MULTILINE)
    fixes += count_depend
    if count_depend:
        print(f'  [{count_depend}] Sub-make depend: $(MAKE) depend → @ @rem (no-op)')

    # 4. Conditional directives: !IF → !if, !ELSE → !else, !ENDIF → !endif
    for upper, lower in [('!IF ', '!if '), ('!ELSE', '!else'), ('!ENDIF', '!endif')]:
        c = content.count(upper)
        if c:
            content = content.replace(upper, lower)
            fixes += c
            print(f'  [{c}] Conditional: {upper.strip()} → {lower.strip()}')

    # 5. Reduce optimization for files that trigger ICE (internal compiler error).
    #    bcc32 classic crashes on certain complex code with -O1/-O2; downgrade to -Od.
    #    Only applies to bcc32 classic — Clang-based compilers (bcc32c, bcc64) don't
    #    have this ICE (C1870) and their wrappers handle -Od inconsistently:
    #    bcc32c accepts -Od but bcc64 passes it raw to Clang which rejects it.
    is_clang = bool(re.search(r'^CC="?(bcc32c|bcc64)"?$', content, re.MULTILINE))
    count_ice = 0
    if not is_clang:
        opt_flag = '-Od'
        ice_files = [
            'hashtable.c',  # C1870 at line 454 with -O1
        ]
        for fname in ice_files:
            # Match the compile line: $(CC) $(LIB_CFLAGS) ... "...hashtable.c"
            # Insert optimization override right after $(LIB_CFLAGS)
            pattern = r'(\$\(LIB_CFLAGS\))(.*"[^"]*' + re.escape(fname) + r'")'
            matches = re.findall(pattern, content)
            if matches:
                content = re.sub(pattern, r'$(LIB_CFLAGS) ' + opt_flag + r'\2', content)
                count_ice += len(matches)
        fixes += count_ice
        if count_ice:
            print(f'  [{count_ice}] ICE workaround: {opt_flag} for {len(ice_files)} file(s)')
    else:
        print('  [skip] ICE workaround not needed for Clang-based compiler')

    # 6. TLIB response files: add '+' prefix before each .obj file.
    #    Borland TLIB requires '+' before each module name to mean "add".
    #    Without it, TLIB tries to read the name as a library and fails
    #    with "Bad header in input LIB".
    #    NOTE: Borland make's inline response file numbering (MAKE0001, MAKE0002, ...)
    #    is unreliable for the 3rd+ block. The build script must invoke make separately
    #    for each library target to avoid this bug.
    count_tlib = 0
    lines = content.split('\n')
    in_ar_block = False
    for i, line in enumerate(lines):
        if '$(AR)' in line and '@&&|' in line:
            in_ar_block = True
            continue
        if in_ar_block:
            stripped = line.strip()
            if stripped == '|' or stripped == '':
                in_ar_block = False
                continue
            # Object file line: starts with path\to\file.obj [&]
            if re.match(r'^(\s*)(\S+\.obj)', line):
                lines[i] = re.sub(r'^(\s*)(\S+\.obj)', r'\1+\2', line)
                count_tlib += 1
    content = '\n'.join(lines)
    fixes += count_tlib
    if count_tlib:
        print(f'  [{count_tlib}] TLIB response files: added + prefix for object files')

    # 7. Tool path-with-spaces workaround for Borland make.
    #    Borland make resolves tool executables to their full filesystem paths
    #    and passes them UNQUOTED to cmd.exe. If the path contains spaces
    #    (e.g. "D:\Embarcadero RAD Studio\23.0\bin\bcc32c.exe"), the command
    #    line breaks. Wrapping with "cmd /c" lets cmd.exe re-resolve the
    #    short name via PATH, avoiding the unquoted expansion entirely.
    #    Affects: CC (compiler), AR (tlib), LD (ilink32), RC (brcc32).
    tool_fixes = 0
    tool_patterns = [
        (r'^CC="(bcc32c?|bcc64)"$',   'CC'),
        (r'^AR="(tlib(?:64)?)"$',    'AR'),
        (r'^LD="(ilink(?:32|64))"$',  'LD'),
        (r'^RC="(brcc32)"$',          'RC'),
    ]
    for pattern, var in tool_patterns:
        m = re.search(pattern, content, re.MULTILINE)
        if m:
            tool_name = m.group(1)
            old_val = m.group(0)
            new_val = f'{var}=cmd /c {tool_name}'
            content = content.replace(old_val, new_val, 1)
            tool_fixes += 1
    if tool_fixes:
        fixes += tool_fixes
        print(f'  [{tool_fixes}] Tool path fix: wrapped {tool_fixes} tool(s) with cmd /c')

    # 8. Skip TLIB: replace AR with a no-op.
    #    Borland make's inline response file mechanism (MAKE000N.@@@) is unreliable:
    #    MAKE0002+ files get corrupted, causing "Bad header in input LIB" errors.
    #    Since Delphi links individual .obj files (not .lib archives), we skip
    #    library creation entirely. The build script collects .obj files directly.
    #    We replace AR with "echo" so make still processes the target dependencies
    #    (compiling all .obj files) but the tlib invocation becomes a no-op.
    ar_pattern = re.compile(r'^AR=.*$', re.MULTILINE)
    m_ar = ar_pattern.search(content)
    if m_ar:
        old_ar = m_ar.group(0)
        new_ar = 'AR=echo'
        content = content.replace(old_ar, new_ar, 1)
        fixes += 1
        print(f'  [1] TLIB skip: {old_ar} → {new_ar} (Delphi links .obj directly)')

    if fixes == 0:
        print('No nmake-specific patterns found — nothing to patch.')
        return 0

    # Add marker at top
    content = MARKER + '\n' + content

    with open(path, 'w') as f:
        f.write(content)

    print(f'Patched {fixes} nmake-specific patterns for Borland make compatibility.')
    return fixes


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MAKEFILE
    if not os.path.isfile(path):
        print(f'ERROR: Makefile not found: {path}')
        sys.exit(1)
    patch(path)


if __name__ == '__main__':
    main()
