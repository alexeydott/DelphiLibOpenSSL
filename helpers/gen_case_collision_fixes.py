"""
gen_case_collision_fixes.py - Detect & fix Delphi case-insensitive symbol collisions

Scans MSVC COFF object files for symbol pairs that differ only by case,
which causes Delphi's linker to merge them (W1028 -> potential AV).

Modes:
  --scan     Full scan: report all case collisions found in OBJ files
  --verify   Quick check: exit 1 if uncovered collisions exist (for CI/build)
  --update   Regenerate openssl_fix_case_collisions.h with new entries

Usage:
  python helpers/gen_case_collision_fixes.py --scan
  python helpers/gen_case_collision_fixes.py --verify
  python helpers/gen_case_collision_fixes.py --update
"""

import subprocess
import os
import re
import sys
import shutil
import argparse
from collections import defaultdict

DUMPBIN = os.environ.get('DUMPBIN') or shutil.which('dumpbin') or r'D:\VisualStudio2019\VC\Tools\MSVC\14.29.30133\bin\Hostx86\x86\dumpbin.exe'
TDUMP = os.environ.get('TDUMP') or shutil.which('tdump') or r'D:\Embarcadero RAD Studio\23.0\bin\tdump.exe'

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER_PATH = os.path.join(BASE_DIR, 'helpers', 'openssl_fix_case_collisions.h')

# OBJ directories per compiler
OBJ_DIRS = {
    'msvc':   os.path.join(BASE_DIR, 'obj3', 'win32', 'vc'),
    'msvc64': os.path.join(BASE_DIR, 'obj3', 'win64', 'vc'),
    'bcc32c': os.path.join(BASE_DIR, 'obj3', 'win32', 'bcc32c'),
    'bcc32':  os.path.join(BASE_DIR, 'obj3', 'win32', 'bcc'),
}

# Symbols to ignore (metadata, sections, compiler internals)
IGNORE_PREFIXES = ('.', '@feat.', '$', '__real@', '__xmm@', '??_', '?', '__imp_')
IGNORE_EXACT = {'_fltused', '@comp.id', '@vol.md', '__isa_available',
                'OPENSSL_ia32cap_P', '_OPENSSL_ia32cap_P'}


def scan_coff_symbols(obj_dir, verbose=False):
    """Scan COFF OBJ files with dumpbin /SYMBOLS. Returns {name: [(obj, class, sect)]}."""
    symbols = defaultdict(list)
    obj_files = sorted(f for f in os.listdir(obj_dir) if f.upper().endswith('.OBJ'))
    total = len(obj_files)

    for i, fname in enumerate(obj_files):
        if verbose and (i + 1) % 100 == 0:
            print(f'  Scanning {i + 1}/{total}...', file=sys.stderr)
        obj_path = os.path.join(obj_dir, fname)
        try:
            result = subprocess.run(
                [DUMPBIN, '/SYMBOLS', obj_path],
                capture_output=True, text=True, timeout=30
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            m = re.match(
                r'\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+'
                r'(SECT\d+|UNDEF|ABS)\s+'
                r'notype\s*(?:\(\))?\s+'
                r'(External|Static)\s+\|\s+(.+)', line)
            if not m:
                continue
            sect, cls, name = m.group(1), m.group(2), m.group(3).strip()
            if any(name.startswith(p) for p in IGNORE_PREFIXES):
                continue
            if name in IGNORE_EXACT:
                continue
            symbols[name].append((fname, cls, sect))
    return symbols


def scan_omf_symbols(obj_dir, verbose=False):
    """Scan OMF OBJ files with tdump -oiPUBDEF. Returns {name: [(obj, class, sect)]}."""
    symbols = defaultdict(list)
    obj_files = sorted(f for f in os.listdir(obj_dir) if f.upper().endswith('.OBJ'))
    total = len(obj_files)

    for i, fname in enumerate(obj_files):
        if verbose and (i + 1) % 100 == 0:
            print(f'  Scanning {i + 1}/{total}...', file=sys.stderr)
        obj_path = os.path.join(obj_dir, fname)
        try:
            result = subprocess.run(
                [TDUMP, '-oiPUBDEF', obj_path],
                capture_output=True, text=True, timeout=30
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        for line in result.stdout.splitlines():
            # Format: "  @symbol_name  offset:... type:..."
            m = re.match(r'\s+([@_]?\w+)\s+offset:', line)
            if not m:
                continue
            name = m.group(1).strip()
            if any(name.startswith(p) for p in IGNORE_PREFIXES):
                continue
            symbols[name].append((fname, 'External', 'PUBDEF'))
    return symbols


def strip_decoration(name):
    """Strip COFF/OMF decoration to get bare C name."""
    # stdcall: _Name@N -> Name
    m = re.match(r'^_(.+)@\d+$', name)
    if m:
        return m.group(1)
    # cdecl: _name -> name
    if name.startswith('_'):
        return name[1:]
    # BCC32 register: @name -> name
    if name.startswith('@'):
        return name[1:]
    return name


def find_case_collisions(symbols):
    """Find symbol pairs that collide case-insensitively.

    Returns list of (bare_lower, [(bare_name, decorated_name, obj, storage_class)]).
    Only includes groups with 2+ distinct bare names (actual case difference).
    """
    # Group by case-insensitive bare name
    groups = defaultdict(list)
    for decorated, entries in symbols.items():
        bare = strip_decoration(decorated)
        for obj, cls, sect in entries:
            groups[bare.lower()].append((bare, decorated, obj, cls, sect))

    collisions = []
    for lower_key, entries in sorted(groups.items()):
        # Get distinct bare names (case-sensitive)
        distinct_names = sorted(set(e[0] for e in entries))
        if len(distinct_names) < 2:
            continue
        collisions.append((lower_key, entries))
    return collisions


def read_existing_header(header_path):
    """Read existing #define entries from the collision header."""
    defines = {}  # old_name -> new_name
    if not os.path.exists(header_path):
        return defines
    with open(header_path, 'r') as f:
        for line in f:
            m = re.match(r'^\s*#define\s+(\w+)\s+(\w+)\s*$', line)
            if m:
                old, new = m.group(1), m.group(2)
                if old.startswith('FIX_CASE_'):
                    continue
                defines[old] = new
    return defines


def determine_rename_target(entries):
    """Given collision entries, determine which symbol should be renamed.

    Strategy: rename the internal (lowercase or mixed-case internal) symbol
    by appending underscore. Keep the public API symbol unchanged.
    """
    distinct_names = sorted(set(e[0] for e in entries))
    if len(distinct_names) != 2:
        return None, None  # complex collision, needs manual review

    name_a, name_b = distinct_names

    # Heuristic: the one with more uppercase chars or starting with uppercase
    # is the public API symbol. The other is the internal function to rename.
    def score_public(name):
        """Higher score = more likely public API."""
        s = 0
        if name[0].isupper():
            s += 10
        s += sum(1 for c in name if c.isupper())
        # Public API symbols are often ALL_CAPS or PascalCase
        if name.isupper():
            s += 5
        return s

    score_a = score_public(name_a)
    score_b = score_public(name_b)

    if score_a > score_b:
        # name_a is public, rename name_b
        return name_b, name_b + '_'
    elif score_b > score_a:
        # name_b is public, rename name_a
        return name_a, name_a + '_'
    else:
        # Tie — rename the one that's more lowercase
        if name_a < name_b:
            return name_a, name_a + '_'
        else:
            return name_b, name_b + '_'


def check_cross_obj_extdefs(symbols, renamed_symbol):
    """Check if a renamed symbol has EXTDEF (UNDEF) references in other OBJs.
    If yes, a Pascal bridge declaration is needed after rebuild."""
    decorated = '_' + renamed_symbol  # COFF cdecl decoration
    if decorated in symbols:
        for obj, cls, sect in symbols[decorated]:
            if sect == 'UNDEF':
                return True
    # Also check renamed version (after header apply)
    decorated_new = '_' + renamed_symbol + '_'
    if decorated_new in symbols:
        for obj, cls, sect in symbols[decorated_new]:
            if sect == 'UNDEF':
                return True
    return False


def generate_header(defines, output_path):
    """Generate the collision header from a dict of old->new defines."""
    lines = []
    lines.append('/*')
    lines.append(' * openssl_fix_case_collisions.h - Resolve case-insensitive symbol collisions')
    lines.append(' *')
    lines.append(' * Delphi\'s linker resolves symbols case-insensitively. OpenSSL uses')
    lines.append(' * case-sensitive naming where internal functions (lowercase foo_bar)')
    lines.append(' * collide with public API wrappers (uppercase FOO_bar) when compared')
    lines.append(' * case-insensitively. This causes the linker to merge them, routing')
    lines.append(' * public API calls to internal stubs that crash with stack overflow / AV.')
    lines.append(' *')
    lines.append(' * This header renames the internal (lowercase) function in each')
    lines.append(' * colliding pair by appending an underscore suffix. Force-include')
    lines.append(' * via /FI ensures all translation units see the rename consistently.')
    lines.append(' *')
    lines.append(' * AUTO-GENERATED by helpers/gen_case_collision_fixes.py')
    lines.append(' * Manual edits will be overwritten on next --update run.')
    lines.append(' *')
    lines.append(' * Used by: build_openssl3_msvc_win32.bat (/FI)')
    lines.append(' *          build_openssl3_cbuilder_win32.bat (/FI)')
    lines.append(' *          build_openssl3_cbuilder_classic_win32.bat (/FI)')
    lines.append(' */')
    lines.append('')
    lines.append('#ifndef FIX_CASE_COLLISIONS_H')
    lines.append('#define FIX_CASE_COLLISIONS_H')
    lines.append('')

    # Group defines by category for readability
    categories = categorize_defines(defines)
    for cat_name, cat_defines in categories:
        lines.append(f'/* {cat_name} */')
        max_old = max(len(old) for old, _ in cat_defines) if cat_defines else 0
        for old, new in sorted(cat_defines):
            lines.append(f'#define {old:<{max_old}}  {new}')
        lines.append('')

    lines.append('#endif /* FIX_CASE_COLLISIONS_H */')
    lines.append('')

    with open(output_path, 'w', newline='\n') as f:
        f.write('\n'.join(lines))
    return len(defines)


def categorize_defines(defines):
    """Group defines into logical categories based on naming patterns."""
    cats = defaultdict(list)
    for old, new in defines.items():
        lo = old.lower()
        if 'provider' in lo or 'lib_ctx' in lo:
            cats['Provider internals'].append((old, new))
        elif lo.startswith('bio_') or lo == 'bio_wait':
            cats['BIO internals'].append((old, new))
        elif lo.startswith('ssl_'):
            cats['SSL internals'].append((old, new))
        elif lo.startswith('evp_'):
            cats['EVP internals'].append((old, new))
        elif 'cipher' in lo and 'evp' not in lo:
            cats['Cipher helpers'].append((old, new))
        elif lo.startswith('ossl_decoder') or lo.startswith('ossl_encoder'):
            cats['Encoder/Decoder internals'].append((old, new))
        elif lo.startswith('ossl_prov_ctx'):
            cats['Provider context helpers'].append((old, new))
        elif 'err' in lo:
            cats['Error subsystem'].append((old, new))
        elif any(lo.startswith(p) for p in ('dh_', 'dsa_', 'rsa_', 'ecdsa_')):
            cats['DH/DSA/RSA/ECDSA internals'].append((old, new))
        elif any(lo.startswith(p) for p in ('hmac_', 'siphash_', 'poly1305_')):
            cats['MAC/Hash internals'].append((old, new))
        elif lo.startswith('pkcs12_') or lo.startswith('rand_'):
            cats['PKCS12/RAND internals'].append((old, new))
        elif lo.startswith('bn_'):
            cats['BN internals'].append((old, new))
        elif lo.startswith('ossl_hpke') or lo.startswith('ossl_cmp'):
            cats['HPKE/CMP internals'].append((old, new))
        elif 'ecpkparameters' in lo.lower():
            cats['EC ASN.1'].append((old, new))
        elif 'ocsp' in lo.lower():
            cats['OCSP'].append((old, new))
        else:
            cats['Other'].append((old, new))

    # Return in a stable order
    order = [
        'Provider internals', 'Provider context helpers',
        'BIO internals', 'SSL internals', 'EVP internals',
        'Cipher helpers', 'Encoder/Decoder internals',
        'Error subsystem', 'DH/DSA/RSA/ECDSA internals',
        'MAC/Hash internals', 'PKCS12/RAND internals',
        'BN internals', 'EC ASN.1', 'HPKE/CMP internals',
        'OCSP', 'Other',
    ]
    result = []
    for cat in order:
        if cat in cats:
            result.append((cat, cats[cat]))
    # Any remaining categories
    for cat in sorted(cats.keys()):
        if cat not in order:
            result.append((cat, cats[cat]))
    return result


def generate_pascal_bridges(new_defines, needs_bridge):
    """Generate Pascal external declarations for new collision renames."""
    lines = []
    lines.append('// --- Case-collision renamed symbols (auto-generated) ---')
    for old, new in sorted(new_defines.items()):
        bridge_needed = old in needs_bridge
        decl = (
            f'procedure {new}; '
            f'{{$IFDEF C_COMPILER_BORLAND_32}}external;'
            f'{{$ELSE}}external name EXTERNAL_NAME_PREFIX + \'{new}\';'
            f'{{$ENDIF}}'
        )
        if bridge_needed:
            lines.append(decl + '  // cross-OBJ: bridge required')
        else:
            lines.append(decl)
    return '\n'.join(lines)


def cmd_scan(args):
    """Full scan: report all case collisions."""
    compiler = args.compiler or 'msvc'
    obj_dir = OBJ_DIRS.get(compiler)
    if not obj_dir or not os.path.isdir(obj_dir):
        print(f'ERROR: OBJ directory not found: {obj_dir}', file=sys.stderr)
        return 1

    fmt = 'coff' if compiler == 'msvc' else 'omf'
    print(f'Scanning {compiler} OBJs in {obj_dir} ({fmt} format)...')

    if fmt == 'coff':
        symbols = scan_coff_symbols(obj_dir, verbose=True)
    else:
        symbols = scan_omf_symbols(obj_dir, verbose=True)

    print(f'  Found {len(symbols)} unique symbols')

    collisions = find_case_collisions(symbols)
    existing = read_existing_header(HEADER_PATH)

    print(f'\n=== Case-Insensitive Collisions: {len(collisions)} ===\n')
    new_count = 0
    for lower_key, entries in collisions:
        distinct = sorted(set(e[0] for e in entries))
        rename_target, rename_to = determine_rename_target(entries)

        covered = rename_target in existing if rename_target else False
        status = 'COVERED' if covered else 'NEW'
        if not covered:
            new_count += 1

        print(f'  [{status}] {lower_key}')
        for bare in distinct:
            # Find OBJs and storage classes for this bare name
            objs_ext = set()
            objs_stat = set()
            for b, d, obj, cls, sect in entries:
                if b == bare:
                    if cls == 'External' and sect != 'UNDEF':
                        objs_ext.add(obj)
                    elif cls == 'Static':
                        objs_stat.add(obj)
            info_parts = []
            if objs_ext:
                info_parts.append(f'External in {len(objs_ext)} OBJ(s)')
            if objs_stat:
                info_parts.append(f'Static in {len(objs_stat)} OBJ(s)')
            print(f'    {bare:40s} {", ".join(info_parts)}')

        if rename_target and not covered:
            has_extdef = check_cross_obj_extdefs(symbols, rename_target)
            bridge = ' [NEEDS PASCAL BRIDGE]' if has_extdef else ''
            print(f'    -> Rename: {rename_target} -> {rename_to}{bridge}')
        print()

    print(f'Summary: {len(collisions)} collisions, {len(collisions) - new_count} covered, {new_count} new')
    return 0


def cmd_verify(args):
    """Quick verify: exit 1 if uncovered collisions exist."""
    compiler = args.compiler or 'msvc'
    obj_dir = OBJ_DIRS.get(compiler)
    if not obj_dir or not os.path.isdir(obj_dir):
        print(f'ERROR: OBJ directory not found: {obj_dir}', file=sys.stderr)
        return 1

    fmt = 'coff' if compiler == 'msvc' else 'omf'
    if fmt == 'coff':
        symbols = scan_coff_symbols(obj_dir)
    else:
        symbols = scan_omf_symbols(obj_dir)

    collisions = find_case_collisions(symbols)
    existing = read_existing_header(HEADER_PATH)

    uncovered = []
    for lower_key, entries in collisions:
        rename_target, rename_to = determine_rename_target(entries)
        if rename_target and rename_target not in existing:
            distinct = sorted(set(e[0] for e in entries))
            uncovered.append((lower_key, distinct, rename_target, rename_to))

    if uncovered:
        print(f'FAIL: {len(uncovered)} uncovered case collision(s):')
        for lower_key, names, target, to in uncovered:
            print(f'  {" vs ".join(names)} -> rename {target} to {to}')
        print(f'\nRun with --update to fix, then rebuild.')
        return 1
    else:
        print(f'OK: All {len(collisions)} case collision(s) are covered by the header.')
        return 0


def cmd_update(args):
    """Update the collision header with any new entries."""
    compiler = args.compiler or 'msvc'
    obj_dir = OBJ_DIRS.get(compiler)
    if not obj_dir or not os.path.isdir(obj_dir):
        print(f'ERROR: OBJ directory not found: {obj_dir}', file=sys.stderr)
        return 1

    fmt = 'coff' if compiler == 'msvc' else 'omf'
    print(f'Scanning {compiler} OBJs...')

    if fmt == 'coff':
        symbols = scan_coff_symbols(obj_dir, verbose=True)
    else:
        symbols = scan_omf_symbols(obj_dir, verbose=True)

    collisions = find_case_collisions(symbols)
    existing = read_existing_header(HEADER_PATH)

    # Merge: keep existing + add new
    merged = dict(existing)
    new_entries = {}
    needs_bridge = set()

    for lower_key, entries in collisions:
        rename_target, rename_to = determine_rename_target(entries)
        if rename_target and rename_target not in merged:
            merged[rename_target] = rename_to
            new_entries[rename_target] = rename_to
            if check_cross_obj_extdefs(symbols, rename_target):
                needs_bridge.add(rename_target)

    if not new_entries:
        print(f'Header is up-to-date. {len(existing)} entries, no changes needed.')
        return 0

    # Generate updated header
    count = generate_header(merged, HEADER_PATH)
    print(f'Updated {HEADER_PATH}:')
    print(f'  {len(existing)} existing + {len(new_entries)} new = {count} total entries')

    if new_entries:
        print(f'\nNew entries added:')
        for old, new in sorted(new_entries.items()):
            bridge = ' [NEEDS PASCAL BRIDGE]' if old in needs_bridge else ''
            print(f'  #define {old} {new}{bridge}')

    if needs_bridge:
        print(f'\n--- Pascal bridge declarations needed ---')
        print(generate_pascal_bridges(new_entries, needs_bridge))

    print(f'\nIMPORTANT: Rebuild ALL compiler targets after header update!')
    print(f'  1. build_openssl3_msvc_win32.bat')
    print(f'  2. build_openssl3_cbuilder_win32.bat')
    print(f'  3. build_openssl3_cbuilder_classic_win32.bat')
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Detect & fix Delphi case-insensitive symbol collisions')
    parser.add_argument('--compiler', choices=['msvc', 'bcc32c', 'bcc32'],
                        default='msvc', help='Compiler target to scan (default: msvc)')

    sub = parser.add_subparsers(dest='command')
    sub.add_parser('--scan', help='Full scan and report')
    sub.add_parser('--verify', help='Verify header coverage (exit 1 if gaps)')
    sub.add_parser('--update', help='Update header with new entries')

    # Support both subcommand and flag style
    args, remaining = parser.parse_known_args()

    if '--scan' in sys.argv:
        args.command = '--scan'
    elif '--verify' in sys.argv:
        args.command = '--verify'
    elif '--update' in sys.argv:
        args.command = '--update'

    if not args.command:
        args.command = '--scan'

    dispatch = {
        '--scan': cmd_scan,
        '--verify': cmd_verify,
        '--update': cmd_update,
    }
    sys.exit(dispatch[args.command](args))


if __name__ == '__main__':
    main()
