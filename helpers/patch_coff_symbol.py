#!/usr/bin/env python3
"""
patch_coff_symbol.py - Demote symbols from GLOBAL to LOCAL in Win64 .OBJ files.

Supports both COFF (MSVC) and ELF (BCC64/Clang) object file formats.

The dcc64 Delphi linker emits W1028 "Bad global symbol definition" when an
OBJ defines a symbol as GLOBAL that conflicts with a Pascal declaration.
Changing the binding from GLOBAL to LOCAL makes the symbol file-local,
resolving the conflict.  The Pascal declaration then serves as the cross-OBJ
bridge.

Usage:
    python helpers/patch_coff_symbol.py --scan <dir_or_file> <symbol>
    python helpers/patch_coff_symbol.py --demote <obj_file> <symbol> [--dry-run]
    python helpers/patch_coff_symbol.py --demote-comdat-dups <dir3> <dir4> [--dry-run]
"""

import os
import sys
import struct
import argparse
import shutil


# ===== Format detection =====

ELF_MAGIC = b'\x7fELF'
COFF_AMD64 = 0x8664


def detect_format(data):
    """Return 'elf', 'coff', or None."""
    if len(data) >= 4 and data[:4] == ELF_MAGIC:
        return 'elf'
    if len(data) >= 2:
        machine = struct.unpack_from('<H', data, 0)[0]
        if machine == COFF_AMD64:
            return 'coff'
    return None


# ===== ELF helpers =====

# Elf64_Sym (24 bytes): st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
ELF64_SYM_SIZE = 24

STB_LOCAL  = 0
STB_GLOBAL = 1
STB_WEAK   = 2

STT_NOTYPE  = 0
STT_OBJECT  = 1
STT_FUNC    = 2
STT_SECTION = 3

SHN_UNDEF = 0

# ELF section header (Elf64_Shdr): 64 bytes
ELF64_SHDR_SIZE = 64
SHT_SYMTAB = 2
SHT_STRTAB = 3


def elf_binding_name(b):
    return {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK'}.get(b, f'bind={b}')

def elf_type_name(t):
    return {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE'}.get(t, f'type={t}')


def parse_elf_sections(data):
    """Parse ELF64 section headers, return list of dicts."""
    e_shoff    = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum    = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx = struct.unpack_from('<H', data, 62)[0]

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from('<II', data, off)
        sh_flags = struct.unpack_from('<Q', data, off + 8)[0]
        sh_addr  = struct.unpack_from('<Q', data, off + 16)[0]
        sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
        sh_size  = struct.unpack_from('<Q', data, off + 32)[0]
        sh_link  = struct.unpack_from('<I', data, off + 40)[0]
        sh_info  = struct.unpack_from('<I', data, off + 44)[0]
        sh_addralign = struct.unpack_from('<Q', data, off + 48)[0]
        sh_entsize   = struct.unpack_from('<Q', data, off + 56)[0]
        sections.append({
            'index': i, 'sh_name': sh_name, 'sh_type': sh_type,
            'sh_flags': sh_flags, 'sh_offset': sh_offset, 'sh_size': sh_size,
            'sh_link': sh_link, 'sh_info': sh_info, 'sh_entsize': sh_entsize,
            'header_offset': off,
        })
    return sections


def elf_get_string(data, strtab_offset, name_idx):
    """Read null-terminated string from string table."""
    start = strtab_offset + name_idx
    end = data.index(b'\x00', start)
    return data[start:end].decode('ascii', errors='replace')


def elf_iter_symbols(data, sections):
    """Yield (sym_index, name, st_info, st_other, st_shndx, st_value, st_size,
              binding, sym_type, symtab_section_index, info_byte_offset)."""
    for sec in sections:
        if sec['sh_type'] != SHT_SYMTAB:
            continue
        strtab_sec = sections[sec['sh_link']]
        strtab_off = strtab_sec['sh_offset']
        nsyms = sec['sh_size'] // ELF64_SYM_SIZE

        for i in range(nsyms):
            sym_off = sec['sh_offset'] + i * ELF64_SYM_SIZE
            st_name  = struct.unpack_from('<I', data, sym_off)[0]
            st_info  = data[sym_off + 4]
            st_other = data[sym_off + 5]
            st_shndx = struct.unpack_from('<H', data, sym_off + 6)[0]
            st_value = struct.unpack_from('<Q', data, sym_off + 8)[0]
            st_size  = struct.unpack_from('<Q', data, sym_off + 16)[0]

            name = elf_get_string(data, strtab_off, st_name)
            binding  = st_info >> 4
            sym_type = st_info & 0xf

            yield (i, name, st_info, st_other, st_shndx, st_value, st_size,
                   binding, sym_type, sec['index'], sym_off + 4)


def elf_scan_file(filepath, symbol):
    """Scan an ELF OBJ for symbol. Returns list of match dicts."""
    with open(filepath, 'rb') as f:
        data = f.read()
    if detect_format(data) != 'elf':
        return []

    sections = parse_elf_sections(data)
    matches = []
    for (idx, name, st_info, st_other, st_shndx, st_value, st_size,
         binding, sym_type, symtab_idx, info_offset) in elf_iter_symbols(data, sections):
        if name == symbol:
            matches.append({
                'file': filepath, 'index': idx, 'name': name,
                'binding': binding, 'sym_type': sym_type,
                'shndx': st_shndx, 'value': st_value, 'size': st_size,
                'info_offset': info_offset, 'st_info': st_info,
                'format': 'elf',
            })
    return matches


def elf_demote(obj_path, symbol, dry_run=False):
    """Demote ELF symbol from GLOBAL to LOCAL."""
    with open(obj_path, 'rb') as f:
        data = bytearray(f.read())

    sections = parse_elf_sections(data)
    target = None
    for (idx, name, st_info, st_other, st_shndx, st_value, st_size,
         binding, sym_type, symtab_idx, info_offset) in elf_iter_symbols(data, sections):
        if name == symbol:
            target = {
                'index': idx, 'name': name, 'binding': binding,
                'sym_type': sym_type, 'shndx': st_shndx,
                'value': st_value, 'size': st_size,
                'info_offset': info_offset, 'st_info': st_info,
            }
            break

    if target is None:
        print(f"Error: symbol '{symbol}' not found in '{os.path.basename(obj_path)}'.",
              file=sys.stderr)
        return 1

    if target['binding'] != STB_GLOBAL:
        print(f"  Symbol '{symbol}' binding is already "
              f"{elf_binding_name(target['binding'])}.  Nothing to do.")
        return 0

    if target['shndx'] == SHN_UNDEF:
        print(f"  Refusing to demote '{symbol}': it is UNDEF (external reference).")
        return 1

    new_info = (STB_LOCAL << 4) | target['sym_type']

    print(f"  {os.path.basename(obj_path)}:  sym[{target['index']}] '{symbol}'")
    print(f"    shndx={target['shndx']}  value=0x{target['value']:016X}  "
          f"size={target['size']}  type={elf_type_name(target['sym_type'])}")
    print(f"    binding: {elf_binding_name(STB_GLOBAL)} -> {elf_binding_name(STB_LOCAL)}")
    print(f"    st_info: 0x{target['st_info']:02X} -> 0x{new_info:02X}")

    if dry_run:
        print("  [DRY RUN] No changes written.")
        return 0

    backup_path = obj_path + '.bak'
    if not os.path.exists(backup_path):
        shutil.copy2(obj_path, backup_path)
        print(f"  Backup: {os.path.basename(backup_path)}")

    data[target['info_offset']] = new_info
    with open(obj_path, 'wb') as f:
        f.write(data)

    print("  Patched successfully.")
    return 0


# ===== COFF helpers =====

COFF_HEADER_SIZE = 20
COFF_SYMTAB_ENTRY_SIZE = 18
IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC   = 3


def coff_storage_name(cls):
    return {0: 'NULL', 2: 'EXTERNAL', 3: 'STATIC', 5: 'EXTERNAL_DEF',
            103: 'FILE', 104: 'SECTION'}.get(cls, f'class={cls}')


def coff_parse_header(data):
    machine, nsections, timestamp, symtab_ptr, nsymbols, opthdr_sz, chars = \
        struct.unpack_from('<HHIIIHH', data, 0)
    return {'machine': machine, 'nsections': nsections, 'symtab_ptr': symtab_ptr,
            'nsymbols': nsymbols}


def coff_decode_name(name_bytes, data, strtab_offset):
    if name_bytes[:4] == b'\x00\x00\x00\x00':
        str_off = struct.unpack_from('<I', name_bytes, 4)[0]
        abs_off = strtab_offset + str_off
        end = data.index(b'\x00', abs_off)
        return data[abs_off:end].decode('ascii', errors='replace')
    return name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')


def coff_iter_symbols(data, hdr):
    symtab_ptr = hdr['symtab_ptr']
    nsymbols   = hdr['nsymbols']
    strtab_off = symtab_ptr + nsymbols * COFF_SYMTAB_ENTRY_SIZE
    i = 0
    while i < nsymbols:
        off = symtab_ptr + i * COFF_SYMTAB_ENTRY_SIZE
        name_bytes = data[off:off + 8]
        value   = struct.unpack_from('<I', data, off + 8)[0]
        section = struct.unpack_from('<h', data, off + 12)[0]
        stype   = struct.unpack_from('<H', data, off + 14)[0]
        storage = data[off + 16]
        naux    = data[off + 17]
        name = coff_decode_name(name_bytes, data, strtab_off)
        yield (i, name, value, section, stype, storage, naux)
        i += 1 + naux


def coff_scan_file(filepath, symbol):
    with open(filepath, 'rb') as f:
        data = f.read()
    if detect_format(data) != 'coff':
        return []
    hdr = coff_parse_header(data)
    matches = []
    for idx, name, value, section, stype, storage, naux in coff_iter_symbols(data, hdr):
        if name == symbol:
            matches.append({
                'file': filepath, 'index': idx, 'name': name,
                'value': value, 'section': section, 'type': stype,
                'storage': storage, 'format': 'coff',
            })
    return matches


def coff_demote(obj_path, symbol, dry_run=False):
    with open(obj_path, 'rb') as f:
        data = bytearray(f.read())
    hdr = coff_parse_header(data)
    target = None
    for idx, name, value, section, stype, storage, naux in coff_iter_symbols(data, hdr):
        if name == symbol:
            target = {'index': idx, 'value': value, 'section': section,
                      'storage': storage}
            break
    if target is None:
        print(f"Error: symbol '{symbol}' not found.", file=sys.stderr)
        return 1
    if target['storage'] != IMAGE_SYM_CLASS_EXTERNAL:
        print(f"  Already {coff_storage_name(target['storage'])}. Nothing to do.")
        return 0
    if target['section'] <= 0:
        print(f"  Refusing to demote '{symbol}': not defined (section={target['section']}).")
        return 1

    storage_offset = hdr['symtab_ptr'] + target['index'] * COFF_SYMTAB_ENTRY_SIZE + 16
    print(f"  {os.path.basename(obj_path)}:  sym[{target['index']}] '{symbol}'")
    print(f"    storage: EXTERNAL(2) -> STATIC(3)")
    if dry_run:
        print("  [DRY RUN] No changes written.")
        return 0
    backup_path = obj_path + '.bak'
    if not os.path.exists(backup_path):
        shutil.copy2(obj_path, backup_path)
        print(f"  Backup: {os.path.basename(backup_path)}")
    data[storage_offset] = IMAGE_SYM_CLASS_STATIC
    with open(obj_path, 'wb') as f:
        f.write(data)
    print("  Patched successfully.")
    return 0


# ===== Unified commands =====

def scan_file(filepath, symbol):
    """Scan a single OBJ (auto-detect format) for symbol."""
    with open(filepath, 'rb') as f:
        magic = f.read(4)
    fmt = detect_format(magic + b'\x00' * 16)
    if fmt == 'elf':
        return elf_scan_file(filepath, symbol)
    elif fmt == 'coff':
        return coff_scan_file(filepath, symbol)
    return []


def cmd_scan(target, symbol):
    if os.path.isfile(target):
        files = [target]
    elif os.path.isdir(target):
        files = sorted(
            os.path.join(target, f) for f in os.listdir(target)
            if f.lower().endswith('.obj')
        )
    else:
        print(f"Error: '{target}' not found.", file=sys.stderr)
        return 1

    found = False
    for fpath in files:
        for m in scan_file(fpath, symbol):
            found = True
            bn = os.path.basename(m['file'])
            if m['format'] == 'elf':
                bind = elf_binding_name(m['binding'])
                tp = elf_type_name(m['sym_type'])
                defined = 'DEFINED' if m['shndx'] != SHN_UNDEF else 'UNDEF'
                print(f"  {bn}: [{m['format'].upper()}] sym[{m['index']}] {m['name']}  "
                      f"bind={bind}  type={tp}  shndx={m['shndx']}  "
                      f"value=0x{m['value']:X}  size={m['size']}  ({defined})")
            else:
                cls = coff_storage_name(m['storage'])
                defined = 'DEFINED' if m['section'] > 0 else 'UNDEF'
                print(f"  {bn}: [{m['format'].upper()}] sym[{m['index']}] {m['name']}  "
                      f"storage={cls}  sect={m['section']}  "
                      f"value=0x{m['value']:X}  ({defined})")

    if not found:
        print(f"  Symbol '{symbol}' not found.")
    return 0


def cmd_demote(obj_path, symbol, dry_run=False):
    if not os.path.isfile(obj_path):
        print(f"Error: '{obj_path}' not found.", file=sys.stderr)
        return 1
    with open(obj_path, 'rb') as f:
        magic = f.read(4)
    fmt = detect_format(magic + b'\x00' * 16)
    if fmt == 'elf':
        return elf_demote(obj_path, symbol, dry_run)
    elif fmt == 'coff':
        return coff_demote(obj_path, symbol, dry_run)
    else:
        print(f"Error: unrecognized format in '{obj_path}'.", file=sys.stderr)
        return 1


def cmd_rename(obj_path, old_name, new_name, dry_run=False):
    """Rename a symbol in-place in the string table. Same length required."""
    if len(old_name) != len(new_name):
        print(f"Error: old_name ({len(old_name)} chars) and new_name ({len(new_name)} chars) "
              f"must be the same length.", file=sys.stderr)
        return 1
    if not os.path.isfile(obj_path):
        print(f"Error: '{obj_path}' not found.", file=sys.stderr)
        return 1

    with open(obj_path, 'rb') as f:
        data = bytearray(f.read())

    fmt = detect_format(bytes(data[:20]))
    if fmt != 'elf':
        print(f"Error: --rename only supports ELF objects (got {fmt}).", file=sys.stderr)
        return 1

    sections = parse_elf_sections(data)
    # Find the symbol and its string table offset
    target = None
    strtab_off = None
    for sec in sections:
        if sec['sh_type'] != SHT_SYMTAB:
            continue
        strtab_sec = sections[sec['sh_link']]
        strtab_off = strtab_sec['sh_offset']
        nsyms = sec['sh_size'] // ELF64_SYM_SIZE
        for i in range(nsyms):
            sym_off = sec['sh_offset'] + i * ELF64_SYM_SIZE
            st_name_idx = struct.unpack_from('<I', data, sym_off)[0]
            name = elf_get_string(data, strtab_off, st_name_idx)
            if name == old_name:
                target = {'index': i, 'st_name_idx': st_name_idx}
                break
        if target:
            break

    if target is None:
        print(f"Error: symbol '{old_name}' not found in '{os.path.basename(obj_path)}'.",
              file=sys.stderr)
        return 1

    str_abs_off = strtab_off + target['st_name_idx']
    print(f"  {os.path.basename(obj_path)}:  sym[{target['index']}]")
    print(f"    rename: '{old_name}' -> '{new_name}'")
    print(f"    strtab offset: 0x{str_abs_off:X}")

    if dry_run:
        print("  [DRY RUN] No changes written.")
        return 0

    backup_path = obj_path + '.bak'
    if not os.path.exists(backup_path):
        shutil.copy2(obj_path, backup_path)
        print(f"  Backup: {os.path.basename(backup_path)}")

    new_bytes = new_name.encode('ascii')
    data[str_abs_off:str_abs_off + len(new_bytes)] = new_bytes
    with open(obj_path, 'wb') as f:
        f.write(data)
    print("  Renamed successfully.")
    return 0


def _coff_scan_comdat1_externals(dirpath):
    """Return {symbol_name: filename} for EXTERNAL DEFINED COMDAT sel=1 symbols in all COFF OBJs."""
    defs = {}
    for fn in sorted(os.listdir(dirpath)):
        if not fn.upper().endswith('.OBJ'):
            continue
        fpath = os.path.join(dirpath, fn)
        try:
            with open(fpath, 'rb') as f:
                data = f.read()
        except OSError:
            continue
        if len(data) < 20 or struct.unpack_from('<H', data, 0)[0] != COFF_AMD64:
            continue
        hdr = coff_parse_header(data)
        if not hdr['symtab_ptr']:
            continue
        strtab_off = hdr['symtab_ptr'] + hdr['nsymbols'] * COFF_SYMTAB_ENTRY_SIZE
        strtbl_size = struct.unpack_from('<I', data, strtab_off)[0] if strtab_off + 4 <= len(data) else 0

        # Collect sections that are COMDAT sel=1 (NODUPLICATES)
        comdat1_secs = set()
        i = 0
        while i < hdr['nsymbols']:
            off = hdr['symtab_ptr'] + i * COFF_SYMTAB_ENTRY_SIZE
            if off + 18 > len(data):
                break
            naux = data[off + 17]
            cls = data[off + 16]
            sec = struct.unpack_from('<h', data, off + 12)[0]
            if cls == IMAGE_SYM_CLASS_STATIC and naux >= 1 and sec > 0:
                aoff = off + 18
                if aoff + 18 <= len(data) and data[aoff + 14] == 1:
                    comdat1_secs.add(sec)
            i += 1 + naux

        # Collect EXTERNAL DEFINED symbols in those sections
        i = 0
        while i < hdr['nsymbols']:
            off = hdr['symtab_ptr'] + i * COFF_SYMTAB_ENTRY_SIZE
            if off + 18 > len(data):
                break
            name_bytes = data[off:off + 8]
            naux = data[off + 17]
            sec = struct.unpack_from('<h', data, off + 12)[0]
            cls = data[off + 16]
            if cls == IMAGE_SYM_CLASS_EXTERNAL and sec > 0 and sec in comdat1_secs:
                name = coff_decode_name(name_bytes, data, strtab_off)
                if '??' not in name:
                    defs[name] = fn
            i += 1 + naux
    return defs


def _coff_bulk_demote(fpath, symbols, dry_run=False):
    """Demote a set of named symbols from EXTERNAL to STATIC in one COFF OBJ file."""
    try:
        with open(fpath, 'rb') as f:
            data = bytearray(f.read())
    except OSError as e:
        print(f"  Error reading {fpath}: {e}", file=sys.stderr)
        return 0, 0

    hdr = coff_parse_header(data)
    if not hdr['symtab_ptr']:
        return 0, 0

    remaining = set(symbols)
    patched = 0
    i = 0
    while i < hdr['nsymbols'] and remaining:
        off = hdr['symtab_ptr'] + i * COFF_SYMTAB_ENTRY_SIZE
        if off + 18 > len(data):
            break
        naux = data[off + 17]
        cls = data[off + 16]
        sec = struct.unpack_from('<h', data, off + 12)[0]
        if cls == IMAGE_SYM_CLASS_EXTERNAL and sec > 0:
            name_bytes = data[off:off + 8]
            strtab_off = hdr['symtab_ptr'] + hdr['nsymbols'] * COFF_SYMTAB_ENTRY_SIZE
            name = coff_decode_name(name_bytes, data, strtab_off)
            if name in remaining:
                if not dry_run:
                    data[off + 16] = IMAGE_SYM_CLASS_STATIC
                patched += 1
                remaining.discard(name)
        i += 1 + naux

    if patched and not dry_run:
        backup_path = fpath + '.bak'
        if not os.path.exists(backup_path):
            import shutil
            shutil.copy2(fpath, backup_path)
        with open(fpath, 'wb') as f:
            f.write(data)

    return patched, len(symbols) - patched


def cmd_demote_comdat_dups(dir3, dir4, dry_run=False):
    """
    Find all EXTERNAL DEFINED COMDAT sel=1 symbols in both dir3 and dir4 (COFF AMD64),
    then demote the dir4 copies to STATIC. dir3's copies remain as the authoritative definitions.
    """
    if not os.path.isdir(dir3):
        print(f"Error: dir3 '{dir3}' not found.", file=sys.stderr)
        return 1
    if not os.path.isdir(dir4):
        print(f"Error: dir4 '{dir4}' not found.", file=sys.stderr)
        return 1

    print(f"Scanning COMDAT sel=1 EXTERNAL symbols in '{dir3}'...")
    defs3 = _coff_scan_comdat1_externals(dir3)
    print(f"  Found {len(defs3)} symbols")

    print(f"Scanning COMDAT sel=1 EXTERNAL symbols in '{dir4}'...")
    defs4 = _coff_scan_comdat1_externals(dir4)
    print(f"  Found {len(defs4)} symbols")

    # Find symbols present in both
    dups = {s: defs4[s] for s in defs3 if s in defs4}
    print(f"Duplicates (in both): {len(dups)}")
    if not dups:
        print("Nothing to do.")
        return 0

    # Group by obj4 file
    by_file = {}
    for sym, fn in dups.items():
        by_file.setdefault(fn, []).append(sym)

    total_patched = 0
    total_missed = 0
    files_changed = 0

    for fn in sorted(by_file):
        fpath = os.path.join(dir4, fn)
        syms = by_file[fn]
        p, m = _coff_bulk_demote(fpath, syms, dry_run=dry_run)
        total_patched += p
        total_missed += m
        if p:
            files_changed += 1

    tag = "[DRY RUN] " if dry_run else ""
    print(f"{tag}Files changed: {files_changed}")
    print(f"{tag}Symbols demoted (EXTERNAL->STATIC): {total_patched}")
    if total_missed:
        print(f"  WARNING: {total_missed} symbols not found in their expected files")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Patch OBJ symbols: demote GLOBAL->LOCAL, rename, scan (COFF + ELF).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--scan', action='store_true', help='Scan for a symbol')
    group.add_argument('--demote', action='store_true', help='Demote GLOBAL->LOCAL')
    group.add_argument('--rename', action='store_true',
                       help='Rename symbol in string table (ELF only, same length)')
    group.add_argument('--demote-comdat-dups', action='store_true',
                       help='Demote all COMDAT sel=1 dups from dir4 that also exist in dir3')
    parser.add_argument('target', nargs='?', help='OBJ file, directory, or dir3 for --demote-comdat-dups')
    parser.add_argument('symbol', nargs='?', help='Symbol name, or dir4 for --demote-comdat-dups')
    parser.add_argument('new_name', nargs='?', help='New name (--rename only, same length)')
    parser.add_argument('--dry-run', action='store_true', help='Preview only')
    args = parser.parse_args()

    if args.demote_comdat_dups:
        if not args.target or not args.symbol:
            print("Error: --demote-comdat-dups requires <dir3> <dir4>", file=sys.stderr)
            return 1
        return cmd_demote_comdat_dups(args.target, args.symbol, dry_run=args.dry_run)
    elif args.scan:
        return cmd_scan(args.target, args.symbol)
    elif args.rename:
        if not args.new_name:
            print("Error: --rename requires new_name argument.", file=sys.stderr)
            return 1
        return cmd_rename(args.target, args.symbol, args.new_name, dry_run=args.dry_run)
    return cmd_demote(args.target, args.symbol, dry_run=args.dry_run)


if __name__ == '__main__':
    sys.exit(main() or 0)
