#!/usr/bin/env python3
"""
patch_omf_symbol.py - Rename symbols in OMF .obj files.

Properly handles OMF record structure: updates length-prefixed names,
record lengths, and checksums.

Usage:
    python helpers/patch_omf_symbol.py <obj_file> <old_symbol> <new_symbol> [--dry-run]
    python helpers/patch_omf_symbol.py --scan <directory> <old_symbol>
"""

import os
import sys
import struct
import argparse
import shutil

# OMF record types that contain symbol names
PUBDEF   = 0x90
PUBDEF32 = 0x91
EXTDEF   = 0x8C
LEXTDEF  = 0xB4
LEXTDEF32 = 0xB5
LPUBDEF  = 0xB6
LPUBDEF32 = 0xB7


def read_records(data):
    """Parse an OMF file into a list of (type, payload) tuples."""
    records = []
    pos = 0
    while pos < len(data):
        if pos + 3 > len(data):
            break
        rec_type = data[pos]
        rec_len = struct.unpack_from('<H', data, pos + 1)[0]
        payload = data[pos + 3: pos + 3 + rec_len]
        records.append((rec_type, bytearray(payload)))
        pos += 3 + rec_len
    return records


def write_records(records):
    """Serialize a list of (type, payload) back to OMF binary."""
    parts = []
    for rec_type, payload in records:
        # Recalculate checksum: sum of type + len_lo + len_hi + all payload bytes = 0 mod 256
        rec_len = len(payload)
        header = struct.pack('<BH', rec_type, rec_len)
        raw = header + bytes(payload[:-1])  # everything except old checksum
        checksum = (-(sum(raw) & 0xFF)) & 0xFF
        parts.append(raw + bytes([checksum]))
    return b''.join(parts)


def patch_pubdef(payload, old_name, new_name, is32):
    """Patch PUBDEF/PUBDEF32/LPUBDEF/LPUBDEF32 record."""
    changed = False
    old_bytes = old_name.encode('ascii')
    new_bytes = new_name.encode('ascii')
    pos = 0

    # Group index (1 or 2 bytes depending on value)
    if pos >= len(payload) - 1:
        return payload, False
    grp_idx = payload[pos]
    pos += 1
    if grp_idx >= 0x80:
        pos += 1

    # Segment index
    if pos >= len(payload) - 1:
        return payload, False
    seg_idx = payload[pos]
    pos += 1
    if seg_idx >= 0x80:
        pos += 1

    # If segment index is 0, there's a 2-byte frame number
    if seg_idx == 0:
        pos += 2

    # Now parse name entries until we hit the checksum byte
    result = bytearray(payload[:pos])
    while pos < len(payload) - 1:  # -1 for checksum
        name_len = payload[pos]
        if pos + 1 + name_len > len(payload) - 1:
            result.extend(payload[pos:])
            break
        name = payload[pos + 1: pos + 1 + name_len]
        # Public offset (2 or 4 bytes)
        offset_size = 4 if is32 else 2
        after_name = pos + 1 + name_len
        pub_offset = payload[after_name: after_name + offset_size]
        # Type index
        ti_pos = after_name + offset_size
        type_idx = payload[ti_pos]
        ti_size = 1
        if type_idx >= 0x80:
            ti_size = 2

        if name == old_bytes:
            result.append(len(new_bytes))
            result.extend(new_bytes)
            changed = True
        else:
            result.append(name_len)
            result.extend(name)
        result.extend(pub_offset)
        result.extend(payload[ti_pos: ti_pos + ti_size])
        pos = ti_pos + ti_size

    # Append checksum placeholder
    result.append(0)
    return bytes(result), changed


def patch_extdef(payload, old_name, new_name):
    """Patch EXTDEF/LEXTDEF record."""
    changed = False
    old_bytes = old_name.encode('ascii')
    new_bytes = new_name.encode('ascii')
    pos = 0
    result = bytearray()

    while pos < len(payload) - 1:  # -1 for checksum
        name_len = payload[pos]
        if pos + 1 + name_len > len(payload) - 1:
            result.extend(payload[pos:])
            break
        name = payload[pos + 1: pos + 1 + name_len]
        # Type index follows the name
        ti_pos = pos + 1 + name_len
        type_idx = payload[ti_pos]
        ti_size = 1
        if type_idx >= 0x80:
            ti_size = 2

        if name == old_bytes:
            result.append(len(new_bytes))
            result.extend(new_bytes)
            changed = True
        else:
            result.append(name_len)
            result.extend(name)
        result.extend(payload[ti_pos: ti_pos + ti_size])
        pos = ti_pos + ti_size

    result.append(0)  # checksum placeholder
    return bytes(result), changed


def patch_obj(obj_path, old_name, new_name, dry_run=False):
    """Patch all occurrences of old_name -> new_name in an OMF obj file."""
    with open(obj_path, 'rb') as f:
        data = f.read()

    records = read_records(data)
    total_changed = 0

    for i, (rec_type, payload) in enumerate(records):
        changed = False
        if rec_type in (PUBDEF, PUBDEF32, LPUBDEF, LPUBDEF32):
            is32 = rec_type in (PUBDEF32, LPUBDEF32)
            new_payload, changed = patch_pubdef(payload, old_name, new_name, is32)
            if changed:
                records[i] = (rec_type, bytearray(new_payload))
                rec_kind = 'PUBDEF' if rec_type in (PUBDEF, PUBDEF32) else 'LPUBDEF'
                print(f"  {rec_kind}: '{old_name}' -> '{new_name}'")
        elif rec_type in (EXTDEF, LEXTDEF, LEXTDEF32):
            new_payload, changed = patch_extdef(payload, old_name, new_name)
            if changed:
                records[i] = (rec_type, bytearray(new_payload))
                print(f"  EXTDEF: '{old_name}' -> '{new_name}'")

        if changed:
            total_changed += 1

    if total_changed == 0:
        print(f"  No occurrences of '{old_name}' found.")
        return False

    if not dry_run:
        backup = obj_path + '.bak'
        if not os.path.exists(backup):
            shutil.copy2(obj_path, backup)
        out_data = write_records(records)
        with open(obj_path, 'wb') as f:
            f.write(out_data)
        print(f"  Patched {total_changed} record(s). Backup: {os.path.basename(backup)}")
    else:
        print(f"  [DRY RUN] Would patch {total_changed} record(s).")

    return True


def scan_directory(directory, symbol):
    """Find all OBJ files containing the given symbol."""
    found = []
    for fname in sorted(os.listdir(directory)):
        if not fname.lower().endswith('.obj'):
            continue
        fpath = os.path.join(directory, fname)
        with open(fpath, 'rb') as f:
            data = f.read()
        records = read_records(data)
        sym_bytes = symbol.encode('ascii')
        for rec_type, payload in records:
            if sym_bytes in payload:
                # Determine if PUBDEF or EXTDEF
                if rec_type in (PUBDEF, PUBDEF32, LPUBDEF, LPUBDEF32):
                    found.append((fname, 'PUBDEF'))
                elif rec_type in (EXTDEF, LEXTDEF, LEXTDEF32):
                    found.append((fname, 'EXTDEF'))
    return found


def fix_pubdef_group(obj_path, symbol, dry_run=False):
    """Set grp_idx=0 in PUBDEF/PUBDEF32 records that contain the given symbol.

    BCC32C (Clang Win32) incorrectly places CODE symbols inside DGROUP
    (grp_idx=1), causing Delphi W1028 "Bad global symbol definition".
    Setting grp_idx=0 (no group) matches what BCC32 classic produces.
    """
    with open(obj_path, 'rb') as f:
        data = f.read()
    records = read_records(data)
    sym_bytes = symbol.encode('ascii')

    changed_count = 0
    for i, (rec_type, payload) in enumerate(records):
        if rec_type not in (PUBDEF, PUBDEF32):
            continue
        if sym_bytes not in payload:
            continue
        grp_idx = payload[0]
        if grp_idx == 0:
            print(f"  grp_idx already 0 for '{symbol}'. Nothing to do.")
            continue
        rec_name = 'PUBDEF32' if rec_type == PUBDEF32 else 'PUBDEF'
        print(f"  {rec_name}: '{symbol}'  grp_idx={grp_idx} -> 0")
        if grp_idx >= 0x80:
            # 2-byte encoding → drop the extra byte
            new_payload = bytearray([0]) + bytearray(payload[2:])
        else:
            # 1-byte encoding → just zero it (size unchanged)
            new_payload = bytearray(payload)
            new_payload[0] = 0
        records[i] = (rec_type, new_payload)
        changed_count += 1

    if changed_count == 0:
        print(f"  No PUBDEF records containing '{symbol}' found.")
        return 1

    if dry_run:
        print("  [DRY RUN] No changes written.")
        return 0

    backup_path = obj_path + '.bak'
    if not os.path.exists(backup_path):
        shutil.copy2(obj_path, backup_path)
        print(f"  Backup: {os.path.basename(backup_path)}")
    out_data = write_records(records)
    with open(obj_path, 'wb') as f:
        f.write(out_data)
    print(f"  Fixed {changed_count} PUBDEF record(s) — grp_idx set to 0.")
    return 0


def fix_all_pubdef_groups(directory, dry_run=False):
    """Fix grp_idx=0 in ALL PUBDEF/PUBDEF32 records across all OBJs in a directory.

    BCC32C emits grp_idx=1 (DGROUP) for every function PUBDEF, which causes
    Delphi W1028 "Bad global symbol definition" for every declared external.
    """
    total_files = 0
    total_fixed = 0
    for fname in sorted(os.listdir(directory)):
        if not fname.lower().endswith('.obj'):
            continue
        fpath = os.path.join(directory, fname)
        with open(fpath, 'rb') as f:
            data = f.read()
        records = read_records(data)

        changed = False
        for i, (rec_type, payload) in enumerate(records):
            if rec_type not in (PUBDEF, PUBDEF32):
                continue
            grp_idx = payload[0]
            if grp_idx == 0:
                continue
            if grp_idx >= 0x80:
                new_payload = bytearray([0]) + bytearray(payload[2:])
            else:
                new_payload = bytearray(payload)
                new_payload[0] = 0
            records[i] = (rec_type, new_payload)
            changed = True

        if not changed:
            continue

        total_files += 1
        total_fixed += 1
        if dry_run:
            continue

        backup_path = fpath + '.bak'
        if not os.path.exists(backup_path):
            shutil.copy2(fpath, backup_path)
        out_data = write_records(records)
        with open(fpath, 'wb') as f:
            f.write(out_data)

    action = '[DRY RUN] Would fix' if dry_run else 'Fixed'
    print(f"  {action} {total_fixed} OBJ files in {directory}")
    return 0


def main():
    parser = argparse.ArgumentParser(description='Patch OMF symbol names / group indices')
    parser.add_argument('--scan', action='store_true',
                        help='Scan directory for OBJs containing a symbol')
    parser.add_argument('--fix-group', action='store_true',
                        help='Set grp_idx=0 in PUBDEF for symbol (fixes W1028 DGROUP mismatch)')
    parser.add_argument('--fix-all-groups', action='store_true',
                        help='Fix grp_idx=0 in ALL PUBDEF records across ALL OBJs in a directory')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('args', nargs='+')
    args = parser.parse_args()

    if args.scan:
        if len(args.args) < 2:
            print("Usage: --scan <directory> <symbol>")
            sys.exit(1)
        directory, symbol = args.args[0], args.args[1]
        found = scan_directory(directory, symbol)
        if found:
            for fname, kind in found:
                print(f"  {fname}: {kind}")
        else:
            print(f"  No OBJs contain '{symbol}'")
    elif args.fix_group:
        if len(args.args) < 2:
            print("Usage: --fix-group <obj_file> <symbol>")
            sys.exit(1)
        obj_path, symbol = args.args[0], args.args[1]
        print(f"Fixing PUBDEF group in {os.path.basename(obj_path)}:")
        fix_pubdef_group(obj_path, symbol, args.dry_run)
    elif args.fix_all_groups:
        if len(args.args) < 1:
            print("Usage: --fix-all-groups <directory>")
            sys.exit(1)
        directory = args.args[0]
        print(f"Fixing all PUBDEF grp_idx in {directory}:")
        fix_all_pubdef_groups(directory, args.dry_run)
    else:
        if len(args.args) < 3:
            print("Usage: <obj_file> <old_symbol> <new_symbol>")
            sys.exit(1)
        obj_path, old_name, new_name = args.args[0], args.args[1], args.args[2]
        print(f"Patching {os.path.basename(obj_path)}:")
        patch_obj(obj_path, old_name, new_name, args.dry_run)


if __name__ == '__main__':
    main()
