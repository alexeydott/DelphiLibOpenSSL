"""Build the classic BCC32 HPKE value-record adapter and rename C entry points."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from patch_omf_symbol import patch_obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--branch', type=int, choices=(3, 4), required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--objects', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).with_name('hpke_bcc32_bridge.c').resolve()
    names = ['OSSL_HPKE_' + suffix for suffix in (
        'CTX_new', 'get_ciphertext_size', 'get_public_encap_size',
        'get_recommended_ikmelen', 'keygen', 'suite_check')]
    if args.branch == 4:
        names.append('OSSL_ECHSTORE_new_config')
    with tempfile.TemporaryDirectory(prefix='openssl-hpke-abi-') as scratch:
        scratch = Path(scratch)
        target = scratch / 'libcrypto-lib-delphi_hpke_win32.obj'
        command = [str(args.compiler), '-q', '-c', '-pr', '-O1', '-o' + str(target)]
        if args.branch == 4:
            command.append('-DOPENSSL_4X')
        subprocess.run(command + [str(source)], check=True)
        shutil.copyfile(target, args.objects / target.name)
        # Rename both definitions and all C references. Otherwise the C adapter
        # resolves the identically named Pascal wrapper and recurses into it.
        for obj in args.objects.glob('*.obj'):
            data = obj.read_bytes()
            matching = [name for name in names if ('@' + name).encode() in data]
            if not matching:
                continue
            temp = scratch / obj.name
            shutil.copyfile(obj, temp)
            for name in matching:
                patch_obj(str(temp), '@' + name, '@ossl_c_' + name)
            os.chmod(obj, 0o666)
            shutil.copyfile(temp, obj)


if __name__ == '__main__':
    main()
