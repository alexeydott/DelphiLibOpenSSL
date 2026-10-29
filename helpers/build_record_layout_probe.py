"""Compile sizeof/offsetof probes from each release's actual public C records.

The generated C needs no OpenSSL build or configured headers: declarations are
copied from the source archive and only opaque pointer dependencies are supplied.
Objects and generated sources belong to the validation output directory.
"""
import argparse
from pathlib import Path
import re
import subprocess
import zipfile


RECORDS = (
    ('asn1_type_st', 'type value'),
    ('ASN1_ITEM_st', 'itype utype templates tcount funcs size sname'),
    ('buf_mem_st', 'length data max flags'),
    ('asn1_string_table_st', 'nid minsize maxsize mask flags'),
    ('X509_algor_st', 'algorithm parameter'),
    ('rsa_pss_params_st', 'hashAlgorithm maskGenAlgorithm saltLength trailerField maskHash'),
    ('rsa_oaep_params_st', 'hashFunc maskGenFunc pSourceFunc maskHash'),
    ('rand_meth_st', 'seed bytes cleanup add pseudorand status'),
    ('ossl_dispatch_st', 'function_id function'),
    ('ossl_item_st', 'id ptr'),
    ('ossl_algorithm_st', 'algorithm_names property_definition implementation algorithm_description'),
    ('ossl_param_st', 'key data_type data data_size return_size'),
    ('crypto_ex_data_st', 'ctx sk'),
)


def extract_record(headers, name):
    for header in headers:
        match = re.search(r'\bstruct\s+' + re.escape(name) + r'\s*\{', header)
        if not match:
            continue
        pos, depth = match.end(), 1
        while depth:
            depth += (header[pos] == '{') - (header[pos] == '}')
            pos += 1
        return header[match.start():pos] + ';'
    raise ValueError('Public record missing from source headers: ' + name)


def generate(archive):
    with zipfile.ZipFile(archive) as source:
        headers = [re.sub(r'/\*.*?\*/', '', source.read(n).decode('utf-8'), flags=re.S)
                   for n in source.namelist()
                   if '/include/openssl/' in n and n.endswith(('.h', '.h.in'))]
    code = '''#ifdef _WIN64
typedef unsigned __int64 size_t;
#else
typedef unsigned int size_t;
#endif
typedef int ASN1_BOOLEAN;
typedef struct asn1_string_st ASN1_STRING;
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct ASN1_VALUE_st ASN1_VALUE;
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
typedef struct stack_st OPENSSL_STACK;
#define STACK_OF(t) struct stack_st
'''
    for alias in ('INTEGER ENUMERATED BIT_STRING OCTET_STRING PRINTABLESTRING T61STRING '
                  'IA5STRING GENERALSTRING BMPSTRING UNIVERSALSTRING UTCTIME GENERALIZEDTIME '
                  'VISIBLESTRING UTF8STRING').split():
        code += f'typedef ASN1_STRING ASN1_{alias};\n'
    for name, alias in (('X509_algor_st', 'X509_ALGOR'), ('asn1_type_st', 'ASN1_TYPE'),
                        ('ossl_dispatch_st', 'OSSL_DISPATCH')):
        code += f'typedef struct {name} {alias};\n'
    for name, _ in RECORDS:
        code += extract_record(headers, name) + '\n'
    code += 'unsigned int openssl_record_layout(unsigned int record, unsigned int field)\n{\n'
    for number, (name, fields) in enumerate(RECORDS, 1):
        code += f'    if (record == {number}) {{\n'
        code += f'        if (field == 0) return sizeof(struct {name});\n'
        for index, field in enumerate(fields.split(), 1):
            code += f'        if (field == {index}) return (unsigned int)(size_t)&((struct {name} *)0)->{field};\n'
        code += '    }\n'
    return code + '''    return 0xFFFFFFFFU;
}
void openssl_invoke_signal(void (__cdecl *handler)(int))
{
    handler(-17);
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--branch', type=int, choices=(3, 4), required=True)
    parser.add_argument('--compiler', choices=('bcc32', 'bcc32c', 'msc32', 'bcc64', 'msc64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = out / 'record_layout_probe.c'
    version = '3.6.1' if args.branch == 3 else '4.1.0'
    source.write_text(generate(root / 'c_src' / f'openssl-{version}.zip'), encoding='ascii')
    obj = out / 'record_layout_probe.obj'
    target = dict(bcc32='bcc32_classic', bcc32c='bcc32c', msc32='msvc_win32',
                  bcc64='bcc64', msc64='msvc_win64')[args.compiler]
    command = dict(bcc32=f'bcc32 -q -c -pr -O1 -o"{obj}" "{source}"',
                   bcc32c=f'bcc32c -c -O1 -o "{obj}" "{source}"',
                   bcc64=f'bcc64 -c -O1 -o "{obj}" "{source}"',
                   msc32=f'cl /nologo /c /W4 /WX /O1 /GS- /Fo"{obj}" "{source}"',
                   msc64=f'cl /nologo /c /W4 /WX /O1 /GS- /Fo"{obj}" "{source}"')[args.compiler]
    bat = out / 'compile_record_probe.bat'
    bat.write_text(f'@echo off\ncall "{root / "build_config.bat"}" {target} >nul 2>&1\n'
                   'if errorlevel 1 exit /b 1\n' + command + '\nexit /b %errorlevel%\n', encoding='ascii')
    process = subprocess.run(['cmd', '/c', str(bat)], capture_output=True, text=True)
    log = process.stdout + process.stderr
    (out / 'record_probe_build.log').write_text(log, encoding='utf-8')
    if process.returncode or re.search(r'\b(?:warning|error|fatal)\b', log, re.I):
        raise SystemExit(log)


if __name__ == '__main__':
    main()
