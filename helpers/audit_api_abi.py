"""Compare directly declared C header prototypes with the Pascal interface.

This conservative audit reports scalar/pointer/record mismatches and missing
calling conventions. Macro-generated APIs and unresolved typedefs need manual
review; a clean report is not proof that every C ABI detail is correct.
"""
import argparse
import ast
import json
from pathlib import Path
import re
import zipfile


def active_source(source, branch, compiler):
    """Select the unit's version/toolchain branches while retaining offsets."""
    symbols = {'MSWINDOWS', 'OPENSSL_' + str(branch) + 'X'}
    symbols.add('C_COMPILER_' + dict(bcc32='BORLAND_32', bcc32c='BCC32C',
                                    msc32='MSC_32', bcc64='BORLAND_64', msc64='MSC_64')[compiler])
    symbols.update(('CPUX64', 'WIN64') if compiler.endswith('64') else ('CPUX86', 'WIN32'))
    def blank(match):
        return ''.join('\n' if c == '\n' else ' ' for c in match[0])
    source = re.sub(r'//[^\r\n]*|\(\*.*?\*\)|\{(?!\$).*?\}', blank, source, flags=re.S)
    def condition(expression):
        expression = re.sub(r'DEFINED\s*\(\s*(\w+)\s*\)',
                            lambda m: str(m[1].upper() in symbols), expression, flags=re.I)
        expression = re.sub(r'\b(?:CompilerVersion|RTLVersion)\b', '36', expression, flags=re.I)
        expression = re.sub(r'\bAND\b', 'and', expression, flags=re.I)
        expression = re.sub(r'\bOR\b', 'or', expression, flags=re.I)
        expression = re.sub(r'\bNOT\b', 'not', expression, flags=re.I)
        expression = expression.replace('<>', '!=')
        expression = re.sub(r'(?<![<>!=])=(?!=)', '==', expression)
        if re.search(r'[^\w\s().<>=!]', expression):
            raise ValueError('Unsupported conditional expression: ' + expression)
        tree = ast.parse(expression, mode='eval')
        allowed = (ast.Expression, ast.Constant, ast.BoolOp, ast.UnaryOp,
                   ast.And, ast.Or, ast.Not, ast.Compare, ast.Lt, ast.LtE,
                   ast.Gt, ast.GtE, ast.Eq, ast.NotEq)
        if any(not isinstance(node, allowed) for node in ast.walk(tree)):
            raise ValueError('Unsupported conditional expression: ' + expression)
        return bool(eval(compile(tree, '<compiler-directive>', 'eval'), {'__builtins__': {}}, {}))
    out = []
    stack = []
    active = True
    pos = 0
    for m in re.finditer(r'\{\$([A-Za-z]+)\s*([^}]*)\}', source):
        text = source[pos:m.start()]
        out.append(text if active else re.sub(r'[^\n]', ' ', text))
        directive, arg = m[1].upper(), m[2].strip()
        if directive in ('IFDEF', 'IFNDEF', 'IF'):
            yes = (arg.upper() in symbols) if directive != 'IF' else condition(arg)
            if directive == 'IFNDEF':
                yes = not yes
            stack.append([active, yes])
            active = active and yes
        elif directive in ('ENDIF', 'IFEND'):
            active = stack.pop()[0]
        elif directive == 'ELSE':
            parent, taken = stack[-1]
            active = parent and not taken
            stack[-1][1] = True
        elif directive == 'ELSEIF':
            parent, taken = stack[-1]
            yes = condition(arg)
            active = parent and not taken and yes
            stack[-1][1] = taken or yes
        elif directive == 'DEFINE' and active:
            symbols.add(arg.upper())
        elif directive == 'UNDEF' and active:
            symbols.discard(arg.upper())
        out.append(blank(m))
        pos = m.end()
    out.append(source[pos:] if active else re.sub(r'[^\n]', ' ', source[pos:]))
    if stack:
        raise ValueError('Unbalanced conditional compilation directives')
    return ''.join(out)


def split_args(text, separator=','):
    depth = 0
    start = 0
    result = []
    for i, ch in enumerate(text):
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        elif ch == separator and depth == 0:
            result.append(text[start:i].strip())
            start = i + 1
    result.append(text[start:].strip())
    return [x for x in result if x and x != 'void']


def pascal_declarations(source):
    interface, implementation = re.split(r'\bimplementation\b', source, maxsplit=1, flags=re.I)
    externals = {m[1].lower() for m in re.finditer(
        r'\b(?:function|procedure)\s+(\w+)[^\r\n]*\bexternal\b', implementation, re.I)}
    # Preserve offsets for precise, byte-preserving fixes and source locations.
    clean = re.sub(r'//[^\r\n]*|\{.*?\}|\(\*.*?\*\)',
                   lambda m: ''.join('\n' if x == '\n' else ' ' for x in m[0]),
                   interface, flags=re.S)
    out = {}
    pattern = r'\b(function|procedure)\s+(\w+)\s*(\(|:|;)|\b(\w+)\s*=\s*(function|procedure)\s*(\(|;)'
    for m in re.finditer(pattern, clean, re.I):
        callback = m[1] is None
        kind, name, token = (m[5], m[4], m[6]) if callback else (m[1], m[2], m[3])
        pos = m.end()
        arguments = []
        if token == '(':
            depth = 1
            start = pos
            while pos < len(clean) and depth:
                depth += (clean[pos] == '(') - (clean[pos] == ')')
                pos += 1
            for group in split_args(clean[start:pos - 1], ';'):
                if ':' not in group:
                    continue
                names, typ = group.rsplit(':', 1)
                names = re.sub(r'^\s*(const|var|out)\s+', '', names, flags=re.I)
                typ = typ.split('=')[0].strip()
                arguments.extend((n.strip(), typ) for n in names.split(','))
        else:
            pos -= 1
        end = clean.find(';', pos)
        if end < 0:
            continue
        ret = clean[pos:end].strip().lstrip(':').strip() if kind.lower() == 'function' else 'void'
        attributes = interface[end + 1:end + 120].split('\n', 1)[0]
        if not attributes.strip():
            attributes = interface[end + 1:end + 120]
        external = name.lower() in externals or bool(re.search(r'\bexternal\b', attributes, re.I))
        out[name] = dict(name=name, result=ret, arguments=arguments,
                         cdecl=bool(re.match(r'\s*cdecl\b', attributes, re.I)),
                         external=external, callback=callback, end=end,
                         line=source.count('\n', 0, m.start()) + 1)
    return out


def header_sources(path):
    if path.suffix.lower() == '.zip':
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if '/include/openssl/' in name and name.endswith(('.h', '.h.in')):
                    yield name, archive.read(name).decode('utf-8', errors='replace')
    else:
        for file in sorted((path / 'include' / 'openssl').glob('*')):
            if file.name.endswith(('.h', '.h.in')):
                yield str(file), file.read_text(encoding='utf-8', errors='replace')


def asn1_prototypes(source):
    """Expand the stable ASN.1 declaration families from openssl/asn1.h."""
    prototypes = []
    for match in re.finditer(r'\bDECLARE_ASN1_(FUNCTIONS\w*|ALLOC_FUNCTIONS\w*|ENCODE_FUNCTIONS\w*|DUP_FUNCTION\w*|NDEF_FUNCTION\w*)\s*\(([^()]*)\)', source):
        family, text = match.groups()
        args = split_args(text)
        if family.endswith('_attr'):
            args = args[1:]
        if not args or any(not re.fullmatch(r'\w+', arg) for arg in args):
            continue
        typ, name = args[0], args[-1]
        if family.startswith('FUNCTIONS') or family.startswith('ALLOC_FUNCTIONS'):
            prototypes += [f'{typ} *{name}_new(void);', f'void {name}_free({typ} *a);']
        if family.startswith(('FUNCTIONS', 'ENCODE_FUNCTIONS')):
            prototypes += [f'{typ} *d2i_{name}({typ} **a, const unsigned char **in, long len);',
                           f'int i2d_{name}(const {typ} *a, unsigned char **out);']
        if family.startswith('DUP_FUNCTION'):
            prototypes.append(f'{typ} *{name}_dup(const {typ} *a);')
        if family.startswith('NDEF_FUNCTION'):
            prototypes.append(f'int i2d_{name}_NDEF(const {typ} *a, unsigned char **out);')
    return '\n'.join(prototypes)


def c_declarations(path):
    result = {}
    for filename, source in header_sources(path):
        clean = re.sub(r'/\*.*?\*/|//[^\n]*', ' ', source, flags=re.S)
        clean = re.sub(r'^\s*#.*(?:\\\n.*)*', '', clean, flags=re.M)
        clean += '\n' + asn1_prototypes(clean)
        # Attribute calls can contain several nested argument lists.
        attribute = re.compile(r'\b(?:ossl_bio__attr__|OSSL_DEPRECATEDIN_\w+_FOR|OSSL_PRINTF_FORMAT|OSSL_SCANF_FORMAT)\s*\(')
        while True:
            match = attribute.search(clean)
            if not match:
                break
            pos, depth = match.end(), 1
            while pos < len(clean) and depth:
                depth += (clean[pos] == '(') - (clean[pos] == ')')
                pos += 1
            clean = clean[:match.start()] + ' ' + clean[pos:]
        clean = re.sub(r'OSSL_DEPRECATEDIN_\w+|OSSL_CRYPTO_ALLOC|__owur', '', clean)
        clean = re.sub(r'STACK_OF\((\w+)\)', r'STACK_OF_\1 *', clean)
        clean = re.sub(r'LHASH_OF\((\w+)\)', r'LHASH_OF_\1 *', clean)
        # Functions returning a function pointer have two parameter lists.
        # Do not confuse the callback's return type with the getter's result.
        for m in re.finditer(r'\b([\w \t*]+?)\(\s*\*\s*(\w+)\s*\(([^()]*)\)\s*\)\s*\(([^;]*)\)\s*;', clean):
            result[m[2]] = dict(name=m[2], result='void *', arguments=split_args(m[3]),
                                header=filename, callback=False,
                                return_callback=dict(result=m[1].strip(), arguments=split_args(m[4]),
                                                     header=filename, callback=True))
        for m in re.finditer(r'([A-Za-z_][\w \t*]*(?:\r?\n[ \t]*[\w \t*]+){0,2}?)\b(\w+)\s*\(', clean):
            prefix, name = m.groups()
            prefix = prefix.rsplit(';', 1)[-1].strip()
            if not prefix or re.search(r'\b(define|return|if|while|static)\b', prefix):
                continue
            pos = m.end()
            depth = 1
            start = pos
            while pos < len(clean) and depth:
                depth += (clean[pos] == '(') - (clean[pos] == ')')
                pos += 1
            if clean[pos:].lstrip()[:1] != ';':
                continue
            prefix = ' '.join(prefix.split())
            callback = prefix.startswith('typedef ')
            if callback:
                prefix = prefix[len('typedef '):]
            # Ignore preprocessor/template debris preceding the return type.
            if len(prefix.split()) > 5:
                continue
            result[name] = dict(name=name, result=prefix,
                                arguments=split_args(clean[start:pos - 1]), header=filename, callback=callback)
        for m in re.finditer(r'\btypedef\s+([\w\s*]+?)\(\s*\*\s*(\w+)\s*\)\s*\(([^;]*?)\)\s*;', clean):
            result[m[2]] = dict(name=m[2], result=' '.join(m[1].split()),
                                 arguments=split_args(m[3]), header=filename, callback=True)
        for m in re.finditer(r'\btypedef\s+([\w \t*]+?)\(\s*(\w+)\s*\)\s*\(([^;]*?)\)\s*;', clean):
            result[m[2]] = dict(name=m[2], result=m[1].strip(),
                                 arguments=split_args(m[3]), header=filename, callback=True)
    return result


def c_kind(typ, parameter=False):
    typ = re.sub(r'\b(const|volatile|restrict)\b', '', typ).strip()
    if '*' in typ or '[' in typ:
        return 'pointer'
    if parameter:
        typ = re.sub(r'\s+\w+$', '', typ).strip()
    typ = re.sub(r'\s+', ' ', typ)
    if typ.startswith('enum ') or typ in ('point_conversion_form_t', 'OSSL_CMP_severity', 'X509_LOOKUP_TYPE', 'DES_LONG', 'OSSL_HANDSHAKE_STATE', 'SSL_TICKET_STATUS', 'SSL_TICKET_RETURN'):
        return 'scalar32'
    if typ in ('void', 'OSSL_PARAM', 'OSSL_HPKE_SUITE'):
        return typ
    if typ in ('int', 'unsigned', 'unsigned int', 'long', 'long int', 'unsigned long',
               'unsigned long int', 'int32_t', 'uint32_t', 'off_t', 'CRYPTO_THREAD_ID', 'CRYPTO_THREAD_LOCAL', 'CRYPTO_ONCE', 'ASN1_BOOLEAN'):
        return 'scalar32'
    if typ in ('int64_t', 'uint64_t', 'long long', 'unsigned long long'):
        return 'scalar64'
    if typ == 'BN_ULONG':
        return 'bn-word'
    if typ in ('size_t', 'ossl_ssize_t'):
        return 'size_t'
    if typ == 'time_t':
        return 'time_t'
    if typ in ('double', 'float'):
        return typ
    if typ in ('char', 'unsigned char', 'int8_t', 'uint8_t'):
        return 'byte'
    if typ in ('short', 'unsigned short', 'int16_t', 'uint16_t'):
        return 'word'
    return None


def pascal_kind(typ):
    lower = typ.lower()
    if lower in ('integer', 'cardinal', 'int32', 'uint32', 'longint', 'longword'):
        return 'scalar32'
    if lower in ('int64', 'uint64'):
        return 'scalar64'
    if lower in ('nativeint', 'nativeuint'):
        return 'size_t'
    if lower in ('c__time_t', 'c_time_t'):
        return 'time_t'
    if lower == 'bn_ulong':
        return 'bn-word'
    if lower in ('byte', 'ansichar'):
        return 'byte'
    if lower == 'word':
        return 'word'
    if lower in ('double', 'single'):
        return 'double' if lower == 'double' else 'float'
    if lower == 'void':
        return 'void'
    if lower in ('ossl_param', 'ossl_hpke_suite'):
        return lower.upper()
    if lower == 'pointer' or lower.startswith('p') or lower.endswith(('_ptr', '_cb', '_fn')):
        return 'pointer'
    return None


def scalar_pointer_mismatch(c_type, pascal_type):
    if c_type.count('*') != 1 or '(' in c_type:
        return False
    c_base = c_kind(c_type.split('*')[0].strip())
    p_base = dict(pinteger='scalar32', pcardinal='scalar32', pint32='scalar32',
                  puint32='scalar32', pint64='scalar64', puint64='scalar64',
                  pnativeint='size_t', pnativeuint='size_t', pdouble='double',
                  psingle='float', pbyte='byte', pansichar='byte', pword='word',
                  c__time_t_ptr='time_t', c_time_t_ptr='time_t').get(pascal_type.lower())
    return bool(c_base and p_base and c_base != p_base)


def callback_signature(declaration, headers):
    match = re.fullmatch(r'\s*([\w\s*]+?)\(\s*\*\s*\w*\s*\)\s*\((.*)\)\s*', declaration, re.S)
    if match:
        return dict(result=match[1].strip(), arguments=split_args(match[2]),
                    header='<inline callback>', callback=True)
    # Named function typedef, optionally followed by * and a parameter name.
    name = declaration.strip().split()[0].rstrip('*')
    signature = headers.get(name)
    return signature if signature and signature.get('callback') else None


def audit(pascal, headers, require_cdecl=True, _depth=0):
    matches = 0
    findings = []
    for name, p in pascal.items():
        c = headers.get(name)
        if not c:
            continue
        matches += 1
        common = dict(name=name, line=p['line'], header=c['header'])
        def check_callback(signature, typ, location):
            callback = pascal.get(typ)
            if not signature or not callback or not callback['callback'] or _depth >= 4:
                return
            nested = audit({typ: callback}, {typ: signature}, require_cdecl, _depth + 1)
            for finding in nested['findings']:
                finding.update(common, issue='callback-' + finding['issue'], location=location)
                findings.append(finding)
        check_callback(c.get('return_callback') or callback_signature(c['result'], headers),
                       p['result'], 'result')
        if require_cdecl and (p['external'] or p['callback']) and not p['cdecl']:
            findings.append(dict(common, issue='missing-cdecl'))
        ck, pk = c_kind(c['result']), pascal_kind(p['result'])
        if (ck and pk and ck != pk) or scalar_pointer_mismatch(c['result'], p['result']):
            findings.append(dict(common, issue='return', c=c['result'], pascal=p['result']))
        args = [a for a in c['arguments'] if a != '...']
        if len(args) != len(p['arguments']):
            findings.append(dict(common, issue='argument-count', c=args, pascal=p['arguments']))
            continue
        for index, (carg, (pname, ptype)) in enumerate(zip(args, p['arguments'])):
            check_callback(callback_signature(carg, headers), ptype, pname)
            if p['callback'] and re.search(r'\*\s*\*', carg) and ptype.lower() == 'pointer':
                findings.append(dict(common, issue='output-pointer-depth', parameter=pname,
                                     c=carg, pascal=ptype))
            ck, pk = c_kind(carg, True), pascal_kind(ptype)
            if (ck and pk and ck != pk) or scalar_pointer_mismatch(carg, ptype):
                findings.append(dict(common, issue='argument', index=index,
                                     c=carg, pascal=ptype, parameter=pname))
    return dict(pascal_declarations=len(pascal), header_declarations=len(headers),
                matched=matches, findings=findings,
                unmatched=sorted(set(pascal) - set(headers)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pascal', type=Path, default=Path('libOpenSSL3.pas'))
    parser.add_argument('--headers', type=Path, required=True)
    parser.add_argument('--branch', type=int, choices=(3, 4), default=4)
    parser.add_argument('--compiler', choices=('bcc32', 'bcc32c', 'msc32', 'bcc64', 'msc64'), default='msc32')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', action='store_true', help='Return nonzero if findings remain')
    args = parser.parse_args()
    source = active_source(args.pascal.read_bytes().decode('latin1'), args.branch, args.compiler)
    report = audit(pascal_declarations(source), c_declarations(args.headers),
                   require_cdecl=args.compiler in ('bcc32c', 'msc32'))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f"{report['matched']} matched declarations, {len(report['findings'])} findings; {args.output}")
    if args.check and report['findings']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
