"""Regression checks for the conservative C/Pascal ABI auditor."""
import unittest
from pathlib import Path
import tempfile

from audit_api_abi import active_source, asn1_prototypes, audit, c_declarations, pascal_declarations


class ABIAuditTests(unittest.TestCase):
    def compare_sources(self, pascal, header):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'include/openssl').mkdir(parents=True)
            (root / 'include/openssl/fixture.h').write_text(header)
            source = active_source('interface\n' + pascal + '\nimplementation\nend.', 4, 'msc32')
            return audit(pascal_declarations(source), c_declarations(root))['findings']

    def compare(self, declaration, result='int', arguments=()):
        source = active_source('interface\n' + declaration + '\nimplementation\nend.', 4, 'msc32')
        headers = {'sample': dict(result=result, arguments=list(arguments), header='fixture.h')}
        return audit(pascal_declarations(source), headers)['findings']

    def test_inline_external_requires_convention(self):
        self.assertEqual('missing-cdecl', self.compare(
            'function sample: Integer; external;')[0]['issue'])

    def test_next_declaration_cannot_supply_convention(self):
        findings = self.compare('function sample: Integer; external;\n'
                                'function other: Integer; cdecl; external;')
        self.assertEqual('missing-cdecl', findings[0]['issue'])

    def test_scalar_return_and_missing_argument(self):
        findings = self.compare('function sample: Pointer; cdecl; external;',
                                arguments=['size_t length'])
        self.assertEqual(['return', 'argument-count'], [x['issue'] for x in findings])

    def test_void_return(self):
        self.assertEqual('return', self.compare(
            'function sample: Integer; cdecl; external;', result='void')[0]['issue'])

    def test_correct_scalar_and_output_pointer(self):
        self.assertEqual([], self.compare(
            'function sample(n: NativeUInt; used: PNativeUInt): Integer; cdecl; external;',
            arguments=['size_t n', 'size_t *used']))

    def test_branch_selection_preserves_lines(self):
        source = 'interface\n{$IFDEF OPENSSL_4X}function sample: Integer;{$ELSE}procedure sample;{$ENDIF}\nimplementation\nend.'
        for branch, expected in ((3, 'void'), (4, 'Integer')):
            selected = active_source(source, branch, 'msc32')
            self.assertEqual(source.count('\n'), selected.count('\n'))
            self.assertEqual(expected, pascal_declarations(selected)['sample']['result'])

    def test_asn1_named_macro(self):
        prototypes = asn1_prototypes('DECLARE_ASN1_FUNCTIONS_name_attr(extern, VALUE, CUSTOM)')
        self.assertIn('VALUE *CUSTOM_new(void);', prototypes)
        self.assertIn('VALUE *d2i_CUSTOM(VALUE **a, const unsigned char **in, long len);', prototypes)
        self.assertIn('int i2d_CUSTOM(const VALUE *a, unsigned char **out);', prototypes)

    def test_narrow_scalar_and_enum_are_not_pointers(self):
        for result in ('uint8_t', 'uint16_t', 'enum UI_string_types', 'DES_LONG'):
            self.assertEqual('return', self.compare(
                'function sample: Pointer; cdecl; external;', result=result)[0]['issue'])

    def test_hpke_record_is_not_pointer(self):
        findings = self.compare('function sample(suite: Pointer): Integer; cdecl; external;',
                                arguments=['OSSL_HPKE_SUITE suite'])
        self.assertEqual('argument', findings[0]['issue'])

    def test_inline_callback_wrong_arity(self):
        findings = self.compare_sources(
            'type Handler = procedure(a: Pointer; b: Pointer); cdecl;\n'
            'procedure sample(cb: Handler); cdecl; external;',
            'void sample(void (*cb)(void *a, const char *b, const char *c, void *arg));')
        self.assertEqual('callback-argument-count', findings[0]['issue'])

    def test_callback_getter_returns_function_pointer(self):
        findings = self.compare_sources('procedure sample(arg: Pointer); cdecl; external;',
                                        'int (*sample(void *arg))(void *a);')
        self.assertEqual('return', findings[0]['issue'])

    def test_nested_callback_requires_calling_convention(self):
        findings = self.compare_sources(
            'type Handler = procedure(a: Pointer);\n'
            'procedure sample(cb: Handler); cdecl; external;',
            'void sample(void (*cb)(void *a));')
        self.assertEqual('callback-missing-cdecl', findings[0]['issue'])

    def test_callback_output_pointer_depth(self):
        findings = self.compare_sources('type sample = function(value: Pointer): Integer; cdecl;',
                                        'typedef int(sample)(void **value);')
        self.assertEqual('output-pointer-depth', findings[0]['issue'])

    def test_named_callback_getter_checks_result_signature(self):
        findings = self.compare_sources(
            'type Handler = procedure(a: Pointer); cdecl;\n'
            'function sample: Handler; cdecl; external;',
            'typedef void (*CHandler)(void *a, int count); CHandler sample(void);')
        self.assertEqual('callback-argument-count', findings[0]['issue'])


if __name__ == '__main__':
    unittest.main()
