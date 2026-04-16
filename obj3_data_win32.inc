// --- OpenSSL cross-obj data placeholders ---
// Data symbols: use procedure external to link real OBJ data.
// The linker matches these to OBJ data PUBDEFs (W1028 warnings expected).
// DO NOT use var declarations - they shadow OBJ data with zeros!


{ Win32 data and internal function externals - these have underscore-prefixed DATA PUBDEFs in BCC32 OBJ }
procedure _CONF_get_section; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + '_CONF_get_section';{$ENDIF}
procedure _CONF_get_string; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + '_CONF_get_string';{$ENDIF}
procedure _DES_SPtrans; external name '_DES_SPtrans';
procedure _DTLSv1_2_enc_data; external name '_DTLSv1_2_enc_data';
procedure _DTLSv1_enc_data; external name '_DTLSv1_enc_data';
procedure _ossl_aes_xts_allow_insecure_decrypt; external name '_ossl_aes_xts_allow_insecure_decrypt';
procedure _ossl_any_to_obj_algorithm; external name '_ossl_any_to_obj_algorithm';
procedure _ossl_bignum_const_2; external name '_ossl_bignum_const_2';
procedure _ossl_bignum_dh1024_160_g; external name '_ossl_bignum_dh1024_160_g';
procedure _ossl_bignum_dh1024_160_p; external name '_ossl_bignum_dh1024_160_p';
procedure _ossl_bignum_dh1024_160_q; external name '_ossl_bignum_dh1024_160_q';
procedure _ossl_bignum_dh2048_224_g; external name '_ossl_bignum_dh2048_224_g';
procedure _ossl_bignum_dh2048_224_p; external name '_ossl_bignum_dh2048_224_p';
procedure _ossl_bignum_dh2048_224_q; external name '_ossl_bignum_dh2048_224_q';
procedure _ossl_bignum_dh2048_256_g; external name '_ossl_bignum_dh2048_256_g';
procedure _ossl_bignum_dh2048_256_p; external name '_ossl_bignum_dh2048_256_p';
procedure _ossl_bignum_dh2048_256_q; external name '_ossl_bignum_dh2048_256_q';
procedure _ossl_bignum_ffdhe2048_p; external name '_ossl_bignum_ffdhe2048_p';
procedure _ossl_bignum_ffdhe2048_q; external name '_ossl_bignum_ffdhe2048_q';
procedure _ossl_bignum_ffdhe3072_p; external name '_ossl_bignum_ffdhe3072_p';
procedure _ossl_bignum_ffdhe3072_q; external name '_ossl_bignum_ffdhe3072_q';
procedure _ossl_bignum_ffdhe4096_p; external name '_ossl_bignum_ffdhe4096_p';
procedure _ossl_bignum_ffdhe4096_q; external name '_ossl_bignum_ffdhe4096_q';
procedure _ossl_bignum_ffdhe6144_p; external name '_ossl_bignum_ffdhe6144_p';
procedure _ossl_bignum_ffdhe6144_q; external name '_ossl_bignum_ffdhe6144_q';
procedure _ossl_bignum_ffdhe8192_p; external name '_ossl_bignum_ffdhe8192_p';
procedure _ossl_bignum_ffdhe8192_q; external name '_ossl_bignum_ffdhe8192_q';
procedure _ossl_bignum_modp_1536_q; external name '_ossl_bignum_modp_1536_q';
procedure _ossl_bignum_modp_2048_q; external name '_ossl_bignum_modp_2048_q';
procedure _ossl_bignum_modp_3072_q; external name '_ossl_bignum_modp_3072_q';
procedure _ossl_bignum_modp_4096_q; external name '_ossl_bignum_modp_4096_q';
procedure _ossl_bignum_modp_6144_q; external name '_ossl_bignum_modp_6144_q';
procedure _ossl_bignum_modp_8192_q; external name '_ossl_bignum_modp_8192_q';
procedure _ossl_bn_generator_19; external name '_ossl_bn_generator_19';
procedure _ossl_bn_generator_2; external name '_ossl_bn_generator_2';
procedure _ossl_bn_generator_5; external name '_ossl_bn_generator_5';
procedure _ossl_bn_group_1024; external name '_ossl_bn_group_1024';
procedure _ossl_bn_group_1536; external name '_ossl_bn_group_1536';
procedure _ossl_bn_group_2048; external name '_ossl_bn_group_2048';
procedure _ossl_bn_group_3072; external name '_ossl_bn_group_3072';
procedure _ossl_bn_group_4096; external name '_ossl_bn_group_4096';
procedure _ossl_bn_group_6144; external name '_ossl_bn_group_6144';
procedure _ossl_bn_group_8192; external name '_ossl_bn_group_8192';
procedure _ossl_bn_inv_sqrt_2; external name '_ossl_bn_inv_sqrt_2';
procedure _ossl_cc_newreno_method; external name '_ossl_cc_newreno_method';
procedure _ossl_curve448_precomputed_base; external name '_ossl_curve448_precomputed_base';
procedure _ossl_curve448_wnaf_base; external name '_ossl_curve448_wnaf_base';
procedure _ossl_dtls_record_method; external name '_ossl_dtls_record_method';
procedure _ossl_v3_aa_issuing_dist_point; external name '_ossl_v3_aa_issuing_dist_point';
procedure _ossl_v3_acc_cert_policies; external name '_ossl_v3_acc_cert_policies';
procedure _ossl_v3_acc_priv_policies; external name '_ossl_v3_acc_priv_policies';
procedure _ossl_v3_addr; external name '_ossl_v3_addr';
procedure _ossl_v3_akey_id; external name '_ossl_v3_akey_id';
procedure _ossl_v3_allowed_attribute_assignments; external name '_ossl_v3_allowed_attribute_assignments';
procedure _ossl_v3_asid; external name '_ossl_v3_asid';
procedure _ossl_v3_attribute_descriptor; external name '_ossl_v3_attribute_descriptor';
procedure _ossl_v3_attribute_mappings; external name '_ossl_v3_attribute_mappings';
procedure _ossl_v3_audit_identity; external name '_ossl_v3_audit_identity';
procedure _ossl_v3_authority_attribute_identifier; external name '_ossl_v3_authority_attribute_identifier';
procedure _ossl_v3_battcons; external name '_ossl_v3_battcons';
procedure _ossl_v3_bcons; external name '_ossl_v3_bcons';
procedure _ossl_v3_cpols; external name '_ossl_v3_cpols';
procedure _ossl_v3_crl_hold; external name '_ossl_v3_crl_hold';
procedure _ossl_v3_crl_invdate; external name '_ossl_v3_crl_invdate';
procedure _ossl_v3_crl_num; external name '_ossl_v3_crl_num';
procedure _ossl_v3_crl_reason; external name '_ossl_v3_crl_reason';
procedure _ossl_v3_crld; external name '_ossl_v3_crld';
procedure _ossl_v3_ct_scts; external name '_ossl_v3_ct_scts';
procedure _ossl_v3_delta_crl; external name '_ossl_v3_delta_crl';
procedure _ossl_v3_ext_admission; external name '_ossl_v3_ext_admission';
procedure _ossl_v3_ext_ku; external name '_ossl_v3_ext_ku';
procedure _ossl_v3_freshest_crl; external name '_ossl_v3_freshest_crl';
procedure _ossl_v3_group_ac; external name '_ossl_v3_group_ac';
procedure _ossl_v3_idp; external name '_ossl_v3_idp';
procedure _ossl_v3_indirect_issuer; external name '_ossl_v3_indirect_issuer';
procedure _ossl_v3_info; external name '_ossl_v3_info';
procedure _ossl_v3_inhibit_anyp; external name '_ossl_v3_inhibit_anyp';
procedure _ossl_v3_issued_on_behalf_of; external name '_ossl_v3_issued_on_behalf_of';
procedure _ossl_v3_issuer_sign_tool; external name '_ossl_v3_issuer_sign_tool';
procedure _ossl_v3_key_usage; external name '_ossl_v3_key_usage';
procedure _ossl_v3_ns_ia5_list; external name '_ossl_v3_ns_ia5_list';
procedure _ossl_v3_nscert; external name '_ossl_v3_nscert';
procedure _ossl_v3_ocsp_accresp; external name '_ossl_v3_ocsp_accresp';
procedure _ossl_v3_sinfo; external name '_ossl_v3_sinfo';
procedure _ossl_v3_targeting_information; external name '_ossl_v3_targeting_information';
procedure _tls_1_3_funcs; external name '_tls_1_3_funcs';
procedure _tls_1_funcs; external name '_tls_1_funcs';
procedure _tls_any_funcs; external name '_tls_any_funcs';
procedure _tls11downgrade; external name '_tls11downgrade';
procedure _tls12downgrade; external name '_tls12downgrade';

procedure _CONF_get_number; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + '_CONF_get_number';{$ENDIF}
procedure _CONF_get_section_values; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + '_CONF_get_section_values';{$ENDIF}
procedure _CONF_add_string; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + '_CONF_add_string';{$ENDIF}
procedure _CONF_free_data; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + '_CONF_free_data';{$ENDIF}
procedure _CONF_new_data; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + '_CONF_new_data';{$ENDIF}
procedure _CONF_new_section; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + '_CONF_new_section';{$ENDIF}
{$IFDEF C_COMPILER_BORLAND_32}
function d2i_ECPKParameters_; external;
function i2d_ECPKParameters_; external;
procedure ossl_err_load_crypto_strings_; external;
{$ENDIF}
{$IFDEF C_COMPILER_MSC_32}
function d2i_ECPKParameters_; external name '_d2i_ECPKParameters_';
function i2d_ECPKParameters_; external name '_i2d_ECPKParameters_';
procedure ossl_err_load_crypto_strings_; external name '_ossl_err_load_crypto_strings_';
{$ENDIF}
{$IFDEF C_COMPILER_BCC32C}
procedure ossl_err_load_crypto_strings_; cdecl; external name EXTERNAL_NAME_PREFIX + 'ossl_err_load_crypto_strings_';
{$ENDIF}
// _ftoul, _llmul, _lludiv, _llumod: satisfied by __xxx implementations below (register convention, raw asm)



// DER OID data arrays: imported from OBJ via procedure external declarations
procedure _ossl_der_oid_id_dsa; external name '_ossl_der_oid_id_dsa';
procedure _ossl_der_oid_id_dsa_with_sha1; external name '_ossl_der_oid_id_dsa_with_sha1';
procedure _ossl_der_oid_id_dsa_with_sha224; external name '_ossl_der_oid_id_dsa_with_sha224';
procedure _ossl_der_oid_id_dsa_with_sha256; external name '_ossl_der_oid_id_dsa_with_sha256';
procedure _ossl_der_oid_id_dsa_with_sha384; external name '_ossl_der_oid_id_dsa_with_sha384';
procedure _ossl_der_oid_id_dsa_with_sha512; external name '_ossl_der_oid_id_dsa_with_sha512';
procedure _ossl_der_oid_id_dsa_with_sha3_224; external name '_ossl_der_oid_id_dsa_with_sha3_224';
procedure _ossl_der_oid_id_dsa_with_sha3_256; external name '_ossl_der_oid_id_dsa_with_sha3_256';
procedure _ossl_der_oid_id_dsa_with_sha3_384; external name '_ossl_der_oid_id_dsa_with_sha3_384';
procedure _ossl_der_oid_id_dsa_with_sha3_512; external name '_ossl_der_oid_id_dsa_with_sha3_512';
procedure _ossl_der_oid_id_ecPublicKey; external name '_ossl_der_oid_id_ecPublicKey';
procedure _ossl_der_oid_ecdsa_with_SHA1; external name '_ossl_der_oid_ecdsa_with_SHA1';
procedure _ossl_der_oid_ecdsa_with_SHA224; external name '_ossl_der_oid_ecdsa_with_SHA224';
procedure _ossl_der_oid_ecdsa_with_SHA256; external name '_ossl_der_oid_ecdsa_with_SHA256';
procedure _ossl_der_oid_ecdsa_with_SHA384; external name '_ossl_der_oid_ecdsa_with_SHA384';
procedure _ossl_der_oid_ecdsa_with_SHA512; external name '_ossl_der_oid_ecdsa_with_SHA512';
procedure _ossl_der_oid_id_ecdsa_with_sha3_224; external name '_ossl_der_oid_id_ecdsa_with_sha3_224';
procedure _ossl_der_oid_id_ecdsa_with_sha3_256; external name '_ossl_der_oid_id_ecdsa_with_sha3_256';
procedure _ossl_der_oid_id_ecdsa_with_sha3_384; external name '_ossl_der_oid_id_ecdsa_with_sha3_384';
procedure _ossl_der_oid_id_ecdsa_with_sha3_512; external name '_ossl_der_oid_id_ecdsa_with_sha3_512';
procedure _ossl_der_oid_id_X25519; external name '_ossl_der_oid_id_X25519';
procedure _ossl_der_oid_id_X448; external name '_ossl_der_oid_id_X448';
procedure _ossl_der_oid_id_Ed25519; external name '_ossl_der_oid_id_Ed25519';
procedure _ossl_der_oid_id_Ed448; external name '_ossl_der_oid_id_Ed448';
procedure _ossl_der_oid_id_ml_dsa_44; external name '_ossl_der_oid_id_ml_dsa_44';
procedure _ossl_der_oid_id_ml_dsa_65; external name '_ossl_der_oid_id_ml_dsa_65';
procedure _ossl_der_oid_id_ml_dsa_87; external name '_ossl_der_oid_id_ml_dsa_87';
procedure _ossl_der_oid_id_sha256; external name '_ossl_der_oid_id_sha256';
procedure _ossl_der_oid_id_sha384; external name '_ossl_der_oid_id_sha384';
procedure _ossl_der_oid_id_sha512; external name '_ossl_der_oid_id_sha512';
procedure _ossl_der_oid_id_sha224; external name '_ossl_der_oid_id_sha224';
procedure _ossl_der_oid_id_sha3_224; external name '_ossl_der_oid_id_sha3_224';
procedure _ossl_der_oid_id_sha3_256; external name '_ossl_der_oid_id_sha3_256';
procedure _ossl_der_oid_id_sha3_384; external name '_ossl_der_oid_id_sha3_384';
procedure _ossl_der_oid_id_sha3_512; external name '_ossl_der_oid_id_sha3_512';
procedure _ossl_der_oid_id_shake128; external name '_ossl_der_oid_id_shake128';
procedure _ossl_der_oid_id_shake256; external name '_ossl_der_oid_id_shake256';
procedure _ossl_der_oid_rsaEncryption; external name '_ossl_der_oid_rsaEncryption';
procedure _ossl_der_oid_id_RSASSA_PSS; external name '_ossl_der_oid_id_RSASSA_PSS';
procedure _ossl_der_oid_id_slh_dsa_sha2_128s; external name '_ossl_der_oid_id_slh_dsa_sha2_128s';
procedure _ossl_der_oid_id_slh_dsa_sha2_128f; external name '_ossl_der_oid_id_slh_dsa_sha2_128f';
procedure _ossl_der_oid_id_slh_dsa_sha2_192s; external name '_ossl_der_oid_id_slh_dsa_sha2_192s';
procedure _ossl_der_oid_id_slh_dsa_sha2_192f; external name '_ossl_der_oid_id_slh_dsa_sha2_192f';
procedure _ossl_der_oid_id_slh_dsa_sha2_256s; external name '_ossl_der_oid_id_slh_dsa_sha2_256s';
procedure _ossl_der_oid_id_slh_dsa_sha2_256f; external name '_ossl_der_oid_id_slh_dsa_sha2_256f';
procedure _ossl_der_oid_id_slh_dsa_shake_128s; external name '_ossl_der_oid_id_slh_dsa_shake_128s';
procedure _ossl_der_oid_id_slh_dsa_shake_128f; external name '_ossl_der_oid_id_slh_dsa_shake_128f';
procedure _ossl_der_oid_id_slh_dsa_shake_192s; external name '_ossl_der_oid_id_slh_dsa_shake_192s';
procedure _ossl_der_oid_id_slh_dsa_shake_192f; external name '_ossl_der_oid_id_slh_dsa_shake_192f';
procedure _ossl_der_oid_id_slh_dsa_shake_256s; external name '_ossl_der_oid_id_slh_dsa_shake_256s';
procedure _ossl_der_oid_id_slh_dsa_shake_256f; external name '_ossl_der_oid_id_slh_dsa_shake_256f';
procedure _ossl_der_oid_id_aes128_wrap; external name '_ossl_der_oid_id_aes128_wrap';
procedure _ossl_der_oid_id_aes192_wrap; external name '_ossl_der_oid_id_aes192_wrap';
procedure _ossl_der_oid_id_aes256_wrap; external name '_ossl_der_oid_id_aes256_wrap';
procedure _ossl_der_oid_id_alg_CMS3DESwrap; external name '_ossl_der_oid_id_alg_CMS3DESwrap';
procedure _ossl_der_oid_id_alg_hkdf_with_sha256; external name '_ossl_der_oid_id_alg_hkdf_with_sha256';
procedure _ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224; external name '_ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224';
procedure _ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256; external name '_ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256';
procedure _ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384; external name '_ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384';
procedure _ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512; external name '_ossl_der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512';
procedure _ossl_der_oid_md2WithRSAEncryption; external name '_ossl_der_oid_md2WithRSAEncryption';
procedure _ossl_der_oid_md4WithRSAEncryption; external name '_ossl_der_oid_md4WithRSAEncryption';
procedure _ossl_der_oid_md5WithRSAEncryption; external name '_ossl_der_oid_md5WithRSAEncryption';
procedure _ossl_der_oid_mdc2WithRSASignature; external name '_ossl_der_oid_mdc2WithRSASignature';
procedure _ossl_der_oid_ripemd160WithRSAEncryption; external name '_ossl_der_oid_ripemd160WithRSAEncryption';
procedure _ossl_der_oid_sha1WithRSAEncryption; external name '_ossl_der_oid_sha1WithRSAEncryption';
procedure _ossl_der_oid_sha224WithRSAEncryption; external name '_ossl_der_oid_sha224WithRSAEncryption';
procedure _ossl_der_oid_sha256WithRSAEncryption; external name '_ossl_der_oid_sha256WithRSAEncryption';
procedure _ossl_der_oid_sha384WithRSAEncryption; external name '_ossl_der_oid_sha384WithRSAEncryption';
procedure _ossl_der_oid_sha512WithRSAEncryption; external name '_ossl_der_oid_sha512WithRSAEncryption';
procedure _ossl_der_oid_sha512_224WithRSAEncryption; external name '_ossl_der_oid_sha512_224WithRSAEncryption';
procedure _ossl_der_oid_sha512_256WithRSAEncryption; external name '_ossl_der_oid_sha512_256WithRSAEncryption';
procedure _ossl_der_oid_sm2_with_SM3; external name '_ossl_der_oid_sm2_with_SM3';
procedure _ssl_3_0_funcs; external name '_ssl_3_0_funcs';

// --- Other cross-obj data (imported from OBJ) ---
{$IFNDEF C_COMPILER_MSC_32}
procedure _bio_lookup_lock; {$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name '_bio_lookup_lock';{$ENDIF}
{$ENDIF}

