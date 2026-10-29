/* Classic BCC32 passes value records on the stack, while Delphi register
 * passes them by reference. Keep this adaptation at the C ABI boundary. */
typedef struct { unsigned short kem_id, kdf_id, aead_id; } OSSL_HPKE_SUITE;
typedef unsigned int size_t;
extern void * OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite, int role, void *libctx, const char *propq);
void * delphi_OSSL_HPKE_CTX_new(int mode, const OSSL_HPKE_SUITE *suite, int role, void *libctx, const char *propq)
{
    return OSSL_HPKE_CTX_new(mode, *suite, role, libctx, propq);
}
extern size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen);
size_t delphi_OSSL_HPKE_get_ciphertext_size(const OSSL_HPKE_SUITE *suite, size_t clearlen)
{
    return OSSL_HPKE_get_ciphertext_size(*suite, clearlen);
}
extern size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite);
size_t delphi_OSSL_HPKE_get_public_encap_size(const OSSL_HPKE_SUITE *suite)
{
    return OSSL_HPKE_get_public_encap_size(*suite);
}
extern size_t OSSL_HPKE_get_recommended_ikmelen(OSSL_HPKE_SUITE suite);
size_t delphi_OSSL_HPKE_get_recommended_ikmelen(const OSSL_HPKE_SUITE *suite)
{
    return OSSL_HPKE_get_recommended_ikmelen(*suite);
}
extern int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);
int delphi_OSSL_HPKE_suite_check(const OSSL_HPKE_SUITE *suite)
{
    return OSSL_HPKE_suite_check(*suite);
}
extern int OSSL_HPKE_keygen(OSSL_HPKE_SUITE suite, unsigned char *pub, size_t *publen, void **priv, const unsigned char *ikm, size_t ikmlen, void *libctx, const char *propq);
int delphi_OSSL_HPKE_keygen(const OSSL_HPKE_SUITE *suite, unsigned char *pub, size_t *publen, void **priv, const unsigned char *ikm, size_t ikmlen, void *libctx, const char *propq)
{
    return OSSL_HPKE_keygen(*suite, pub, publen, priv, ikm, ikmlen, libctx, propq);
}

#ifdef OPENSSL_4X
extern int OSSL_ECHSTORE_new_config(void *es, unsigned short echversion, unsigned char max_name_length, const char *public_name, OSSL_HPKE_SUITE suite);
int delphi_OSSL_ECHSTORE_new_config(void *es, unsigned short echversion, unsigned char max_name_length, const char *public_name, const OSSL_HPKE_SUITE *suite)
{
    return OSSL_ECHSTORE_new_config(es, echversion, max_name_length, public_name, *suite);
}
#endif
