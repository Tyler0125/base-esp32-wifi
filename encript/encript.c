#include "encript.h"


mbedtls_pk_context pk;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

int init(const unsigned char *public_key, const unsigned char *private_key)
{
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int res = set_public_key(public_key);
    if (res != 0) return res;
    res = set_private_key(private_key);
    return res;
}
int set_public_key(const unsigned char *public_key)
{
    int ret = mbedtls_pk_parse_public_key(&pk, public_key, PUBLIC_KEY_LENGTH + 1);
    if (ret != 0)
    {
        mbedtls_pk_free(&pk);
        return ret;
    }

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0)
    {
        mbedtls_pk_free(&pk);
        return ret;
    }

    return 0;
}
int set_private_key(const unsigned char *private_key)
{
    int ret = mbedtls_pk_parse_key(&pk, private_key, NULL, 0, NULL, 0, NULL);
    if (ret != 0)
    {
        mbedtls_pk_free(&pk);
        return ret;
    }

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0)
    {
        mbedtls_pk_free(&pk);
        return ret;
    }

    return 0;
}


int encript(const char* data, char* encription) {
    int ret = 0;

    size_t data_len = strlen(data);
    size_t max_encrypted_len = mbedtls_pk_get_len(&pk);
    unsigned char* encrypted = malloc(max_encrypted_len);
    memset(encrypted, 0, max_encrypted_len);

    ret = mbedtls_pk_encrypt(&pk, (const unsigned char*)data, data_len, encrypted,
                             &max_encrypted_len, max_encrypted_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        free(encrypted);
        return ret;
    }

    memcpy(encription, encrypted, max_encrypted_len);

    free(encrypted);
    return 0;
}

int decript(const char* encription, char* data) {
    int ret = 0;

    size_t encription_len = strlen(encription);
    size_t max_decrypted_len = mbedtls_pk_get_len(&pk);
    unsigned char* decrypted = malloc(max_decrypted_len);
    memset(decrypted, 0, max_decrypted_len);

    ret = mbedtls_pk_decrypt(&pk, (const unsigned char*)encription, encription_len, decrypted,
                             &max_decrypted_len, max_decrypted_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        free(decrypted);
        return ret;
    }

    memcpy(data, decrypted, max_decrypted_len);

    free(decrypted);
    return 0;
}
