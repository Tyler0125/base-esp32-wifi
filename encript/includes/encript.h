#ifndef ENCRIPT_H
#define ENCRIPT_H

#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <string.h>

#define PUBLIC_KEY_LENGTH 512
extern mbedtls_pk_context pk;
extern mbedtls_entropy_context entropy;
extern mbedtls_ctr_drbg_context ctr_drbg;

int init(const unsigned char* public_key, const unsigned char* private_key);

int set_public_key(const unsigned char* public_key);
int set_private_key(const unsigned char* private_key);

int encript(const char* data, char* encription);
int decript(const char* encription, char* data);




#endif