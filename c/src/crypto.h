#ifndef __CFPP_CRYPTO_H
#define __CFPP_CRYPTO_H

#include <stdlib.h>
#include <openssl/rsa.h>

#define ALGORITHM_TDES 0
#define ALGORITHM_AES 1


#define TDES_KEY_LENGTH_1 8
#define TDES_KEY_LENGTH_2 16
#define TDES_KEY_LENGTH_3 24

#define TDES_BLOCK_SIZE 8

#define AES_KEY_LENGTH_1 16
#define AES_KEY_LENGTH_2 24
#define AES_KEY_LENGTH_3 32

#define VALID_AES_KEY_SIZE(x) ( (x)==AES_KEY_LENGTH_1 || (x)==AES_KEY_LENGTH_2 || (x)==AES_KEY_LENGTH_3)

#define AES_BLOCK_SIZE 16

#define AES_GCM_TAG_SIZE 16
#define AES_HMAC_TAG_SIZE 16

#define HMAC_AAD_LEN_SIZE 	8
#define SHA256_OUTPUT_SIZE	32

#define AES_MAX_TAG_SIZE AES_GCM_TAG_SIZE

/**
 * Allocates and returns an RSA structure or NULL in case of an error. It is the caller's responsibility
 * to call RSA_free on the return value.
 *
 * @param n the modulus
 * @param n_len the modulus length
 * @param e the exponent
 * @param d the private key, can be NULL
 * @param d_len size of the private key, must be 0 if d is NULL
 * @result the RSA structure or NULL if an error occurred
 */
RSA *make_rsa_key( uint8_t n[], size_t n_len, uint32_t e, uint8_t d[], size_t d_len );

#endif
