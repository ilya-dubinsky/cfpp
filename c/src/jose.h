#ifndef CFPP_JOSE_H_
#define CFPP_JOSE_H_

/* The examples here use a very basic JSON serialization, written specifically
 * for the sake of presenting the examples. A full-blown serialized and parser
 * should be substituted for the functions herein.
 *
 * It is assumed that the functions allocate memory from the generic heap. It is
 * the caller's responsibility to free it.
 *
 * Only selected public keys are supported.
 */

#include <openssl/bn.h>

/* Use this for the encrypted CEK to be fixed value according to the example from RFC 5716 */
#define RFC_5716_TEST

#define UNREASONABLY_BIG 128*(1<<10) /* 128 Kb will be considered too big */
#define TOO_BIG(x) ((size_t)(x) > UNREASONABLY_BIG)

 /* these are assigned sequentially and map into an internal array */

#define JOSE_KEY_TYPE_RSA 		0
#define JOSE_KEY_TYPE_EC 		1

#define VALID_KEY_TYPE(x) (JOSE_KEY_TYPE_RSA==(x) || (JOSE_KEY_TYPE_EC==(x)))

#define JOSE_KEY_USE_NONE 		0
#define JOSE_KEY_USE_ENC 		1
#define JOSE_KEY_USE_SIG 		2

#define VALID_KEY_USE(x) (JOSE_KEY_USE_ENC==(x) || (JOSE_KEY_USE_SIG==(x)))

#define JOSE_RSA_256			0 /* for examples only, basic RSA w/SHA-256*/
#define JOSE_RSA_OAEP_256		1 /* Used for 3DS 2.0. RSA with OAEP padding using SHA-256 */
#define JOSE_ECDH_ES			2 /* Used for 3DS 2.0. Elliptic-curve Diffie Hellman */
#define JOSE_AES_128_CBC_HS_256	3 /* Used for 3DS 2.0. AES-128 CBC with HMAC using SHA-256 */
#define JOSE_AES_128_GCM		4 /* Used for 3DS 2.0. AES-128 Galois/Counter Mode */

#define VALID_KEY_ALG(x) ( 	JOSE_RSA_256==(x) || \
							JOSE_RSA_OAEP_256==(x) || \
							JOSE_ECDH_ES==(x) || \
							JOSE_AES_128_CBC_HS_256==(x) || \
							JOSE_AES_128_GCM==(x) )


#define JOSE_KEY_EC_CURVE_P256		0 /* Used for 3DS 2.0 */

#define VALID_KEY_EC_CURVE(x) (JOSE_KEY_EC_CURVE_P256==(x))

typedef struct tag_RSA_PARAMS {
	BIGNUM * n;
	BIGNUM * e;
} RSA_PARAMS;

typedef struct tag_EC_PARAMS {
	uint8_t curve;
	BIGNUM * x;
	BIGNUM * y;
} EC_PARAMS;

/**
 * Returns a char buffer with the JWK representation of the key. Allocates memory which
 * the caller must free.
 * @param key_type Key type
 * @param key_use  Key use
 * @param kid Key ID (optional)
 * @param data key data, specific to the key algorithm
 * @result returns NULL or pointer to an allocated memory buffer
 */
char * jose_create_jwk( uint8_t key_type, uint8_t key_use, char* kid, void * data);

/**
 * Creates the JWE representation of the given payload.
 * @param key_protection_alg the key protection algorithm
 * @param payload_enc_alg the payload encryption algorithm
 * @param cek the Content Encryption Key
 * @param cek_len the Content Encryption Key length
 * @param kek_data  points to the structure corresponding to the algorithm. In our case it is only RSA_PARAMS.
 * @param iv the initialization vector
 * @param iv_len the IV length
 * @param payload the payload
 * @param payload_len the payload length
 * @result the string with base64 encoding of the payload, dot, then the auth tag. It is caller's responsibility to free the memory.
 */
char * jose_create_jwe ( uint8_t key_protection_alg, uint8_t payload_enc_alg, uint8_t * cek, size_t cek_len, void *kek_data,
		uint8_t *iv, size_t iv_size, uint8_t * payload, size_t payload_len);

#endif /* CFPP_JOSE_H_ */
