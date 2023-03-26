#include "jose.h"

#include "bits.h"
#include "crypto.h"
#include "test_io.h"

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

/* the overhead of whitespace, key, separators and new line is less than 16 chars */
#define JSON_OVERHEAD_LINE 16
/* for our examples there are at most 10 key pairs */
#define JSON_OVERHEAD_KEY JSON_OVERHEAD_LINE*10

#define JOSE_TAG_KEY_TYPE	"kty"
#define JOSE_TAG_KID 		"kid"
#define JOSE_TAG_USE 		"use"
#define JOSE_TAG_ALG 		"alg"
#define JOSE_TAG_ENC 		"enc"

#define JOSE_TAG_RSA_N 		"n"
#define JOSE_TAG_RSA_E 		"e"

#define JOSE_TAG_EC_CURVE	"crv"
#define JOSE_TAG_EC_X		"x"
#define JOSE_TAG_EC_Y		"y"
#define JOSE_TAG_EC_D		"d"

#define JSON_ENTRY_TEMPLATE  "\"%s\":\"%s\""

#define JOSE_SEPARATOR_DOT '.'

const char * table_kty [] = {
	"RSA", /* JOSE_KEY_TYPE_RSA */
	"EC"   /* JOSE_KEY_TYPE_EC */
};

const char * table_use [] = {
	NULL,  /* JOSE_KEY_USE_NONE */
	"enc", /* JOSE_KEY_USE_ENC */
	"sig"  /* JOSE_KEY_USE_SIG */
};

const char * table_alg [] = {
	"RSA256", 			/* JOSE_KEY_RSA_256 */
	"RSA-OAEP", 		/* JOSE_KEY_RSA_OAEP_256 */
	"ECDH-ES",			/* JOSE_KEY_ECDH_ES */
	"A128CBC-HS256",	/* JOSE_KEY_AES_128_CBC_HS_256 */
	"A128GCM"			/* JOSE_KEY_AES_128_GCM */
};

const char * table_curves[] = {
	"P-256" 			/* JOSE_KEY_EC_CURVE_P256 */
};

/**
 * Estimate the memory required to represent the key by peeping into the data
 * @param key_type the key type
 * @param data the data provided for the key
 */
static size_t jose_estimate_memory( uint8_t key_type, void * data) {
	if (!VALID_KEY_TYPE(key_type) || !data) return 0;

	size_t retval = 0;
	RSA_PARAMS *p ;
	EC_PARAMS *q;

	/* RSA keys are just modulus and the public exponent */
	switch (key_type ) {
		case JOSE_KEY_TYPE_RSA:
			p = (RSA_PARAMS* )data;
			retval += BASE64_LEN(BN_num_bytes(p->e)) +BASE64_LEN(BN_num_bytes(p->n)) + JSON_OVERHEAD_LINE*2;
			break;
		case JOSE_KEY_TYPE_EC:
			q = (EC_PARAMS*) data;
			retval += BASE64_LEN(BN_num_bytes(q->x)) + BASE64_LEN(BN_num_bytes(q->y)) + 4*JSON_OVERHEAD_LINE;
			break;
	}
	return retval;
}

/* Prints the base64-encoded BIGNUM to the buffer. Returns the buffer. The caller must free it.
 * @param buffer The target buffer
 * @param bignum The BIGNUM to print
 * @result number of chars printed
 */
static char * jose_print_base64_BN_value(const BIGNUM * bignum ) {

	if (!(bignum)) return NULL;

	uint8_t* bn_bin;

	bn_bin = malloc(BN_num_bytes(bignum));

	size_t out_size = BASE64_LEN(BN_num_bytes(bignum));

	char* buffer = calloc(out_size, sizeof(char));

	size_t bin_size = BN_bn2bin(bignum, bn_bin);
	base64url_encode(bn_bin, bin_size, buffer, BASE64_NO_PADDING);

	free(bn_bin);

	return buffer;
}

/** Prints the key value into the buffer in JSON format
 * @param buffer_ptr Point to print from
 * @param tag key value tag
 * @param value the value to print
 * @result Number of characters printed
 */
static size_t jose_print_BN_value (char * buffer_ptr, const char * tag, const BIGNUM * value) {
	size_t retval = 0;

	if (! (buffer_ptr && tag && value)) return retval;

	char * b;
	b = jose_print_base64_BN_value(value);
	retval = sprintf(buffer_ptr, "," JSON_ENTRY_TEMPLATE, tag, b);
	free (b);
	return retval;
}

/**
 * Returns a char buffer with the JWK representation of the key. Allocates memory which
 * the caller must free.
 * @param key_type Key type
 * @param key_use  Key use
 * @param kid Key ID (optional)
 * @param data key data, specific to the key algorithm
 * @result returns NULL or pointer to an allocated memory buffer
 */
char * jose_create_jwk( uint8_t key_type, uint8_t key_use, char* kid, void * data) {

	size_t buffer_size = JSON_OVERHEAD_KEY;
	char * buffer;

	RSA_PARAMS *rsa_params;
	EC_PARAMS  *ec_params;

	/* validate the input values */
	if (!VALID_KEY_TYPE(key_type) ) return NULL;

	/* calculate the required memory */
	buffer_size += jose_estimate_memory(key_type, data);

	/* allocate the buffer */
	if ( TOO_BIG(buffer_size) ) return NULL;
	buffer = calloc(buffer_size, sizeof(char));

	/* start populating it */
	char* buffer_ptr = buffer;
	buffer_ptr += sprintf(buffer_ptr, "{" );

	/* key type, use, KID and algorithm */
	buffer_ptr += sprintf(buffer_ptr, JSON_ENTRY_TEMPLATE, JOSE_TAG_KEY_TYPE, table_kty[key_type]);

	if ( JOSE_KEY_USE_NONE!= key_use && VALID_KEY_USE(key_use) )
		buffer_ptr += sprintf(buffer_ptr, "," JSON_ENTRY_TEMPLATE, JOSE_TAG_USE, table_use[key_use]);

	/* key values themselves */
	switch (key_type){
		case JOSE_KEY_TYPE_RSA:
			rsa_params = (RSA_PARAMS*) data;
			buffer_ptr+= jose_print_BN_value(buffer_ptr, JOSE_TAG_RSA_E, rsa_params->e);
			buffer_ptr+= jose_print_BN_value(buffer_ptr, JOSE_TAG_RSA_N, rsa_params->n);
			break;
		case JOSE_KEY_TYPE_EC:
			ec_params = (EC_PARAMS*) data;
			if (!VALID_KEY_EC_CURVE(ec_params->curve)) goto error;
			buffer_ptr += sprintf(buffer_ptr, "," JSON_ENTRY_TEMPLATE, JOSE_TAG_EC_CURVE, table_curves[ec_params->curve]);
			buffer_ptr += jose_print_BN_value(buffer_ptr, JOSE_TAG_EC_X, ec_params->x);
			buffer_ptr += jose_print_BN_value(buffer_ptr, JOSE_TAG_EC_Y, ec_params->y);
			break;
	}

	if (kid)
		buffer_ptr+= sprintf(buffer_ptr, "," JSON_ENTRY_TEMPLATE, JOSE_TAG_KID, kid);

	sprintf(buffer_ptr, "}");
	return buffer;
error:
	if (buffer!=NULL) free(buffer);
	return NULL;
}

#ifdef RFC_5716_TEST

uint8_t test_enc_cek [] = {56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
		   22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
		   82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
		   145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
		   74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
		   13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
		   173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
		   89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
		   243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
		   41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
		   215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
		   63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
		   193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
		   206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
		   104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
		   89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
		   172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
		   117, 114, 135, 206};

#endif

/**
 * Encrypts the payload using the given cipher and computes the authentication value. The key and the IV are assumed to be of the length
 * corresponding to the algorithm.
 * @param payload_enc_alg the algorithm
 * @param cek the Content Encryption Key
 * @param iv the initialization vector
 * @param aad additional authentication data
 * @param aad_len AAD length
 * @param payload the payload
 * @param payload_len the payload length
 * @result the string with base64 encoding of the payload, dot, then the auth tag. It is caller's responsibility to free the memory.
 */
static char* jose_encrypt_payload(uint8_t payload_enc_alg, uint8_t *cek,
		uint8_t *iv, uint8_t *aad, uint8_t aad_len, uint8_t *payload,
		size_t payload_len) {

	char * result = NULL;
	uint8_t * buffer = NULL;
	int buffer_len = 0;

	EVP_CIPHER_CTX * ctx = NULL;

	unsigned long long aad_len_64 = aad_len*8;

	/* Retrieve the tag */
	uint8_t tag[AES_MAX_TAG_SIZE];
	memset(tag, 0, AES_MAX_TAG_SIZE);
	size_t tag_len = AES_MAX_TAG_SIZE;

	if (!(cek && payload && payload_len )) return NULL;
	if (!VALID_KEY_ALG(payload_enc_alg)) return NULL;

	/* Using EVP framework for the sake of simplicity of GCM implementation */
	ctx = EVP_CIPHER_CTX_new();

	/* Number of blocks rounded up */
	buffer_len = ( payload_len / AES_BLOCK_SIZE+1) * AES_BLOCK_SIZE  ;
	buffer = malloc( buffer_len );

	switch (payload_enc_alg) {
		case JOSE_AES_128_GCM:
			tag_len = AES_GCM_TAG_SIZE;

			/* The process is: Init, Update, Final. The framework will append the signature to the end of the output
			 */
			/* Init the algorithm */
			if (!EVP_EncryptInit(ctx, EVP_aes_256_gcm(), cek, iv)) goto cleanup;

			/* AAD is provided bia a call to the EncryptUpdate with the out param set to NULL */
			int sig_len =0;
			if (! EVP_EncryptUpdate(ctx, NULL, &sig_len, aad, aad_len) ) goto cleanup;

			/* Process the payload */
			if (! EVP_EncryptUpdate(ctx, buffer, &buffer_len, payload, payload_len) ) goto cleanup;

			/* Finalize the processing */
			if (!EVP_EncryptFinal(ctx, buffer+buffer_len, &sig_len)) goto cleanup;
			buffer_len += sig_len;
			print_array("\tEncrypted payload: ", buffer, buffer_len, "\n");

			if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag)) goto cleanup;
			print_array("\tTag: ", tag, tag_len, "\n");
		break;

		case JOSE_AES_128_CBC_HS_256:
			/* this is a different process */

			/* ENC key is the second half, MAC is the first half of the CEK*/

			/* Initialize the encryption */
			if (!EVP_EncryptInit(ctx, EVP_aes_128_cbc(), cek + AES_KEY_LENGTH_1 , iv)) goto cleanup;
			/* Set padding to PKCS7 */
			if (!EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7)) goto cleanup;
			/* Encrypt the data */
			if (! EVP_EncryptUpdate(ctx, buffer, &buffer_len, payload, payload_len) ) goto cleanup;
			if (!EVP_EncryptFinal(ctx, buffer+buffer_len, &sig_len)) goto cleanup;
			buffer_len += sig_len;
			print_array("\tEncrypted payload: ", buffer, buffer_len, "\n");

			/* Compute the 64-bit length of the AAD */

			/* The following is fine but prompts a warning */
			aad_len_64 = htonll(aad_len_64);

			print_array("\t\tAAD length: ", (uint8_t*) &aad_len_64, HMAC_AAD_LEN_SIZE, "\n");

			uint8_t* combined_auth_input = NULL; /* AAD || IV || ciphertext || length */
			size_t combined_auth_input_len = aad_len + AES_BLOCK_SIZE /*iv */ + buffer_len /* payload */ + HMAC_AAD_LEN_SIZE;

			combined_auth_input = malloc(combined_auth_input_len);
			uint8_t *p = combined_auth_input;

			memcpy(p, aad, aad_len);
			p+= aad_len;

			memcpy(p, iv, AES_BLOCK_SIZE);
			p+= AES_BLOCK_SIZE;

			memcpy(p, buffer, buffer_len);
			p+= buffer_len;

			memcpy(p, (uint8_t*)&aad_len_64, HMAC_AAD_LEN_SIZE);
			print_array("\t\tAuth input: ", combined_auth_input, combined_auth_input_len, "\n");

			uint8_t hmac_tag[SHA256_OUTPUT_SIZE];
			unsigned int hmac_output_len;
			/* feed into HMAC, using the first half of CEK as the key */

			HMAC(EVP_sha256(), cek, AES_KEY_LENGTH_1, combined_auth_input,
					combined_auth_input_len, hmac_tag, &hmac_output_len);
			print_array("\t\tFull auth tag: ", hmac_tag, hmac_output_len, "\n");
			/* copy the result and free the temp buffer */

			tag_len = AES_HMAC_TAG_SIZE;
			memcpy(tag, hmac_tag, AES_HMAC_TAG_SIZE);
			free( combined_auth_input );

		break;
	}
	/* Allocate the result buffer*/
	result = calloc(BASE64_LEN(buffer_len + tag_len) + 1, sizeof(char)); /* includes the separator dot */

	buffer_len = base64url_encode(buffer, buffer_len, result, BASE64_NO_PADDING);
	result[buffer_len++] = JOSE_SEPARATOR_DOT;
	buffer_len += base64url_encode(tag, tag_len, result+buffer_len, BASE64_NO_PADDING);

	print_array("\tBase64-encoded payload: ", (uint8_t*)result, buffer_len, "\n");

cleanup:
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	if (buffer) free(buffer);
	return result;
}
/**
 * Encrypts the CEK using the given algorithm. At present only RSA OAEP 256 is supported.
 * @param key_protection_alg the algorithm
 * @param cek the Content Encryption Key
 * @param cek_len the CEK length.
 * @param kek_dat points to the structure corresponding to the algorithm. In our case it is only RSA_PARAMS.
 * @result the string with base64 encoding of the encrypted cek. It is caller's responsibility to free the memory.
 */
static char * jose_encrypt_cek(uint8_t key_protection_alg, uint8_t *cek, size_t cek_len, void *kek_data) {
	char * buffer = NULL;
	RSA_PARAMS *rsa_params;
	RSA *rsa  = NULL;
	uint8_t * encrypted_cek = NULL;

	if (!(cek && cek_len)) return NULL;

	if (!VALID_KEY_ALG(key_protection_alg)) return NULL;

	/* encrypt the CEK */
	switch (key_protection_alg){
	case JOSE_RSA_OAEP_256:
		/* the only one currently supported */
		rsa_params = (RSA_PARAMS*) kek_data;
		rsa = RSA_new();

		/* Freeing the RSA structure will also free the BNs, so we should make a copy of the input parameters */
		BIGNUM * n = BN_new();
		BN_copy(n, rsa_params->n);
		BIGNUM * e = BN_new();
		BN_copy(e, rsa_params->e);

		if (RSA_set0_key(rsa, n, e, NULL)!=ERR_LIB_NONE)
			goto cleanup;

		encrypted_cek = malloc(RSA_size(rsa));

		size_t encrypted_cek_len = RSA_public_encrypt(cek_len, cek, encrypted_cek, rsa, RSA_PKCS1_OAEP_PADDING);
		/* the encrypted value is ready */
		print_array("\tEncrypted CEK: ", encrypted_cek, encrypted_cek_len, "\n");

#ifdef RFC_5716_TEST
		buffer = calloc(BASE64_LEN(sizeof(test_enc_cek)), sizeof(char));
		base64url_encode(test_enc_cek, sizeof(test_enc_cek), buffer, BASE64_NO_PADDING);
#else
		buffer = calloc(BASE64_LEN(encrypted_cek_len), sizeof(char));
		base64url_encode(encrypted_cek, encrypted_cek_len, buffer, BASE64_NO_PADDING);
#endif
		break;
	}

cleanup:

	/* Handle errors */
	if (rsa) RSA_free(rsa);
	if (encrypted_cek) free(encrypted_cek);
	return buffer;
}

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
char* jose_create_jwe(uint8_t key_protection_alg, uint8_t payload_enc_alg,
		uint8_t *cek, size_t cek_len,
		void *kek_data,
		uint8_t *iv, size_t iv_len,
		uint8_t *payload, size_t payload_len) {

	char * jwe_protected_header = NULL;
	char * jwe_encrypted_key = NULL;
	char * jwe_iv = NULL;
	char * jwe_payload = NULL;

	char * result = NULL;
	size_t result_len = 0;

	char * jwe_protected_header_raw;
	size_t jwe_protected_header_len = 0;

	/* validate inputs */
	if (!(payload && payload_len) || TOO_BIG(payload_len)) return NULL;

	if (!VALID_KEY_ALG(key_protection_alg) || !VALID_KEY_ALG(payload_enc_alg)) return NULL;

	/* estimate header length. Since we currently only support alg + enc, this is JSON_OVERHEAD_KEY */
	jwe_protected_header_len = JSON_OVERHEAD_KEY;
	jwe_protected_header_raw = calloc(jwe_protected_header_len, sizeof(char));

	/* the jwe_protected_header_len is now corrected to reflect the actual length */

	jwe_protected_header_len = sprintf(jwe_protected_header_raw, "{" JSON_ENTRY_TEMPLATE "," JSON_ENTRY_TEMPLATE "}",
			JOSE_TAG_ALG, table_alg[key_protection_alg], JOSE_TAG_ENC, table_alg[payload_enc_alg]);

	/* reallocation and reusing pointers since we only need this data in the BASE64-encoded way*/
	jwe_protected_header = calloc(BASE64_LEN(jwe_protected_header_len), sizeof(char));
	jwe_protected_header_len = base64url_encode(
			(uint8_t*) jwe_protected_header_raw, jwe_protected_header_len,
			jwe_protected_header, BASE64_NO_PADDING);

	free(jwe_protected_header_raw);

	/* The protected header after the BASE64 encoding plus the separator dot */
	result_len = jwe_protected_header_len +1;

	/* Prepare the encrypted key */
	jwe_encrypted_key = jose_encrypt_cek(key_protection_alg, cek, cek_len, kek_data);
	/* The encrypted CEK after the BASE64 encoding plus the separator dot */
	result_len += strlen(jwe_encrypted_key) + 1;

	/* Prepare the IV*/
	jwe_iv = calloc(BASE64_LEN(iv_len), sizeof(char));

	result_len += base64url_encode(iv, iv_len, jwe_iv, BASE64_NO_PADDING) +1;

	jwe_payload = jose_encrypt_payload(payload_enc_alg, cek, iv,
			(uint8_t*) jwe_protected_header, jwe_protected_header_len, payload,
			payload_len);
	if (jwe_payload)
		result_len += strlen(jwe_payload);

	result = calloc(result_len+1, sizeof(char));
	sprintf(result, "%s%c%s%c%s%c%s", jwe_protected_header, JOSE_SEPARATOR_DOT,
			jwe_encrypted_key, JOSE_SEPARATOR_DOT, jwe_iv, JOSE_SEPARATOR_DOT,
			jwe_payload);

	/* free the memory */
	if (!jwe_protected_header) free(jwe_protected_header);
	if (!jwe_encrypted_key) free(jwe_encrypted_key);
	if (!jwe_payload) free(jwe_payload);
	if (!jwe_iv) free(jwe_payload);

	return result;

}
