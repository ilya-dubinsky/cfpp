#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "tr31.h"
#include "bits.h"
#include "crypto.h"
#include "test_io.h"

#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/err.h>


/* Readability constant string lists */
const char * tr31_algorithm_name[] = {
	"Double-length TDES",
	"Triple-length TDES",
	"AES-128",
	"AES-192",
	"AES-256"
};

const char * tr31_usage[] = {
	"Encryption",
	"Authentication"
};


/* Key length lookup arrays, in bits and bytes */
static size_t bit_key_length[] = /* Using the fact that key algorithms are numbered sequentially, 0 to 4*/
				{ TDES_KEY_LENGTH_2 *8, 	/* 0x0000 */
				  TDES_KEY_LENGTH_3 *8, 	/* 0x0001 */
				  AES_KEY_LENGTH_1 *8, 		/* 0x0002 */
				  AES_KEY_LENGTH_2 *8, 		/* 0x0003 */
				  AES_KEY_LENGTH_3 *8, 		/* 0x0004 */
				};

static size_t key_length[] =
				{ TDES_KEY_LENGTH_2, 	/* 0x0000 */
				  TDES_KEY_LENGTH_3, 	/* 0x0001 */
				  AES_KEY_LENGTH_1, 		/* 0x0002 */
				  AES_KEY_LENGTH_2, 		/* 0x0003 */
				  AES_KEY_LENGTH_3, 		/* 0x0004 */
				};

/* Encryption algorithm lookup array */
typedef const EVP_CIPHER* (*evp_cipher_fp) (void);

static evp_cipher_fp algo_impl[] = /* algorithm implementations based on the ID */
				{
					EVP_des_ede,
					EVP_des_ede3,
					EVP_aes_128_ecb,
					EVP_aes_192_ecb,
					EVP_aes_256_ecb
				};
/** Populates the data in the key derivation base structure, conscious of byte order
 *  @param base the struct to populate
 *  @param counter the counter value
 *  @key_usage key usage (encryption or MAC)
 *  @algorithm algorithm (a flavor of TDES or AES)
 *  @length desired key length
 *  @result TR31_OK if ok, TR31_ERROR otherwise
 */
int tr31_prepare_key_derivation(TR31_KEY_DERIVATION_BASE * base, uint8_t counter, uint16_t key_usage, uint16_t algorithm ) {
	int result = TR31_ERROR;
	/* populate and validate the struct */
	if (!base) return result;

	base->counter = counter;

	if (! VALID_KEY_USAGE(key_usage)) return TR31_ERROR;
	*(uint16_t*) &base->key_usage = HTONS(key_usage);

	base->separator = TR31_SEPARATOR;

	if (! VALID_ALGORITHM(algorithm) )
		return TR31_ERROR;

	*(uint16_t*) &base->algorithm = HTONS(algorithm);

	*(uint16_t*) &base->length = HTONS(bit_key_length [algorithm]);

	result = TR31_OK;
	return result;
}

static uint8_t variant_mask [] = { 0x45 /* 'E' */, 0x4D /* 'M' */ };

/** Derives encryption/MAC keys using the variant method.
 *  @param kbpk 		Key Block Protection Key
 *  @param kbpk_size 	Length of the KBPK, can be either double or triple TDES.
 *  @param key_usage	Defines key usage, TR31_KEY_USAGE_ENC or TR31_KEY_USAGE_MAC
 *  @param output  		Output buffer, must be same length as the KBPK
 *  @result TR31_OK if OK, TR31_ERROR otherwise
 */
int tr31_derive_variant( uint8_t * kbpk, size_t kbpk_size, uint8_t key_usage, uint8_t * output ) {
	/* validate inputs */
	if (!(kbpk && kbpk_size && output)) return TR31_ERROR;

	if (!( TR31_KEY_USAGE_ENC == key_usage || TR31_KEY_USAGE_MAC == key_usage )) return TR31_ERROR;

	if (!(TDES_KEY_LENGTH_2 == kbpk_size || TDES_KEY_LENGTH_3 == kbpk_size )) return TR31_ERROR;

	/* apply the mask */
	for (size_t i=0; i < kbpk_size; i++)
		output[i] = kbpk[i] ^ variant_mask[key_usage];

	return TR31_OK;
}

/**
 * Derives keys in the binding mode, according to ANSI TR-31, by calculating
 * CMAC with the specified block cipher on an input vector as defined in TR31_KEY_DERIVATION_BASE.
 *
 * @param key_usage Derived key usage, TR31_KEY_USAGE_ENC or TR31_KEY_USAGE_MAC
 * @param derivation_algorithm Derivation algorithm, double or triple TDES, or an AES flavor
 * @param output Buffer for the derived key of sufficient length
 * @result returns TR31_OK on success or TR31_ERROR otherwise
 */
int tr31_derive_binding(uint16_t key_usage, uint16_t derivation_algorithm, uint8_t * kbpk, uint8_t* output) {

	char error_message_buffer[4096];
	unsigned long error_code = 0;

	int result = TR31_ERROR;
	TR31_KEY_DERIVATION_BASE base;
	uint8_t output_buffer[AES_BLOCK_SIZE];

	CMAC_CTX * cmac_ctx = NULL;

	/* validate the inputs*/
	if (! (kbpk && output)) goto cleanup;
	if (!VALID_KEY_USAGE(key_usage)) goto cleanup;
	if (!VALID_ALGORITHM(derivation_algorithm)) goto cleanup;

	size_t output_position = 0;
	uint8_t counter = 1;

	cmac_ctx = CMAC_CTX_new();


	while (output_position < key_length[derivation_algorithm]) { /* while necessary number of bits is not ready yet */
		size_t cmac_out_len;

		if (tr31_prepare_key_derivation(&base, counter, key_usage, derivation_algorithm)) goto cleanup;
		/* base is ready, now we CMAC */

		print_array("\t\tInput value: ", (uint8_t *)&base, TR31_KEY_DERIVATION_BASE_SIZE, "\n");

		/* Init the CMAC */
		if (!CMAC_Init(cmac_ctx, kbpk, key_length[derivation_algorithm],
				algo_impl[derivation_algorithm](), NULL)) goto cleanup;

		/* Calculate the value */
		if (!CMAC_Update(cmac_ctx, &base, TR31_KEY_DERIVATION_BASE_SIZE)) goto cleanup;

		/* Finalize the computation */
		if (!CMAC_Final(cmac_ctx, output_buffer, &cmac_out_len)) goto cleanup;

		print_array("\t\tIteration output: ", output_buffer, cmac_out_len, "\n");

		/* now copy from the output buffer to the output */
		size_t to_copy = (output_position + cmac_out_len) >  key_length[derivation_algorithm] ?
				key_length[derivation_algorithm]-output_position
				: cmac_out_len;
		memcpy(output+output_position, output_buffer, to_copy);
		/* advance counters */
		counter++;
		output_position+= to_copy;
	}


cleanup:

	/* Handle OpenSSL errors */
	error_code = ERR_get_error();
	if (error_code) {
		ERR_error_string(error_code, error_message_buffer);
		printf("ERROR: %s\n", error_message_buffer);
	}

	if (cmac_ctx) CMAC_CTX_free(cmac_ctx);
	PURGE(output_buffer);
	return result;
}
