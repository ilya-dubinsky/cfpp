#include "emv.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "crypto.h"
#include "bits.h"
#include "payments.h"

#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include "test_io.h"

#define EMV_OPTION_A_MAX_PAN_LEN 16

typedef struct tag_CA_PUBLIC_KEY {
	uint8_t index;
	uint8_t modulus[248];
	size_t modulus_len;
	uint32_t public_exponent;
} CA_PUBLIC_KEY;

CA_PUBLIC_KEY pk_table[] = {
		{
				0x92,
				{ 0x99, 0x6A, 0xF5, 0x6F, 0x56, 0x91, 0x87,
		0xD0, 0x92, 0x93, 0xC1, 0x48, 0x10, 0x45, 0x0E, 0xD8, 0xEE, 0x33, 0x57,
		0x39, 0x7B, 0x18, 0xA2, 0x45, 0x8E, 0xFA, 0xA9, 0x2D, 0xA3, 0xB6, 0xDF,
		0x65, 0x14, 0xEC, 0x06, 0x01, 0x95, 0x31, 0x8F, 0xD4, 0x3B, 0xE9, 0xB8,
		0xF0, 0xCC, 0x66, 0x9E, 0x3F, 0x84, 0x40, 0x57, 0xCB, 0xDD, 0xF8, 0xBD,
		0xA1, 0x91, 0xBB, 0x64, 0x47, 0x3B, 0xC8, 0xDC, 0x9A, 0x73, 0x0D, 0xB8,
		0xF6, 0xB4, 0xED, 0xE3, 0x92, 0x41, 0x86, 0xFF, 0xD9, 0xB8, 0xC7, 0x73,
		0x57, 0x89, 0xC2, 0x3A, 0x36, 0xBA, 0x0B, 0x8A, 0xF6, 0x53, 0x72, 0xEB,
		0x57, 0xEA, 0x5D, 0x89, 0xE7, 0xD1, 0x4E, 0x9C, 0x7B, 0x6B, 0x55, 0x74,
		0x60, 0xF1, 0x08, 0x85, 0xDA, 0x16, 0xAC, 0x92, 0x3F, 0x15, 0xAF, 0x37,
		0x58, 0xF0, 0xF0, 0x3E, 0xBD, 0x3C, 0x5C, 0x2C, 0x94, 0x9C, 0xBA, 0x30,
		0x6D, 0xB4, 0x4E, 0x6A, 0x2C, 0x07, 0x6C, 0x5F, 0x67, 0xE2, 0x81, 0xD7,
		0xEF, 0x56, 0x78, 0x5D, 0xC4, 0xD7, 0x59, 0x45, 0xE4, 0x91, 0xF0, 0x19,
		0x18, 0x80, 0x0A, 0x9E, 0x2D, 0xC6, 0x6F, 0x60, 0x08, 0x05, 0x66, 0xCE,
		0x0D, 0xAF, 0x8D, 0x17, 0xEA, 0xD4, 0x6A, 0xD8, 0xE3, 0x0A, 0x24, 0x7C,
		0x9F },
		176,
		0x03 },
		{
				0xFA,
				{ 0xA9, 0x0F, 0xCD, 0x55, 0xAA, 0x2D, 0x5D,
		0x99, 0x63, 0xE3, 0x5E, 0xD0, 0xF4, 0x40, 0x17, 0x76, 0x99, 0x83, 0x2F,
		0x49, 0xC6, 0xBA, 0xB1, 0x5C, 0xDA, 0xE5, 0x79, 0x4B, 0xE9, 0x3F, 0x93,
		0x4D, 0x44, 0x62, 0xD5, 0xD1, 0x27, 0x62, 0xE4, 0x8C, 0x38, 0xBA, 0x83,
		0xD8, 0x44, 0x5D, 0xEA, 0xA7, 0x41, 0x95, 0xA3, 0x01, 0xA1, 0x02, 0xB2,
		0xF1, 0x14, 0xEA, 0xDA, 0x0D, 0x18, 0x0E, 0xE5, 0xE7, 0xA5, 0xC7, 0x3E,
		0x0C, 0x4E, 0x11, 0xF6, 0x7A, 0x43, 0xDD, 0xAB, 0x5D, 0x55, 0x68, 0x3B,
		0x14, 0x74, 0xCC, 0x06, 0x27, 0xF4, 0x4B, 0x8D, 0x30, 0x88, 0xA4, 0x92,
		0xFF, 0xAA, 0xDA, 0xD4, 0xF4, 0x24, 0x22, 0xD0, 0xE7, 0x01, 0x35, 0x36,
		0xC3, 0xC4, 0x9A, 0xD3, 0xD0, 0xFA, 0xE9, 0x64, 0x59, 0xB0, 0xF6, 0xB1,
		0xB6, 0x05, 0x65, 0x38, 0xA3, 0xD6, 0xD4, 0x46, 0x40, 0xF9, 0x44, 0x67,
		0xB1, 0x08, 0x86, 0x7D, 0xEC, 0x40, 0xFA, 0xAE, 0xCD, 0x74, 0x0C, 0x00,
		0xE2, 0xB7, 0xA8, 0x85, 0x2D },
		144,
		0x03
		}
};

/* locates the CA PK in the CA PK repository by index */
CA_PUBLIC_KEY* find_ca_pk (uint8_t index) {
	for (size_t i = 0; i<sizeof(pk_table)/sizeof(pk_table[0]); i++)
		if (pk_table[i].index == index)
			return pk_table +i;
	return NULL;
}

/* prints the issuer PK details header */
void print_issuer_pk_details_header(ISSUER_PK_DETAILS_HEADER* header) {
	if (!header)
		return;
	printf("Header sentinel (always 6A): %02X\n", header->sentinel);
	printf("Certificate format (always 02): %02X\n", header->certificate_format);
	print_array("Issuer identifier (right-padded with FF): ", header->issuer_identifier, 4, "\n");
	print_array("Certificate expiration MMYY: ", header->certificate_expiration, 2, "\n");
	print_array("Certificate serial: ", header->certificate_serial, 3, "\n");
	printf("Hash algorithm: %02X\n", header->hash_algo);
	printf("Issuer PK algorithm: %02X\n", header->issuer_pk_algo);
	printf("Issuer PK length: %d\n", header->issuer_pk_len);
	printf("Issuer PK exponent length: %d\n", header->issuer_pk_exponent_len);
}

/**
 * Recovers the issuer key from EMV tags
 * @param ca_pk_idx Index of the CA Public Key
 * @param issuer_pk_cert Issuer public key certificate
 * @param issuer_pk_cert_len Length of the issuer public key certificate
 * @param issuer_pk_remainder Remainder of the issuer public key
 * @param issuer_pk_remainder_len Length of the issuer public key remainder
 * @param issuer_pk_exponent Value of the exponent of the issuer key, can be either 3 or 65537 only
 * @param recovered_key_buf If not NULL, the function will copy the recovered key into the buffer
 * @param details_header If not NULL, the function will copy issuer PK header details there
 * @result -1 if error, or length of the key recovered
 */
int recover_issuer_key(uint8_t ca_pk_idx, uint8_t *issuer_pk_cert,
		size_t issuer_pk_cert_len, uint8_t *issuer_pk_remainder,
		size_t issuer_pk_remainder_len, uint32_t issuer_pk_exponent, uint8_t *recovered_key_buf, ISSUER_PK_DETAILS_HEADER* details_header) {

	//TODO: handle padding/unpadding by 0xBB
	//TODO: handle empty remainder
	if (!(issuer_pk_cert && issuer_pk_remainder))
		return -1; /* TODO replace with a #define */
	/* internal variables */
	CA_PUBLIC_KEY * ca_pk = NULL;
	int retval = EMV_SUCCESS;

	/* buffer for the combined key */
	uint8_t combined_key[4096];
	memset( combined_key, 0, sizeof(combined_key));

	/* buffer for the hash function */
	uint8_t hash_function_input[4096];
	memset( hash_function_input, 0, sizeof(hash_function_input));

	/* buffer for the hash value */
	uint8_t hash_buffer[SHA_DIGEST_LENGTH];
	memset (hash_buffer, 0, SHA_DIGEST_LENGTH);

	/* error handling */
	unsigned long error_code;
	char error_message_buffer[4096];

	/* rsa objects */
	BIGNUM * public_exponent = NULL, *modulus = NULL;
	RSA * rsa = NULL;

	/* Try to locate the CA public key by its index */
	ca_pk = find_ca_pk(ca_pk_idx);
	if (!ca_pk) goto cleanup;
	/* We found a public key, now we can instantiate the RSA structure around it */

	/* first, prepare the public exponent part */
	public_exponent = BN_new();

	if (!public_exponent) goto cleanup;

	if (BN_set_word(public_exponent, ca_pk->public_exponent)!=ERR_LIB_NONE)
		goto cleanup;

	/* now load the modulus */
	modulus = BN_new();

	if (!modulus) goto cleanup;

	if (BN_bin2bn( (unsigned char*)&ca_pk->modulus, ca_pk->modulus_len, modulus)==NULL)
		goto cleanup;

	/* both numbers are represented as BIGNUMs, time to instantiate an RSA structure */
	rsa = RSA_new();
	if (!rsa) goto cleanup;

	/* set the modulus and the public exponent as parts of the RSA struct */
	if (RSA_set0_key(rsa, modulus, public_exponent, NULL)!=ERR_LIB_NONE)
		goto cleanup;

	/* prepare the output buffer */
	uint8_t to[4096]; //TODO make the 4096 a calculated maximum
	memset(to ,0, sizeof(to));

	int recovered_size = RSA_public_decrypt(issuer_pk_cert_len, issuer_pk_cert, to, rsa, RSA_NO_PADDING ) ;

	/* decrypt the key part */
	if (recovered_size<0)
		goto cleanup;

	print_array("Recovered issuer key raw data: ", to, recovered_size, "\n");

	/* check the sentinels */
	if ( !(EMV_SIGNATURE_B == to[0] && EMV_SIGNATURE_E == to[recovered_size-1])) /* sentinel bytes are invalid */
	{
		retval = EMV_ERROR;
		printf ("Sentinel value check failed\n");
	}
	/* parse the key */
	ISSUER_PK_DETAILS_HEADER *header = (ISSUER_PK_DETAILS_HEADER*) to;

	printf("Key data header:\n");

	print_issuer_pk_details_header(header);
	/* combine the key */
	/* copy the first part */
	memcpy(combined_key, to+sizeof(ISSUER_PK_DETAILS_HEADER), recovered_size-SHA_DIGEST_LENGTH-sizeof(ISSUER_PK_DETAILS_HEADER)-1);
	memcpy(combined_key + recovered_size-SHA_DIGEST_LENGTH-sizeof(ISSUER_PK_DETAILS_HEADER)-1, issuer_pk_remainder, issuer_pk_remainder_len);

	print_array("Combined key: ", combined_key, header->issuer_pk_len, "\n");

	printf("Combined key size: %d\n", header->issuer_pk_len);

	/* check the hash value */
	/* For that, we concatenate the header values from Certificate Format to the end,
	 * then the deciphered PK part, then the remainder and finally the exponent */
	size_t hash_buffer_ptr = 0; /* tracks the position in the hash buffer for convenience */
	memcpy(hash_function_input, &header->certificate_format, (hash_buffer_ptr+= sizeof(ISSUER_PK_DETAILS_HEADER)-1) );
	memcpy(hash_function_input+hash_buffer_ptr, combined_key,  header->issuer_pk_len);
	hash_buffer_ptr+= header->issuer_pk_len;

	/* the exponent is either 3 or 65537, i.e. either 1 or 3 bytes */
	if (header->issuer_pk_exponent_len==1) {
		hash_function_input[hash_buffer_ptr++] = issuer_pk_exponent;
	}
	else {
		hash_function_input[hash_buffer_ptr++] = 1;
		hash_function_input[++hash_buffer_ptr] = 1;
	}

	print_array("Hash function input: ", hash_function_input, hash_buffer_ptr, "\n");

	SHA1(hash_function_input, hash_buffer_ptr, hash_buffer);

	print_array("Key hash as computed: ", hash_buffer, SHA_DIGEST_LENGTH, "\n");
	print_array("Key hash as provided: ", to + recovered_size-SHA_DIGEST_LENGTH-1, SHA_DIGEST_LENGTH, "\n");

	if (memcmp(hash_buffer, to + recovered_size-SHA_DIGEST_LENGTH-1, SHA_DIGEST_LENGTH)) {
		/* the signature didn't match */
		retval = EMV_ERROR;
		goto cleanup;
	}
	/* copy outputs if pointers for them were provided */
	if (recovered_key_buf!=NULL)
		memcpy(recovered_key_buf, combined_key, header->issuer_pk_len);
	retval = header->issuer_pk_len;

	if (details_header != NULL)
		memcpy(details_header, header, sizeof(ISSUER_PK_DETAILS_HEADER) );

cleanup:
	error_code = ERR_get_error();
	if (error_code) {
		ERR_error_string(error_code, error_message_buffer);
		printf("ERROR: %s\n", error_message_buffer);
		retval = EMV_ERROR;
	}
	RSA_free(rsa); /* since both BNs we've allocated were assigned into the RSA struct, freeing it will free them too */
	return retval;
}

int derive_icc_master_key_aes(uint8_t *unpacked_input, size_t unpacked_input_len,
		uint8_t *encryption_key, size_t encryption_key_len, uint8_t *output, size_t output_len);

int derive_icc_master_key_des(uint8_t *unpacked_input, size_t unpacked_input_len,
		uint8_t *encryption_key, uint8_t *output, size_t output_len);

/**
 * Derive ICC Master key from an IMK
 * @param unpacked_pan unpacked BCD pan
 * @param unpacked_pan_len length of the pan
 * @param unpacked_csn unpacked CSN
 * @param encryption_key encryption key
 * @param encryption_Key_len length of the encryption key
 * @param algorithm, ALGORITHM_TDES or ALGORITHM_AES
 * @param output output buffer
 * @param output_len length of the output buffer
 */
int derive_icc_master_key(uint8_t *unpacked_pan, size_t unpacked_pan_len, uint8_t *unpacked_csn,
		uint8_t *encryption_key, size_t encryption_key_len, int algorithm,  uint8_t *output, size_t output_len) {
	if (! (unpacked_pan && unpacked_pan_len && output && output_len && encryption_key && encryption_key_len))
		return EMV_ERROR;
	/* validate the input */
	if (!PAN_LENGTH_VALID(unpacked_pan_len))
		return EMV_ERROR;

	algorithm &= 0x1; /* sanitize the input */
	size_t key_size = encryption_key_len;
	/* validate the key length */
	if (ALGORITHM_TDES == algorithm) {
		if (key_size != TDES_KEY_LENGTH_2) return EMV_ERROR;
	} else if (ALGORITHM_AES == algorithm) {
		if (!VALID_AES_KEY_SIZE(key_size)) return EMV_ERROR;
	}

	uint8_t unpacked_input[MAX_PAN_LENGTH + CSN_LENGTH ];
	memcpy(unpacked_input, unpacked_pan, unpacked_pan_len);

	/* csn is optional */
	if (unpacked_csn)
		memcpy(unpacked_input+unpacked_pan_len, unpacked_csn, CSN_LENGTH);

	print_array("Unpacked input: ", unpacked_input, MAX_PAN_LENGTH + CSN_LENGTH, "\n");

	if (ALGORITHM_AES == algorithm) {
		return derive_icc_master_key_aes(unpacked_input, unpacked_pan_len+CSN_LENGTH, encryption_key, encryption_key_len, output, output_len);
	}
	else {
		return derive_icc_master_key_des(unpacked_input, unpacked_pan_len+CSN_LENGTH, encryption_key, output, output_len);
	}

}

int derive_icc_master_key_aes(uint8_t *unpacked_input, size_t unpacked_input_len,
		uint8_t *encryption_key, size_t encryption_key_len, uint8_t *output, size_t output_len) {
	return EMV_ERROR; /* TODO not implemented yet */
}

int derive_icc_master_key_des(uint8_t *unpacked_input, size_t unpacked_input_len,
		uint8_t *encryption_key, uint8_t *output, size_t output_len) {
	/* prepare the encryption input */
	uint8_t enc_input[TDES_BLOCK_SIZE<<1];
	memset(enc_input, 0, TDES_BLOCK_SIZE<<1);

	unsigned long error_code;
	/* Option A is for PANs under 16 digits, i.e. of total length <= 18
	 * Option B is for longer values
	 */
	if (unpacked_input_len<= EMV_OPTION_A_MAX_PAN_LEN + CSN_LENGTH) /* Option A */ {
		if (unpacked_input_len <= TDES_BLOCK_SIZE<<1)
			/* pack with right padding */
			pack_bcd(unpacked_input, unpacked_input_len, enc_input, TDES_BLOCK_SIZE, PAD_RIGHT);
		else {
			/* pack while skipping the extra digits from the left */
			pack_bcd(unpacked_input + (unpacked_input_len- (TDES_BLOCK_SIZE<<1)), TDES_BLOCK_SIZE<<1, enc_input, TDES_BLOCK_SIZE, PAD_RIGHT);
		}
	}
	else {
		printf("Option B\n");
		/* pack with left padding by 1 nibble if odd */
		pack_bcd(unpacked_input, unpacked_input_len, enc_input,  (unpacked_input_len+1)>>1,  PAD_LEFT);
		print_array("Packed input: ", enc_input, TDES_BLOCK_SIZE<<1, "\n");
		uint8_t hash_output[SHA_DIGEST_LENGTH];
		SHA1((unsigned char*)enc_input, (unpacked_input_len+1)>>1, (unsigned char*)&hash_output);

		error_code = ERR_get_error();
		if (error_code)
			return EMV_ERROR;

		print_array("Hash output: ", hash_output, SHA_DIGEST_LENGTH, "\n");
		uint8_t hash_decimalized_unpacked[TDES_BLOCK_SIZE<<1];

		decimalize_vector(hash_output, 2*SHA_DIGEST_LENGTH, hash_decimalized_unpacked, TDES_BLOCK_SIZE<<1);
		print_array("Decimalized output: ", hash_decimalized_unpacked, TDES_BLOCK_SIZE<<1, "\n");

		memset(enc_input, 0, TDES_BLOCK_SIZE<<1);
		pack_bcd(hash_decimalized_unpacked, TDES_BLOCK_SIZE<<1, enc_input, TDES_BLOCK_SIZE, PAD_RIGHT);
	}

	print_array("Encryption input: ", enc_input, TDES_BLOCK_SIZE, "\n");

	DES_key_schedule key_a, key_b;
	DES_set_key_unchecked( (const_DES_cblock *)encryption_key, &key_a);
	DES_set_key_unchecked( (const_DES_cblock *) (encryption_key+(TDES_KEY_LENGTH_1)), &key_b);

	DES_ecb2_encrypt( (DES_cblock*) enc_input, (DES_cblock*)output, &key_a, &key_b, DES_ENCRYPT);
	error_code = ERR_get_error();
	if (error_code)
		return EMV_ERROR;

	print_array("First half: ", output, TDES_BLOCK_SIZE, "\n");

	for (size_t i=0; i<sizeof(enc_input); i++)
		enc_input[i]^=0xFF;

	print_array("Second input: ", enc_input, TDES_BLOCK_SIZE, "\n");
	DES_ecb2_encrypt( (DES_cblock*) enc_input, (DES_cblock*) (output+TDES_BLOCK_SIZE), &key_a, &key_b, DES_ENCRYPT);
	error_code = ERR_get_error();
	if (error_code)
		return EMV_ERROR;

	print_array("Second half: ", output+TDES_BLOCK_SIZE, TDES_BLOCK_SIZE, "\n");
	fix_parity(output, output_len, PARITY_ODD);

	print_array("Final ICC Master key: ", output, output_len, "\n");

	return EMV_SUCCESS;
}

int derive_icc_session_key(uint8_t *icc_master_key,
		size_t icc_master_key_length, int algorithm, uint8_t *atc, uint8_t *output,
		size_t output_len){

	uint8_t magic_number[2] = {0xF0, 0x0F};
	unsigned long error_code = 0;

	/* validate inputs */
	if (! (icc_master_key && icc_master_key_length && atc && output && output_len))
		return EMV_ERROR;

	algorithm &= 0x1;

	/* check output length */
	if (algorithm==ALGORITHM_TDES && output_len!= TDES_KEY_LENGTH_2)
		return EMV_ERROR;
	if (algorithm==ALGORITHM_AES && !VALID_AES_KEY_SIZE(output_len))
		return EMV_ERROR;

	uint8_t output_data[2*AES_BLOCK_SIZE];
	memset(output_data, 0, sizeof(output_data));

	uint8_t input_data[AES_BLOCK_SIZE];
	memset(input_data, 0, AES_BLOCK_SIZE);
	memcpy(input_data, atc, EMV_ATC_LENGTH);

	for (int i =0; i<2; i++) {
		input_data[EMV_ATC_LENGTH] = magic_number[i];
		printf("Iteration %d\n", i+1);

		print_array("Input data for encryption: ", input_data, TDES_BLOCK_SIZE, "\n");
		if (algorithm==ALGORITHM_TDES)
		{
			DES_key_schedule key_a, key_b;
			DES_set_key_unchecked( (const_DES_cblock *) icc_master_key, &key_a);
			DES_set_key_unchecked( (const_DES_cblock *) (icc_master_key+(TDES_KEY_LENGTH_1)), &key_b);

			DES_ecb2_encrypt( (DES_cblock*) input_data, (DES_cblock*)(output_data + (i*TDES_BLOCK_SIZE)), &key_a, &key_b, DES_ENCRYPT);

			print_array("Encryption output: ", output_data + (i*TDES_BLOCK_SIZE), TDES_BLOCK_SIZE, "\n");

			error_code = ERR_get_error();
			if (error_code)
				return EMV_ERROR;
		}
		fix_parity(output_data, TDES_BLOCK_SIZE*2, PARITY_ODD);
	}
	memcpy(output, output_data, output_len);
	return EMV_SUCCESS;
}

