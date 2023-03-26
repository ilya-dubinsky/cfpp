#include "emv.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/err.h>

#include <netinet/in.h>

#include "crypto.h"
#include "bits.h"
#include "payments.h"
#include "test_io.h"


#define EMV_OPTION_A_MAX_PAN_LEN 16

#define EMV_PK_PADDING 0xBB

#define EMV_CERTIFICATE_FORMAT_ISSUER_KEY	 0x02
#define EMV_CERTIFICATE_FORMAT_SDA	 		 0x03
#define EMV_CERTIFICATE_FORMAT_ICC_KEY	 	 0x04
#define EMV_CERTIFICATE_FORMAT_DDA	 		 0x05

#define EMV_HASH_ALGORITHM_SHA1				 0x01

#define EMV_PK_ALGORIHTM_RSA  				 0x01

#define EMV_ARQC_PADDING					 0x80


typedef struct tag_CA_KEY {
	uint8_t index;
	uint8_t modulus[EMV_MAX_CA_KEY_SIZE+1];
	size_t modulus_len;
	uint32_t public_exponent;
	uint8_t private_exponent[EMV_MAX_CA_KEY_SIZE+1];
	size_t private_exponent_len;
} CA_KEY;

static CA_KEY ca_key_table[] = {
		{
			0x01,
			{ 0xc3, 0x39, 0xcd, 0x81, 0x3e, 0xbe,
		0xab, 0xaf, 0xd4, 0xcb, 0x37, 0x11, 0x06, 0xb0, 0x03, 0x3e, 0x96, 0x72,
		0x03, 0x79, 0x93, 0x71, 0x55, 0xd8, 0x33, 0x37, 0x5d, 0x83, 0x3f, 0x00,
		0x2b, 0xc6, 0x0f, 0xa3, 0x7e, 0x18, 0xd5, 0xdd, 0x7b, 0x88, 0x02, 0xa1,
		0xf5, 0x8f, 0x4d, 0x62, 0xc6, 0x36, 0x7a, 0x1f, 0x3a, 0x9c, 0x0b, 0xa4,
		0xbb, 0x00, 0x57, 0xf5, 0xf3, 0x3e, 0x89, 0x14, 0xb4, 0xf9, 0x0e, 0xb7,
		0x56, 0x85, 0xe5, 0xbf, 0x8e, 0x17, 0x33, 0x5a, 0x55, 0x68, 0xbc, 0x18,
		0xa8, 0x72, 0x0d, 0xa3, 0x3c, 0x8e, 0x79, 0x4c, 0xe1, 0x4f, 0xb3, 0xa3,
		0xe7, 0xd5, 0xd0, 0x5e, 0x58, 0xf9, 0x00, 0x62, 0x16, 0xb0, 0xd8, 0xf8,
		0x4a, 0x06, 0x54, 0xfb, 0x9c, 0x10, 0x09, 0xd6, 0xe7, 0xb0, 0x6a, 0xe6,
		0xeb, 0xb4, 0x9a, 0xd4, 0xb1, 0x37, 0x55, 0x5b, 0x0b, 0x04, 0x8f, 0xc8,
		0xdc, 0x99, 0x23, 0x9c, 0x7f, 0x4c, 0x22, 0x5c, 0xce, 0xbf, 0xb7, 0x66,
		0x7f, 0xd9, 0x09, 0x10, 0x43, 0x7c, 0x7f, 0xe8, 0xe7, 0xae, 0x83, 0x15,
		0x75, 0x1a, 0xeb, 0xa6, 0xab, 0xd6, 0xed, 0x35, 0x74, 0x91, 0x7b, 0xb8,
		0xf6, 0x52, 0x6b, 0xbb, 0xfb, 0x30, 0x60, 0x73, 0xaa, 0x49, 0x3a, 0x18,
		0xff, 0x04, 0x6f, 0xf9, 0x9e, 0xff, 0xfe, 0x13, 0x42, 0x67, 0x65, 0xf4,
		0x9b, 0x80, 0xf1, 0x34, 0x6f, 0xbc, 0xd7, 0xd6, 0x6b, 0x1c, 0x44, 0x86,
		0x49, 0x72, 0x2c, 0xed, 0x53, 0xe8, 0x66, 0xc6, 0x82, 0xe3, 0x68, 0x1d,
		0x98, 0xc8, 0xf2, 0x9e, 0xff, 0xcd, 0x29, 0x84, 0x24, 0x53, 0xf2, 0x60,
		0x81, 0xb3, 0xa4, 0xb0, 0xd3, 0xd2, 0x8f, 0x18, 0x3a, 0x31, 0xc9, 0x7e,
		0x3d, 0x79, 0xbd, 0x49, 0x68, 0xcb, 0xca, 0x17, 0xfc, 0xfd, 0x1d, 0x5f,
		0x2f, 0xab }, 248,
			0x03,
			{ 0x82, 0x26, 0x89, 0x00, 0xd4, 0x7f, 0x1d,
		0x1f, 0xe3, 0x32, 0x24, 0xb6, 0x04, 0x75, 0x57, 0x7f, 0x0e, 0xf6, 0xac,
		0xfb, 0xb7, 0xa0, 0xe3, 0xe5, 0x77, 0x7a, 0x3e, 0x57, 0x7f, 0x55, 0x72,
		0x84, 0x0a, 0x6c, 0xfe, 0xbb, 0x39, 0x3e, 0x52, 0x5a, 0xac, 0x6b, 0xf9,
		0x0a, 0x33, 0x97, 0x2e, 0xce, 0xfc, 0x14, 0xd1, 0xbd, 0x5d, 0x18, 0x7c,
		0xaa, 0xe5, 0x4e, 0xa2, 0x29, 0xb0, 0xb8, 0x78, 0xa6, 0x09, 0xcf, 0x8f,
		0x03, 0xee, 0x7f, 0xb4, 0x0f, 0x77, 0x91, 0x8e, 0x45, 0xd2, 0xbb, 0x1a,
		0xf6, 0xb3, 0xc2, 0x28, 0x5e, 0xfb, 0x88, 0x96, 0x35, 0x22, 0x6d, 0x45,
		0x39, 0x35, 0x94, 0x3b, 0x50, 0xaa, 0xec, 0x0f, 0x20, 0x90, 0xa5, 0x86,
		0xae, 0xe3, 0x52, 0x68, 0x0a, 0xb1, 0x39, 0xef, 0xca, 0xf1, 0xef, 0x47,
		0xcd, 0xbc, 0x8d, 0xcb, 0x7a, 0x38, 0xe7, 0x5c, 0xac, 0x8b, 0x17, 0x4b,
		0x3e, 0x63, 0x10, 0x61, 0x90, 0x41, 0x39, 0x6a, 0x6e, 0x3e, 0x86, 0x7d,
		0x90, 0x16, 0x46, 0x82, 0xed, 0x5f, 0x40, 0x60, 0x26, 0xf9, 0xb0, 0xeb,
		0xe4, 0x35, 0x21, 0x78, 0xa1, 0x9b, 0x8e, 0x85, 0x25, 0x16, 0x23, 0x1a,
		0xc5, 0xd1, 0xef, 0x15, 0xd1, 0x91, 0x7d, 0x47, 0x5b, 0xfb, 0x38, 0xfe,
		0x75, 0xe8, 0x53, 0xb7, 0x21, 0xfa, 0x0c, 0xe5, 0x62, 0xbb, 0x0d, 0xfe,
		0x5a, 0xf7, 0x94, 0xac, 0x27, 0xd1, 0xee, 0x52, 0x98, 0x66, 0x6b, 0xe2,
		0xc5, 0x33, 0x7e, 0x09, 0xd4, 0x8f, 0x6b, 0x93, 0x0e, 0x9f, 0xc8, 0xad,
		0x24, 0x67, 0x11, 0x8e, 0xb9, 0xd5, 0x1d, 0xa4, 0x5f, 0x7a, 0xf7, 0xdf,
		0x61, 0x53, 0x58, 0x4d, 0x9b, 0xe9, 0x92, 0x5b, 0x83, 0x28, 0x54, 0x60,
		0xc5, 0x90, 0xd7, 0x3f, 0xb2, 0xf6, 0x5e, 0xe6, 0x3e, 0xbf, 0x5e, 0x31,
		0x8b }, 248
		},
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
		0x03, {0}, 0 },
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
		0x03, {0}, 0
		}
};

/* locates the CA PK in the CA PK repository by PKI */
static CA_KEY* find_ca_key (uint8_t index) {
	for (size_t i = 0; i<sizeof(ca_key_table)/sizeof(ca_key_table[0]); i++)
		if (ca_key_table[i].index == index)
			return ca_key_table +i;
	return NULL;
}


static int emv_derive_icc_master_key_aes(uint8_t *unpacked_input, size_t unpacked_input_len,
		uint8_t *encryption_key, size_t encryption_key_len, uint8_t *output, size_t output_len);

static int emv_derive_icc_master_key_des(uint8_t *unpacked_input, size_t unpacked_input_len,
		uint8_t *encryption_key, uint8_t *output, size_t output_len);

static int emv_compute_3des_mac(uint8_t* data, size_t data_len, uint8_t * key, uint8_t * output, size_t output_len);

static int emv_compute_aes_cmac( uint8_t * data, size_t data_len, uint8_t * key, size_t key_len, uint8_t * output, size_t output_len ) ;

/* prints the issuer PK details header in a human-readable format */
void print_issuer_pk_details_header(ISSUER_PK_DETAILS_HEADER* header) {
	if (!header)
		return;
	printf("\t\tHeader sentinel (always 6A): %02X\n", header->sentinel);
	printf("\t\tCertificate format (always 02): %02X\n", header->certificate_format);
	print_array("\t\tIssuer identifier (right-padded with FF): ", header->issuer_identifier, 4, "\n");
	print_array("\t\tCertificate expiration MMYY: ", header->certificate_expiration, 2, "\n");
	print_array("\t\tCertificate serial: ", header->certificate_serial, 3, "\n");
	printf("\t\tHash algorithm: %02X\n", header->hash_algo);
	printf("\t\tIssuer PK algorithm: %02X\n", header->issuer_pk_algo);
	printf("\t\tIssuer PK length: %d\n", header->issuer_pk_len);
	printf("\t\tIssuer PK exponent length: %d\n", header->issuer_pk_exponent_len);
}

/* prints the ICC PK details header in a human-readable format */
void print_icc_pk_details_header(ICC_PK_DETAILS_HEADER * header) {
	if (!header)
		return;
	printf("\t\tHeader sentinel (always 6A): 0x%02X\n", header->sentinel);
	printf("\t\tCertificate format (always 04): 0x%02X\n", header->certificate_format);
	print_array("\t\tApplication PAN(right-padded with 0xF): ", header->applicaton_pan, 10, "\n");
	print_array("\t\tCertificate expiration MMYY: ", header->certificate_expiration, 2, "\n");
	print_array("\t\tCertificate serial: ", header->certificate_serial, 3, "\n");
	printf("\t\tHash algorithm: 0x%02X\n", header->hash_algo);
	printf("\t\tICC PK algorithm: 0x%02X\n", header->icc_pk_algo);
	printf("\t\tICC PK length: %d (0x%02X)\n", header->icc_pk_len,header->icc_pk_len);
	printf("\t\tICC PK exponent length: %d\n", header->icc_pk_exponent_len);
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
int emv_recover_issuer_public_key(uint8_t ca_pk_idx, uint8_t *issuer_pk_cert,
		size_t issuer_pk_cert_len, uint8_t *issuer_pk_remainder,
		size_t issuer_pk_remainder_len, uint32_t issuer_pk_exponent,
		uint8_t *recovered_key_buf, ISSUER_PK_DETAILS_HEADER *details_header) {

	if (!(issuer_pk_cert && issuer_pk_remainder))
		return EMV_ERROR;
	/* internal variables */
	CA_KEY * ca_pk = NULL;
	int retval = EMV_ERROR;

	/* buffer for the combined key */
	uint8_t combined_key[EMV_MAX_CA_KEY_SIZE];
	memset( combined_key, 0, sizeof(combined_key));

	/* buffer for the hash function */
	uint8_t *hash_function_input = calloc(EMV_MAX_CA_KEY_SIZE + issuer_pk_remainder_len, sizeof(uint8_t));

	/* buffer for the hash value */
	uint8_t hash_buffer[SHA_DIGEST_LENGTH];
	memset (hash_buffer, 0, SHA_DIGEST_LENGTH);


	/* rsa objects */
	RSA * rsa = NULL;

	/* Try to locate the CA public key by its index */
	ca_pk = find_ca_key(ca_pk_idx);
	if (!ca_pk) goto cleanup;
	/* We found a public key, now we can instantiate the RSA structure around it */

	rsa = make_rsa_key(ca_pk->modulus, ca_pk->modulus_len, ca_pk->public_exponent, NULL, 0);
	/* first, prepare the public exponent part */

	if (!rsa) goto cleanup;

	/* prepare the output buffer */
	uint8_t to[EMV_MAX_CA_KEY_SIZE];
	memset(to ,0, sizeof(to));

	int recovered_size = RSA_public_decrypt(issuer_pk_cert_len, issuer_pk_cert, to, rsa, RSA_NO_PADDING ) ;

	/* decrypt the key part */
	if (recovered_size<0)
		goto cleanup;

	print_array("\tRecovered raw data: ", to, recovered_size, "\n\n");

	/* parse the key */
	ISSUER_PK_DETAILS_HEADER *header = (ISSUER_PK_DETAILS_HEADER*) to;

	/* combine the key */
	/* copy the first part */
	memcpy(combined_key, to+sizeof(ISSUER_PK_DETAILS_HEADER), recovered_size-SHA_DIGEST_LENGTH-sizeof(ISSUER_PK_DETAILS_HEADER)-1);
	memcpy(combined_key + recovered_size-SHA_DIGEST_LENGTH-sizeof(ISSUER_PK_DETAILS_HEADER)-1, issuer_pk_remainder, issuer_pk_remainder_len);

	print_array("\tCombined key:       ", combined_key, header->issuer_pk_len, "\n\n");

	/* Check the hash value. For that, we concatenate the header values from Certificate Format to the end,
	 * then the deciphered PK part, then the remainder and finally the exponent */

	size_t hash_buffer_ptr = 0; /* tracks the position in the hash buffer for convenience */

	memcpy(hash_function_input, to+1, recovered_size-SHA_DIGEST_LENGTH-2);
	hash_buffer_ptr+= recovered_size-SHA_DIGEST_LENGTH-2;

	if (issuer_pk_remainder_len >0) {
		memcpy(hash_function_input+hash_buffer_ptr, issuer_pk_remainder,  issuer_pk_remainder_len);
		hash_buffer_ptr += issuer_pk_remainder_len;
	}

	/* the exponent is either 3 or 65537, i.e. either 1 or 3 bytes */
	if (header->issuer_pk_exponent_len==1) {
		hash_function_input[hash_buffer_ptr++] = issuer_pk_exponent;
	}
	else {
		uint32_t network_order = htonl(issuer_pk_exponent);
		memcpy(hash_function_input + hash_buffer_ptr, ((uint8_t*)&network_order)+1, 3);

		hash_buffer_ptr += 3;
	}

	print_array("\tHash input:         ", hash_function_input, hash_buffer_ptr, "\n\n");

	SHA1(hash_function_input, hash_buffer_ptr, hash_buffer);

	print_array("\tKey hash as computed: ", hash_buffer, SHA_DIGEST_LENGTH, "\n");
	print_array("\tKey hash as provided: ", to + recovered_size-SHA_DIGEST_LENGTH-1, SHA_DIGEST_LENGTH, "\n");

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
	free (hash_function_input);
	RSA_free(rsa);
	return retval;
}

/** Recovers the ICC key from the ICC certificate, the remainder, and the issuer public key
 * @param icc_cert The ICC public key certificate
 * @param icc_cert_len The length of the ICC certificate
 * @param icc_remainder The ICC public key remainder, if applicable
 * @param icc_remainder_len The length of the ICC PK remainder
 * @param icc_exponent The ICC public key exponent
 * @param ipk The issuer public key (modulus)
 * @param ipk_len The length of the issuer public key
 * @param ipk_exponent The issuer public key exponent
 * @param output the output buffer for the ICC public key
 * @param header the holder for ICC public key data
 * @param static_data Additional data for the hash computation
 * @param static_data_len Length of the additional data
 */
int emv_recover_icc_key(uint8_t *icc_cert, size_t icc_cert_len,
		uint8_t *icc_remainder, size_t icc_remainder_len, uint32_t icc_exponent,
		uint8_t *ipk, size_t ipk_len, uint32_t ipk_exponent,
		uint8_t * output, ICC_PK_DETAILS_HEADER *header, uint8_t * static_data, size_t static_data_len) {
	int retval = 0;

	uint8_t * hash_input = NULL;

	/* validate the input */
	if (! ( icc_cert && ipk && ipk_len && output && header ) )
		return EMV_ERROR;
	/* decrypt the certificate */
	RSA* rsa = NULL;

	rsa = make_rsa_key(ipk, ipk_len, ipk_exponent, NULL, 0);
	if (!rsa) goto cleanup;
	uint8_t decrypted_cert[EMV_MAX_CA_KEY_SIZE];
	int decrypted_cert_len = 0;
	if (! (decrypted_cert_len=RSA_public_decrypt(icc_cert_len, icc_cert, decrypted_cert, rsa, RSA_NO_PADDING)))
		goto cleanup;

	print_array("\tDecrypted certificate: ", decrypted_cert, decrypted_cert_len, "\n");
	/* Copy the header to the output */
	memcpy(header, decrypted_cert, sizeof(ICC_PK_DETAILS_HEADER));
	/* Copy the public key part to the output */

	retval = header->icc_pk_len + icc_remainder_len;

	size_t to_copy = header->icc_pk_len > EMV_MAX_ICC_KEY_LEN? EMV_MAX_ICC_KEY_LEN:header->icc_pk_len;
	memcpy(output, decrypted_cert+sizeof(ICC_PK_DETAILS_HEADER), to_copy);

	if (icc_remainder_len > 0) { /* Can only happen if the ICC PK is of max len */
		memcpy(output + to_copy, icc_remainder, icc_remainder_len);
	}
	/* Prepare the hash function input */

	size_t hash_input_len = sizeof(ICC_PK_DETAILS_HEADER) - 1
			+ decrypted_cert_len + header->icc_pk_exponent_len
			+ header->icc_pk_exponent_len
			+ static_data_len;
	size_t hash_ptr = 0;
	hash_input = calloc(hash_input_len, sizeof(uint8_t));

	/* copy the certificate header */
	memcpy( hash_input, decrypted_cert +1, sizeof(ICC_PK_DETAILS_HEADER) -1);
	hash_ptr += sizeof(ICC_PK_DETAILS_HEADER) -1;

	/* copy the ICC PK, including the padding */
	memcpy( hash_input + hash_ptr, decrypted_cert + sizeof(ICC_PK_DETAILS_HEADER),
			decrypted_cert_len - EMV_HASH_SIZE - 1 - sizeof(ICC_PK_DETAILS_HEADER));

	hash_ptr += /* header->icc_pk_len */decrypted_cert_len - EMV_HASH_SIZE - 1 - sizeof(ICC_PK_DETAILS_HEADER);

	/* copy the exponent */
	if (header->icc_pk_exponent_len == 1) {
		hash_input[hash_ptr++] = icc_exponent;
	}
	else {
		uint32_t network_order = htonl(icc_exponent);
		memcpy(hash_input + hash_ptr, ((uint8_t*)&network_order)+1, 3);

		hash_ptr += 3;
	}
	/* copy the static data*/
	memcpy(hash_input+hash_ptr, static_data, static_data_len);
	hash_ptr += static_data_len;
	print_array("\tHash function input:  ", hash_input, hash_ptr, "\n");
	uint8_t hash_result[EMV_HASH_SIZE];

	SHA1(hash_input, hash_ptr, hash_result);
	print_array("\tHash function result: ", hash_result, EMV_HASH_SIZE, "\n");
	print_array("\tValue as provided:    ", decrypted_cert+decrypted_cert_len-EMV_HASH_SIZE-1, EMV_HASH_SIZE, "\n");

cleanup:
	if (rsa) RSA_free(rsa);

	if (hash_input) free(hash_input);

	return retval;
}


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
int emv_derive_icc_master_key(uint8_t *unpacked_pan, size_t unpacked_pan_len, uint8_t *unpacked_csn,
		uint8_t *encryption_key, size_t encryption_key_len, int algorithm,  uint8_t *output, size_t output_len) {
	if (! (unpacked_pan && unpacked_pan_len && output && output_len && encryption_key && encryption_key_len))
		return EMV_ERROR;
	/* validate the input */
	if (!VALID_PAN_LENGTH(unpacked_pan_len))
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

	print_array("\tPAN+CSN: ", unpacked_input, unpacked_pan_len + CSN_LENGTH, "\n");

	if (ALGORITHM_AES == algorithm) {
		return emv_derive_icc_master_key_aes(unpacked_input, unpacked_pan_len+CSN_LENGTH, encryption_key, encryption_key_len, output, output_len);
	}
	else {
		return emv_derive_icc_master_key_des(unpacked_input, unpacked_pan_len+CSN_LENGTH, encryption_key, output, output_len);
	}

}

/**
 * Generates the certificate and the issuer key remainder for an issuer PK.
 * @param ca_index index of the CA whose keys are going to be used to sign the certificate
 * @param issuer_pk points to the issuer public key modulus
 * @param issuer_pk_exponent Issuer public key exponent. Only values of 3 and RSA_F4 are supported.
 * @param issuer_detais Issuer and certificate details
 * @param output_cert Buffer for the output certificate, must be of at least EMV_MAX_KEY_SIZE length
 * @param output_cert_len Actual certificate length will be written out to this variable
 * @param output_remainder Buffer for the issuer PK remainder output. Must be of sufficient length. The required length is the issuer PK
 * 			length minus (EMV_MAX_KEY_SIZE -36)
 * @param output_remainder_len Actual remainder lenght will be updated
 * @result EMV_SUCCESS if successful, EMV_ERROR otherwise
 */
int emv_sign_issuer_public_key(uint8_t ca_index, uint8_t * issuer_pk, uint32_t issuer_pk_exponent,
		ISSUER_PK_DETAILS_HEADER * issuer_details, uint8_t * output_cert, size_t* output_cert_len,
		uint8_t * output_remainder, size_t* output_remainder_len) {

	/* validate the input */
	if (!(issuer_pk && issuer_details && output_cert && output_cert_len && output_remainder && output_remainder_len )) return EMV_ERROR;

	uint8_t result[EMV_MAX_CA_KEY_SIZE];
	memset(result, 0, sizeof(result));

	uint8_t hash_input[EMV_MAX_CA_KEY_SIZE + 2 /* exponent */ + 14 /* header */];
	memset(hash_input, 0, sizeof(hash_input));

	size_t result_ptr = 0;

	/* copy issuer data header */
	memcpy(result, issuer_details, sizeof(ISSUER_PK_DETAILS_HEADER));
	result_ptr += sizeof(ISSUER_PK_DETAILS_HEADER);

	/* force fixed values in the issuer details */
	ISSUER_PK_DETAILS_HEADER *issuer_copy = (ISSUER_PK_DETAILS_HEADER *)result;

	issuer_copy->sentinel = EMV_SIGNATURE_B;
	issuer_copy->certificate_format = EMV_CERTIFICATE_FORMAT_ISSUER_KEY;
	issuer_copy->hash_algo = EMV_HASH_ALGORITHM_SHA1;
	issuer_copy->issuer_pk_algo = EMV_PK_ALGORIHTM_RSA;

	print_array("\tIssuer key: ", issuer_pk, issuer_details->issuer_pk_len, "\n");
	/* copy the issuer public key */
	size_t issuer_pk_len_used = issuer_details->issuer_pk_len>EMV_MAX_ISS_KEY_LEN ? EMV_MAX_ISS_KEY_LEN : issuer_details->issuer_pk_len;

	memcpy(result+result_ptr, issuer_pk, issuer_pk_len_used);

	result_ptr += issuer_pk_len_used;
	*output_cert_len = EMV_MAX_CA_KEY_SIZE;

	if (issuer_pk_len_used<EMV_MAX_ISS_KEY_LEN) {
		/* pad with 0xBB */
		memset(result+result_ptr, EMV_PK_PADDING, EMV_MAX_ISS_KEY_LEN-issuer_pk_len_used);
		result_ptr += EMV_MAX_ISS_KEY_LEN-issuer_pk_len_used;
		*output_remainder_len = 0;
	} else {
		/* copy the remainder */
		*output_remainder_len = issuer_pk_len_used-EMV_MAX_ISS_KEY_LEN;
		if (*output_remainder_len>0)
			memcpy(output_remainder, issuer_pk + issuer_pk_len_used, *output_remainder_len );
		print_array("\tKey remainder: ", output_remainder, *output_remainder_len, "\n");
	}

	/* prepare hash input: this is the issuer header, full issuer key and then the exponent */
	size_t hash_ptr = sizeof(ISSUER_PK_DETAILS_HEADER)-1 + EMV_MAX_ISS_KEY_LEN;

	/* copy with padding */
	memcpy(hash_input, result+1, sizeof(ISSUER_PK_DETAILS_HEADER)-1 + EMV_MAX_ISS_KEY_LEN);

	if (*output_remainder_len >0 ) {
		memcpy(hash_input + hash_ptr, output_remainder, *output_remainder_len);
		hash_ptr+= *output_remainder_len;
	}

	/* append the exponent */
	if ( 1 ==  issuer_details->issuer_pk_exponent_len ) {
		hash_input[hash_ptr++] = (uint8_t)issuer_pk_exponent;
	} else
	{
		uint32_t network_order = htonl(issuer_pk_exponent);
		memcpy(hash_input + hash_ptr, ((uint8_t*)&network_order)+1, 3);
		hash_ptr+=3;
	}
	print_array("\tHash input: ", hash_input, hash_ptr, "\n");
	/* calculate the hash and place it into the certificate */
	SHA1(hash_input, hash_ptr, result+EMV_MAX_CA_KEY_SIZE-1-EMV_HASH_SIZE);

	print_array("\tHash output: ", result+EMV_MAX_CA_KEY_SIZE-1-EMV_HASH_SIZE, EMV_HASH_SIZE, "\n");

	/* trailer sentinel */
	result[EMV_MAX_CA_KEY_SIZE-1] = EMV_SIGNATURE_E;
	print_array("\tBuffer:     ", result, EMV_MAX_CA_KEY_SIZE, "\n");

	/* Now we encrypt */
	int retval = EMV_ERROR;
	RSA* rsa = NULL;

	CA_KEY * ca_key = find_ca_key(ca_index);
	if (!ca_key) return EMV_ERROR;

	rsa = make_rsa_key(ca_key->modulus, ca_key->modulus_len, ca_key->public_exponent, ca_key->private_exponent, ca_key->private_exponent_len);

	if (!rsa) goto cleanup;

	int actual_len=RSA_private_encrypt(EMV_MAX_CA_KEY_SIZE, result, output_cert, rsa, RSA_NO_PADDING);
	if (actual_len<0)
		goto cleanup;

	*output_cert_len = (size_t)actual_len;

	print_array("\tEncrypted:  ", output_cert, (*output_cert_len), "\n");

	retval = EMV_SUCCESS;

cleanup:
	if (ERR_get_error())
		ERR_print_errors_fp(stdout);

	if (!rsa)
		RSA_free(rsa);

	return retval;
}

/**
 * Signs the static data for SDA with the provided issuer key
 * @param issuer_pub_key Issuer public key (modulus)
 * @param issuer_pub_key_len Length of issuer public key
 * @param issuer_pk_exponent Exponent for the issuer public key
 * @param issuer_priv_key Issuer private key
 * @param issuer_priv_key_len Length of issuer private key
 * @param auth_data Additional authentication data
 * @param auth_data_len Length of the additional data
 * @output points to the output buffer
 * @result length of the SDA, or EMV_ERROR if an error has occurred
 */
int emv_sign_static_data(uint8_t * issuer_pub_key, size_t issuer_pub_key_len,
		uint32_t issuer_pk_exponent, uint8_t *issuer_priv_key, size_t issuer_priv_key_len,
		uint8_t *auth_data, size_t auth_data_len, SDA_DETAILS_HEADER *sda_details,
		uint8_t *output) {
	int retval = 0;

	RSA* rsa = NULL;

	/* validate the inputs */
	if (!(issuer_pub_key && issuer_priv_key_len && issuer_pk_exponent && issuer_priv_key && issuer_priv_key_len && auth_data && auth_data_len && output))
		return EMV_ERROR;
	/* allocate buffer for the hash function input. The size is roughly the issuer modulus length plus the extra data */
	uint8_t *buffer = calloc(issuer_pub_key_len + auth_data_len, sizeof(uint8_t));
	size_t hash_ptr = 0;

	/* copy and correct the header */
	memcpy(buffer, sda_details, sizeof(SDA_DETAILS_HEADER));
	hash_ptr += sizeof(SDA_DETAILS_HEADER);

	SDA_DETAILS_HEADER * header = (SDA_DETAILS_HEADER*) buffer;
	header->sentinel = EMV_SIGNATURE_B;
	header->hash_algo = EMV_HASH_ALGORITHM_SHA1;
	header->sda_format = EMV_CERTIFICATE_FORMAT_SDA;

	/* pad to the full length*/
	memset(buffer + hash_ptr, EMV_PK_PADDING, issuer_pub_key_len-sizeof(SDA_DETAILS_HEADER)-EMV_HASH_SIZE-1);
	hash_ptr = issuer_pub_key_len - EMV_HASH_SIZE -1;

	size_t bookmark = hash_ptr;
	/* append the static data */
	memcpy(buffer + hash_ptr, auth_data, auth_data_len);
	hash_ptr += auth_data_len;

	print_array("\t\tHash input:       ", buffer+1, hash_ptr-1, "\n");

	/* compute the hash */
	uint8_t hash_value[EMV_HASH_SIZE];
	SHA1(buffer+1, hash_ptr-1, hash_value);
	print_array("\t\tHash output:      ", hash_value, EMV_HASH_SIZE, "\n");

	/* copy the result */
	memcpy(buffer + bookmark, hash_value, EMV_HASH_SIZE);
	hash_ptr = bookmark + EMV_HASH_SIZE;
	/* set the trailer sentinel */
	buffer[hash_ptr++] = EMV_SIGNATURE_E;

	/* encrypt */
	print_array("\t\tEncryption input: ", buffer, hash_ptr, "\n");
	rsa = make_rsa_key(issuer_pub_key, issuer_pub_key_len, issuer_pk_exponent, issuer_priv_key, issuer_priv_key_len);

	retval = RSA_private_encrypt(hash_ptr, buffer, output, rsa, RSA_NO_PADDING);

	ERR_print_errors_fp(stdout);
	/* free memory and return */
	free (buffer);
	if (rsa) RSA_free(rsa);
	return retval;
}

/**
 * Signs the dynamic data for DDA with the provided ICC key
 * @param icc_pub_key Issuer public key (modulus)
 * @param icc_pub_key_len Length of issuer public key
 * @param icc_pk_exponent Exponent for the issuer public key
 * @param icc_priv_key Issuer private key
 * @param icc_priv_key_len Length of issuer private key
 * @param auth_data Dynamic authentication data
 * @param auth_data_len Length of the additional data
 * @param dda_details DDA details header
 * @output points to the output buffer
 * @result length of the DDA, or EMV_ERROR if an error has occurred
 */
int emv_sign_dynamic_data(uint8_t * icc_pub_key, size_t icc_pub_key_len,
		uint32_t icc_pk_exponent, uint8_t *icc_priv_key, size_t icc_priv_key_len,
		uint8_t *icc_data, uint8_t *term_data, size_t term_data_len, DDA_DETAILS_HEADER *dda_details,
		uint8_t *output) {
	int retval = EMV_ERROR;

	RSA* rsa = NULL;

	/* validate the inputs */
	if (!( icc_pub_key && icc_pub_key_len && icc_pk_exponent && icc_priv_key && icc_priv_key_len
			&& term_data && term_data_len && icc_data && dda_details && output))
		return EMV_ERROR;
	/* allocate buffer for the hash function input. The size is roughly the ICC modulus length plus the extra data */
	uint8_t *buffer = calloc(icc_pub_key_len + dda_details->dd_len + term_data_len, sizeof(uint8_t));
	size_t hash_ptr = 0;

	/* copy and correct the header */
	memcpy(buffer, dda_details, sizeof(DDA_DETAILS_HEADER));
	hash_ptr += sizeof(DDA_DETAILS_HEADER);

	DDA_DETAILS_HEADER * header = (DDA_DETAILS_HEADER*) buffer;
	header->sentinel = EMV_SIGNATURE_B;
	header->hash_algo = EMV_HASH_ALGORITHM_SHA1;
	header->dda_format = EMV_CERTIFICATE_FORMAT_DDA;

	/* copy the ICC dynamic data */
	memcpy(buffer+hash_ptr, icc_data, dda_details->dd_len);
	hash_ptr += dda_details->dd_len;

	/* pad to the full length of the ICC PK*/
	memset(buffer + hash_ptr, EMV_PK_PADDING, icc_pub_key_len-sizeof(DDA_DETAILS_HEADER)-dda_details->dd_len-EMV_HASH_SIZE-1);
	hash_ptr += icc_pub_key_len-sizeof(DDA_DETAILS_HEADER)-dda_details->dd_len-EMV_HASH_SIZE-1;

	size_t bookmark = hash_ptr;
	/* append the terminal dynamic data data */
	memcpy(buffer + hash_ptr, term_data, term_data_len);
	hash_ptr += term_data_len;

	print_array("\t\tHash input:       ", buffer+1, hash_ptr-1, "\n");

	/* compute the hash */
	uint8_t hash_value[EMV_HASH_SIZE];
	SHA1(buffer+1, hash_ptr-1, hash_value);
	print_array("\t\tHash output:      ", hash_value, EMV_HASH_SIZE, "\n");

	/* copy the result */
	memcpy(buffer + bookmark, hash_value, EMV_HASH_SIZE);
	hash_ptr = bookmark + EMV_HASH_SIZE;
	/* set the trailer sentinel */
	buffer[hash_ptr++] = EMV_SIGNATURE_E;

	/* encrypt */
	print_array("\t\tEncryption input: ", buffer, hash_ptr, "\n");
	rsa = make_rsa_key(icc_pub_key, icc_pub_key_len, icc_pk_exponent, icc_priv_key, icc_priv_key_len);

	retval = RSA_private_encrypt(hash_ptr, buffer, output, rsa, RSA_NO_PADDING);

	/* free memory and return */
	free (buffer);
	if (rsa) RSA_free(rsa);
	return retval;
}

/**
 * Validates that the DDA hash matches the data. Doesn't perform full EMV validation. Returns EMV_SUCESS
 * or EMV_ERROR
 *
 * @param dda the DDA signature
 * @param dda_len the DDA signature length
 * @param icc_pub_key Issuer public key (modulus)
 * @param icc_pub_key_len Length of issuer public key
 * @param icc_pk_exponent Exponent for the issuer public key
 * @param icc_priv_key Issuer private key
 * @param icc_priv_key_len Length of issuer private key
 * @param icc_data ICC dynamic authentication data
 * @param term_data Terminal dynamic authentication data
 * @param term_data_len Length of the terminal additional data
 * @param dda_details DDA details header
 * @result EMV_ERROR or EMV_SUCCESS
 */
int emv_validate_dda(uint8_t *dda, size_t dda_len, uint8_t * icc_pub_key, size_t icc_pub_key_len,
		uint32_t icc_pk_exponent, uint8_t *term_data, size_t term_data_len, DDA_DETAILS_HEADER *header)  {
	int retval = EMV_ERROR;
	RSA * rsa = NULL;
	/* validate the inputs */
	if (!(dda && dda_len && icc_pub_key && icc_pub_key_len && icc_pk_exponent
			&& term_data && term_data_len && header))
		return EMV_ERROR;

	/* allocate the buffer for SHA computation */
	uint8_t * buffer = calloc(icc_pub_key_len + term_data_len, sizeof(uint8_t));
	/* decrypt the SDA value */
	rsa = make_rsa_key(icc_pub_key, icc_pub_key_len, icc_pk_exponent, NULL, 0);
	if (!rsa) goto cleanup;

	int actual_len = RSA_public_decrypt(icc_pub_key_len, dda, buffer, rsa, RSA_NO_PADDING);
	if (actual_len<0)
		goto cleanup;

	memcpy(header, buffer, sizeof(SDA_DETAILS_HEADER));
	/* copy away the provided SHA */
	uint8_t hash_provided[EMV_HASH_SIZE];
	memcpy(hash_provided, buffer + icc_pub_key_len-1-EMV_HASH_SIZE, EMV_HASH_SIZE);
	print_array("\t\tDecrypted value: ", buffer, actual_len, "\n");
	/* copy the terminal data into the buffer */
	memcpy(buffer + icc_pub_key_len-1-EMV_HASH_SIZE, term_data, term_data_len);

	/* compute the SHA of the data */
	print_array("\t\tHash input:      ", buffer+1, icc_pub_key_len-2-EMV_HASH_SIZE + term_data_len, "\n");
	uint8_t hash_computed[EMV_HASH_SIZE];
	SHA1(buffer+1, icc_pub_key_len-2-EMV_HASH_SIZE + term_data_len, hash_computed);
	print_array("\t\tHash provided:   ", hash_provided, EMV_HASH_SIZE, "\n");
	print_array("\t\tHash computed:   ", hash_computed, EMV_HASH_SIZE, "\n");

	if (!memcmp(hash_provided, hash_computed, EMV_HASH_SIZE))
		retval=EMV_SUCCESS;

cleanup:
	free(buffer);
	if (rsa) RSA_free(rsa);
	return retval;
}

/** Validate the provided SDA. Performs only comparison of the computed hash with the provided
 * value.
 * @param sda The SDA value. Assumed to be of the same length as the issuer PK.
 * @param issuer_pk Issuer public key modulus
 * @param issuer_pk_len Issuer public key modulus length
 * @param issuer_exponent Issuer exponent
 * @param auth_data Additional authentication data
 * @param auth_data_len Length of the additional data
 * @param header holder for the recovered SDA details header
 * @result EMV_SUCCESS if the values match, EMV_ERROR otherwise
 */
int emv_validate_sda(uint8_t * sda, uint8_t * issuer_pk, size_t issuer_pk_len, uint32_t issuer_exponent,
		uint8_t * auth_data, size_t auth_data_len, SDA_DETAILS_HEADER * header)  {
	int retval = EMV_ERROR;
	RSA * rsa = NULL;
	/* validate the inputs */
	if (!(sda && issuer_pk && issuer_pk_len && issuer_exponent && auth_data && auth_data_len && header))
		return EMV_ERROR;

	/* allocate the buffer for SHA computation */
	uint8_t * buffer = calloc(issuer_pk_len + auth_data_len, sizeof(uint8_t));
	/* decrypt the SDA value */
	rsa = make_rsa_key(issuer_pk, issuer_pk_len, issuer_exponent, NULL, 0);
	if (!rsa) goto cleanup;

	int actual_len = RSA_public_decrypt(issuer_pk_len, sda, buffer, rsa, RSA_NO_PADDING);
	if (actual_len<0)
		goto cleanup;

	memcpy(header, buffer, sizeof(SDA_DETAILS_HEADER));
	/* copy away the provided SHA */
	uint8_t hash_provided[EMV_HASH_SIZE];
	memcpy(hash_provided, buffer + issuer_pk_len-1-EMV_HASH_SIZE, EMV_HASH_SIZE);
	print_array("\t\tDecrypted value: ", buffer, actual_len, "\n");
	/* copy the additional data into the buffer */
	memcpy(buffer + issuer_pk_len-1-EMV_HASH_SIZE, auth_data, auth_data_len);
	/* compute the SHA of the data */
	print_array("\t\tHash input:      ", buffer+1, issuer_pk_len-2-EMV_HASH_SIZE + auth_data_len, "\n");
	uint8_t hash_computed[EMV_HASH_SIZE];
	SHA1(buffer+1, issuer_pk_len-2-EMV_HASH_SIZE + auth_data_len, hash_computed);
	print_array("\t\tHash provided:   ", hash_provided, EMV_HASH_SIZE, "\n");
	print_array("\t\tHash computed:   ", hash_computed, EMV_HASH_SIZE, "\n");

	if (!memcmp(hash_provided, hash_computed, EMV_HASH_SIZE))
		retval=EMV_SUCCESS;

cleanup:
	free(buffer);
	if (rsa) RSA_free(rsa);
	return retval;
}

/**
 * Signs the ICC public key with an issuer public key.
 * @param issuer_pub_key Issuer public key (modulus)
 * @param issuer_pub_key_len Length of issuer public key
 * @param issuer_pk_exponent Exponent for the issuer public key
 * @param issuer_priv_key Issuer private key
 * @param issuer_priv_key_len Length of issuer private key
 * @param icc_pk ICC public key to sign
 * @param icc_pk_exponent ICC public key exponent
 * @param icc_details ICC details header, including PAN, certificate expiry, and serial
 * @param auth_data Additional authentication data
 * @param auth_data_len Length of the additional data
 * @output_cert points to the output buffer
 * @output_remainder points to the buffer for the output remainder
 * @output_remainder_len pointer to the length of the remainder
 * @result length of the certificate, or EMV_ERROR if an error has occured
 */
int emv_sign_icc_public_key(uint8_t * issuer_pub_key, size_t issuer_pub_key_len,
		uint32_t issuer_pk_exponent,  uint8_t * issuer_priv_key, size_t issuer_priv_key_len,
		uint8_t * icc_pk, uint32_t icc_pk_exponent,
		ICC_PK_DETAILS_HEADER * icc_details, uint8_t *auth_data, size_t auth_data_len,
		uint8_t * output_cert,
		uint8_t * output_remainder, size_t* output_remainder_len) {

	int retval = EMV_ERROR;
	RSA* rsa = NULL;

	/* validate the inputs */
	if (!(issuer_pub_key && issuer_priv_key_len && issuer_priv_key
			&& issuer_priv_key_len && icc_pk  && icc_details && output_cert
			&& output_remainder && output_remainder_len))
		return EMV_ERROR;

	/* prepare the buffer */
	uint8_t * buffer = calloc( EMV_MAX_ISS_KEY_LEN + auth_data_len, sizeof(uint8_t) );
	size_t buffer_ptr = 0;

	memcpy(buffer, icc_details, sizeof(ICC_PK_DETAILS_HEADER));
	buffer_ptr += sizeof(ICC_PK_DETAILS_HEADER);

	ICC_PK_DETAILS_HEADER * icc_copy = (ICC_PK_DETAILS_HEADER*) buffer;
	/* set the fixed values */
	icc_copy->sentinel = EMV_SIGNATURE_B;
	icc_copy->certificate_format = EMV_CERTIFICATE_FORMAT_ICC_KEY;
	icc_copy->hash_algo = EMV_HASH_ALGORITHM_SHA1;
	icc_copy->icc_pk_algo = EMV_PK_ALGORIHTM_RSA;

	/* copy the ICC PK */
	size_t icc_pk_len = icc_details->icc_pk_len;
	/* maximum length */
	size_t icc_pk_cert_max_len = issuer_pub_key_len-EMV_HASH_SIZE-sizeof(ICC_PK_DETAILS_HEADER)-1;
	/* actual length */
	size_t icc_pk_cert_len;

	if (icc_pk_len > icc_pk_cert_max_len ) {
		/* there is a remainder */
		memcpy (output_remainder, icc_pk + icc_pk_cert_max_len, icc_pk_len-icc_pk_cert_max_len);
		*output_remainder_len = icc_pk_len-icc_pk_cert_max_len;
		icc_pk_cert_len = icc_pk_cert_max_len;
	} else {
		icc_pk_cert_len = icc_pk_len;
		*output_remainder_len = 0;
	}
	/* copy the PK */
	memcpy (buffer+buffer_ptr, icc_pk, icc_pk_cert_len);
	/* pad the PK as needed  */
	memset(buffer+buffer_ptr+icc_pk_cert_len, EMV_PK_PADDING, icc_pk_cert_max_len-icc_pk_cert_len);

	buffer_ptr += icc_pk_cert_max_len;

	size_t bookmark = buffer_ptr;
	/* Add the exponent and the static data to sign. Anything past the bookmark will be overwritten */
	if (icc_details->icc_pk_exponent_len == 1) {
		buffer[buffer_ptr++] = icc_pk_exponent;
	} else {
		uint32_t network_order = htonl(icc_pk_exponent);
		memcpy(buffer + buffer_ptr, ((uint8_t*)&network_order)+1, 3);
		buffer_ptr +=3;
	}
	if (auth_data_len>0) {
		memcpy(buffer+ buffer_ptr, auth_data, auth_data_len);
		buffer_ptr += auth_data_len;
	}
	/* hash the result */
	print_array("\tHash function input:    ", buffer+1, buffer_ptr-1, "\n");
	uint8_t signature[EMV_HASH_SIZE];
	if (!SHA1(buffer+1, buffer_ptr-1, signature)) goto cleanup;

	print_array("\tHash function output: \t", signature, EMV_HASH_SIZE, "\n");
	memcpy(buffer+bookmark, signature, EMV_HASH_SIZE);
	buffer_ptr = bookmark+EMV_HASH_SIZE;
	buffer[buffer_ptr++] = EMV_SIGNATURE_E;

	/* encrypt */
	print_array("\tInput to encryption: ", buffer, buffer_ptr, "\n");

	rsa = make_rsa_key(issuer_pub_key, issuer_pub_key_len, issuer_pk_exponent, issuer_priv_key, issuer_priv_key_len);
	if (rsa == NULL) goto cleanup;

	retval = RSA_private_encrypt(buffer_ptr, buffer, output_cert, rsa, RSA_NO_PADDING);
	if (retval<0) goto cleanup;

	print_array("\tICC certificate: ", output_cert, retval, "\n");

cleanup:
	ERR_print_errors_fp(stdout);
	free (buffer);
	if (rsa) RSA_free(rsa);
	return retval;
}

static int emv_derive_icc_master_key_aes(uint8_t *unpacked_input, size_t unpacked_input_len,
		uint8_t *encryption_key, size_t encryption_key_len, uint8_t *output, size_t output_len) {

	int result = EMV_ERROR;

	/* the unpacked input contains the PAN and the CSN already */
	uint8_t packed_input[AES_BLOCK_SIZE];

	pack_bcd(unpacked_input, unpacked_input_len, packed_input, AES_BLOCK_SIZE, PAD_LEFT);
	print_array("\tPacked input: ", packed_input, AES_BLOCK_SIZE, "\n");

	/* prepare the first chunk of the output */
	AES_KEY key;
	if (AES_set_encrypt_key(encryption_key, encryption_key_len*8, &key)) goto cleanup;

	AES_ecb_encrypt(packed_input, output, &key, AES_ENCRYPT);
	print_array("\tFirst chunk: ", output, AES_BLOCK_SIZE, "\n");

	if (output_len>AES_BLOCK_SIZE) {
		/* continue for the second half of the key */
		uint8_t output_buffer[AES_BLOCK_SIZE];

		/* inverse the input vector */
		for (int i = 0; i<AES_BLOCK_SIZE; i++)
			packed_input[i] ^= 0xFF;


		print_array("\tInverted input: ", packed_input, AES_BLOCK_SIZE, "\n");

		AES_ecb_encrypt(packed_input, output_buffer, &key, AES_ENCRYPT);
		print_array("\tFull second chunk: ", output_buffer, AES_BLOCK_SIZE, "\n");

		memcpy(output+AES_BLOCK_SIZE, output_buffer, output_len-AES_BLOCK_SIZE);
	}
	result = EMV_SUCCESS;

cleanup:
	PURGE(key);
	PURGE(packed_input);
	return result;
}

static int emv_derive_icc_master_key_des(uint8_t *unpacked_input, size_t unpacked_input_len,
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
		/* pack with left padding by 1 nibble if odd */
		pack_bcd(unpacked_input, unpacked_input_len, enc_input,  (unpacked_input_len+1)>>1,  PAD_LEFT);
		print_array("\tPacked input: ", enc_input, (unpacked_input_len+1)>>1, "\n");
		uint8_t hash_output[SHA_DIGEST_LENGTH];
		SHA1((unsigned char*)enc_input, (unpacked_input_len+1)>>1, (unsigned char*)&hash_output);

		error_code = ERR_get_error();
		if (error_code)
			return EMV_ERROR;

		print_array("\tHash output: ", hash_output, SHA_DIGEST_LENGTH, "\n");
		uint8_t hash_decimalized_unpacked[TDES_BLOCK_SIZE<<1];

		decimalize_vector(hash_output, 2*SHA_DIGEST_LENGTH, hash_decimalized_unpacked, TDES_BLOCK_SIZE<<1);

		memset(enc_input, 0, TDES_BLOCK_SIZE<<1);
		pack_bcd(hash_decimalized_unpacked, TDES_BLOCK_SIZE<<1, enc_input, TDES_BLOCK_SIZE, PAD_RIGHT);
		print_array("\tDecimalized output: ", enc_input, TDES_BLOCK_SIZE, "\n");
	}

	print_array("\tEncryption input: ", enc_input, TDES_BLOCK_SIZE, "\n");

	DES_key_schedule key_a, key_b;
	DES_set_key_unchecked( (const_DES_cblock *)encryption_key, &key_a);
	DES_set_key_unchecked( (const_DES_cblock *) (encryption_key+(TDES_KEY_LENGTH_1)), &key_b);

	DES_ecb2_encrypt( (DES_cblock*) enc_input, (DES_cblock*)output, &key_a, &key_b, DES_ENCRYPT);
	error_code = ERR_get_error();
	if (error_code)
		return EMV_ERROR;

	print_array("\tFirst half: ", output, TDES_BLOCK_SIZE, "\n");

	for (size_t i=0; i<sizeof(enc_input); i++)
		enc_input[i]^=0xFF;

	print_array("\tSecond input: ", enc_input, TDES_BLOCK_SIZE, "\n");
	DES_ecb2_encrypt( (DES_cblock*) enc_input, (DES_cblock*) (output+TDES_BLOCK_SIZE), &key_a, &key_b, DES_ENCRYPT);
	error_code = ERR_get_error();
	if (error_code)
		return EMV_ERROR;

	print_array("\tSecond half: ", output+TDES_BLOCK_SIZE, TDES_BLOCK_SIZE, "\n");

	print_array("\tBefore parity: ", output, output_len, "\n");
	fix_parity(output, output_len, PARITY_ODD);

	print_array("\tFinal ICC Master key: ", output, output_len, "\n");

	return EMV_SUCCESS;
}

int emv_derive_icc_session_key(uint8_t *icc_master_key,
		size_t icc_master_key_length, int algorithm, uint8_t *atc, uint8_t *output,
		size_t output_len){

	uint8_t magic_number[2] = {0xF0, 0x0F};
	int result = EMV_ERROR;
	unsigned long error_code;

	/* validate inputs */
	if (! (icc_master_key && icc_master_key_length && atc && output && output_len))
		return EMV_ERROR;

	algorithm &= 0x1;

	/* check output length */
	if (ALGORITHM_TDES==algorithm && output_len!= TDES_KEY_LENGTH_2)
		return EMV_ERROR;
	if (ALGORITHM_AES==algorithm && !VALID_AES_KEY_SIZE(output_len))
		return EMV_ERROR;

	uint8_t output_data[2*AES_BLOCK_SIZE];
	memset(output_data, 0, sizeof(output_data));

	uint8_t input_data[AES_BLOCK_SIZE];
	memset(input_data, 0, AES_BLOCK_SIZE);
	memcpy(input_data, atc, EMV_ATC_LENGTH);

	/* initiate the keys */
	DES_key_schedule des_key_a, des_key_b;
	AES_KEY aes_key;

	if (ALGORITHM_TDES==algorithm) {
		DES_set_key_unchecked( (const_DES_cblock *) icc_master_key, &des_key_a);
		DES_set_key_unchecked( (const_DES_cblock *) (icc_master_key+(TDES_KEY_LENGTH_1)), &des_key_b);
	} else { /* assuming it can only be AES */
		AES_set_encrypt_key(icc_master_key, icc_master_key_length<<3, &aes_key);
	}

	int iters = 2;

	if (AES_BLOCK_SIZE==output_len && ALGORITHM_AES == algorithm) {
		/* AES 128 bit key derivation has no magic number and a single iteration */
		iters = 1;
		magic_number[0] = 0;
	}

	for (int i =0; i<iters; i++) {
		input_data[EMV_ATC_LENGTH] = magic_number[i];

		print_array("\tInput data for encryption: ", input_data, TDES_BLOCK_SIZE, "\n");
		if (algorithm==ALGORITHM_TDES)
		{

			DES_ecb2_encrypt((DES_cblock* ) input_data,
					(DES_cblock*)(output_data + (i*TDES_BLOCK_SIZE)), &des_key_a,
					&des_key_b, DES_ENCRYPT);

			print_array("\tEncryption output: ", output_data + (i*TDES_BLOCK_SIZE), TDES_BLOCK_SIZE, "\n");

			error_code = ERR_get_error();
			if (error_code) goto cleanup;
			fix_parity(output_data, TDES_BLOCK_SIZE*2, PARITY_ODD);
		} else {
			AES_ecb_encrypt(input_data, output_data+(i*AES_BLOCK_SIZE), &aes_key, AES_ENCRYPT);
			print_array("\tEncryption output: ", output_data + (i*AES_BLOCK_SIZE), AES_BLOCK_SIZE, "\n");
			error_code = ERR_get_error();
			if (error_code) goto cleanup;
		}
		result = EMV_SUCCESS;
	}

	cleanup:
	/* purge the keys */
	PURGE(des_key_a);
	PURGE(des_key_b);
	PURGE(aes_key);
	memcpy(output, output_data, output_len);
	return result;
}

/**
 * Generates ARQC
 * @param session_key session key
 * @param session_key_len length of the session key
 * @param algorithm, TDES or AES
 * @param arqc_data Input data for the ARQC
 * @param arqc_data_len length of the input data
 * @param output the output buffer
 * @param output_len desired length
 * @result returns EMV_ERROR or EMV_SUCCESS
 */
int emv_generate_arqc(uint8_t *session_key, size_t session_key_len,
		int algorithm, uint8_t *arqc_data, size_t arqc_data_len,
		uint8_t *output, size_t output_len) {
	int result = EMV_ERROR;


	/* Validate inputs */
	if (!(session_key && session_key_len && arqc_data && arqc_data_len && output && output_len)) return result;

	algorithm &= 0x1;

	/* check key length */
	if (ALGORITHM_TDES==algorithm && session_key_len!= TDES_KEY_LENGTH_2)
		return EMV_ERROR;

	if (ALGORITHM_AES==algorithm && !VALID_AES_KEY_SIZE(session_key_len))
		return EMV_ERROR;

	/* check output length */
	if (output_len < EMV_ARQC_MIN_LEN || output_len > EMV_ARQC_MAX_LEN)
		return EMV_ERROR;

	print_array("\tInput ARQC data: ", arqc_data, arqc_data_len, "\n");

	/* AES ARQC is a simple CMAC */
	if (ALGORITHM_AES == algorithm) {
		if (!emv_compute_aes_cmac(arqc_data, arqc_data_len, session_key, session_key_len, output, output_len)) goto cleanup;
	} else {
		if (!emv_compute_3des_mac( arqc_data, arqc_data_len, session_key, output, output_len)) goto cleanup;
	}

	/* done */
	print_array("\tResult:", output, output_len, "\n");
	result = EMV_SUCCESS;

cleanup:

	return result;
}

/*
 * Generates ARPC using one of the two standard methods. If ARC is provided, uses Method 1. Otherwise, uses Method 2.
 * @param arqc The ARQC value, assumed to be 8 byte length.
 * @param arc The ARC is 2 byte length. If present, other input parameters are ignored.
 * @param csu The Card Status Update, assumed to be 4 byte length.
 * @param pad Proprietary Auth Data, 0 to 8 byte length.
 * @param pad_len Length of the PAD
 * @param key Encryption key
 * @param key_len Length of the encryption key
 * @param algorithm Algorithm to use.
 * @param output Output buffer, must have enough digits
 * @result EMV_ERROR or the actual length of the ARPC.
 */
int emv_generate_arpc(uint8_t *arqc, uint8_t *arc, uint8_t *csu, uint8_t *pad,
		size_t pad_len, int algorithm, uint8_t *key, size_t key_len,
		uint8_t *output) {
	int result = EMV_ERROR;
	/* validate the input */
	if (! (arqc && output && (arc || (csu&&pad)))) return EMV_ERROR;
	DES_key_schedule des_key_a, des_key_b;
	AES_KEY aes_key;

	algorithm &= 0x1;

	if (ALGORITHM_AES == algorithm && !(VALID_AES_KEY_SIZE(key_len))) return EMV_ERROR;
	if (ALGORITHM_TDES == algorithm && (TDES_KEY_LENGTH_2!=key_len)) return EMV_ERROR;

	uint8_t buffer [EMV_ARPC_MAX_LEN];
	memset( buffer, 0, sizeof(buffer));

	if (arc) {
		/* ARPC Method 1 */
		memcpy(buffer, arc, EMV_ARPC_ARC_LEN);
		xor_array(buffer, arqc, buffer, EMV_ARQC_MAX_LEN);
		print_array("\tMethod 1 input: ", buffer, sizeof(buffer), "\n");
		if (ALGORITHM_TDES==algorithm) {
			DES_set_key_unchecked((const_DES_cblock*)key, &des_key_a);
			DES_set_key_unchecked((const_DES_cblock*)key + TDES_KEY_LENGTH_1, &des_key_b);
			DES_ecb2_encrypt((const_DES_cblock*) buffer, (DES_cblock*)output, &des_key_a, &des_key_b, DES_ENCRYPT);
			result = TDES_BLOCK_SIZE;
		} else {
			/* AES */
			AES_set_encrypt_key(key, key_len*8, &aes_key);
			AES_ecb_encrypt(buffer, output, &aes_key, AES_ENCRYPT);
			result = AES_BLOCK_SIZE;
		}
	} else {
		/* ARPC Method 2 */
		size_t input_len = 0;
		memcpy(buffer, arqc, EMV_ARQC_MAX_LEN);
		input_len += EMV_ARQC_MAX_LEN;

		memcpy(buffer+input_len, csu, EMV_ARPC_CSU_LEN);
		input_len += EMV_ARPC_CSU_LEN;

		memcpy(buffer+input_len, pad, pad_len);
		input_len += pad_len;
		print_array("\tMethod 2 input: ", buffer, input_len, "\n");
		/* place CSU and PAD in the output buffer */
		memcpy(output + EMV_ARQC_MIN_LEN, csu, EMV_ARPC_CSU_LEN);
		memcpy(output + EMV_ARQC_MIN_LEN + EMV_ARPC_CSU_LEN, pad, pad_len);
		if (ALGORITHM_TDES == algorithm) {
			emv_compute_3des_mac(buffer, input_len, key, output, EMV_ARQC_MIN_LEN);
		} else {
			emv_compute_aes_cmac(buffer, input_len, key, key_len, output, EMV_ARQC_MIN_LEN);
		}
		result = EMV_ARQC_MIN_LEN + EMV_ARPC_CSU_LEN + pad_len;
	}

	print_array("\tResult: ", output, result, "\n");

	PURGE(des_key_a);
	PURGE(des_key_b);
	return result;
}

/**
 * Computes the AES CMAC
 * Returns EMV_ERROR or EMV_SUCCESS.
 * @param data data to sign
 * @param data_len length of the data to sign
 * @param key encryption key
 * @param key_len encryption key length
 * @param output output buffer
 * @param output_len desired length of the output
 * @result EMV_ERROR on error and EMV_SUCCESS on success
 */

static int emv_compute_aes_cmac( uint8_t * data, size_t data_len, uint8_t * key, size_t key_len, uint8_t * output, size_t output_len ) {
	int result = EMV_ERROR;

	/* Validate inputs */
	if (! (data && data_len && key && key_len && output && output_len)) return EMV_ERROR;

	CMAC_CTX * cmac_ctx = NULL;
	uint8_t output_buffer[AES_BLOCK_SIZE];
	/* Compute the CMAC */
	EVP_CIPHER * cipher;
	switch (key_len ) {
	case AES_KEY_LENGTH_3:
		cipher = (EVP_CIPHER *) EVP_aes_256_cbc();
		break;
	case AES_KEY_LENGTH_2:
		cipher = (EVP_CIPHER *) EVP_aes_192_cbc();
		break;
	default:
		cipher = (EVP_CIPHER *) EVP_aes_128_cbc();
	}

	cmac_ctx = CMAC_CTX_new();
	if (!CMAC_Init(cmac_ctx, key, key_len, cipher, NULL)) goto cleanup;

	if (!CMAC_Update(cmac_ctx, data, data_len)) goto cleanup;

	size_t outlen;
	if (!CMAC_Final(cmac_ctx, output_buffer, &outlen)) goto cleanup;
	print_array("\tCMAC output:", output_buffer, outlen, "\n");

	/* copy the desired number of bytes */
	memcpy(output, output_buffer, output_len);

cleanup:
	if (cmac_ctx) CMAC_CTX_free(cmac_ctx);

	return result;
}

/**
 * Computes the 3DES MAC (CBC-MAC with padding).
 * Assumes that the key is of the right length, returns EMV_ERROR or EMV_SUCCESS.
 * @param data data to sign
 * @param data_len length of the data to sign
 * @param key encryption key
 * @param output output buffer
 * @param output_len desired length of the output
 * @result EMV_ERROR on error and EMV_SUCCESS on success
 */
static int emv_compute_3des_mac(uint8_t* data, size_t data_len, uint8_t * key, uint8_t * output, size_t output_len) {
	/* validate inputs */
	if (!(data&& data_len && key && output && output_len)) return EMV_ERROR;

	int result = EMV_ERROR;

	DES_key_schedule key_a, key_b;
	uint8_t *padding_buffer = NULL;

	size_t padded_data_size =  TDES_BLOCK_SIZE*((data_len+1)/TDES_BLOCK_SIZE + !!((data_len+1 )%TDES_BLOCK_SIZE) );

	/* Pad the data */
	padding_buffer = calloc(padded_data_size, sizeof(uint8_t));
	memcpy(padding_buffer, data, data_len);

	padding_buffer[data_len] = EMV_ARQC_PADDING;
	print_array("\tPadded input: ", padding_buffer, padded_data_size, "\n");

	/* perform CBC encryption with the key */
	DES_set_key_unchecked( (const_DES_cblock*) key, &key_a);
	DES_set_key_unchecked( (const_DES_cblock*) (key+TDES_KEY_LENGTH_1), &key_b);
	/* IV is all zeros */
	uint8_t iv[TDES_BLOCK_SIZE];
	memset(iv, 0, TDES_BLOCK_SIZE);

	/* encrypt */
	DES_ede2_cbc_encrypt(padding_buffer, padding_buffer, padded_data_size,
			&key_a, &key_b, (DES_cblock* )iv, DES_ENCRYPT);

	/* copy last block to the output */
	memcpy(output, padding_buffer + (padded_data_size-TDES_BLOCK_SIZE), output_len);
	result = EMV_SUCCESS;

	if (padding_buffer) free(padding_buffer);
	PURGE(key_a);
	PURGE(key_b);
	return result;
}
