/*
 * test_crypto_primitives.c
 * Executes various cryptographic primitives and prints test vectors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* DES and TDES */
#include <openssl/des.h>

/* AES */
#include <openssl/aes.h>

/* RSA*/
#include <openssl/rsa.h>

/* Diffie-Hellman */
#include <openssl/dh.h>

/* Digital Signature Algorithm */
#include <openssl/dsa.h>

/* HMAC */
#include <openssl/hmac.h>

/* CMAC */
#include <openssl/cmac.h>

/* Random number generator */
#include <openssl/rand.h>

#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>


#include "test_io.h"
#include "bits.h"

void DES_example();
void TDES_example();
void RSA_example();
void AES_example();
void DH_example();
void OAEP_example();
void DSA_example();
void HMAC_example();
void CMAC_example();

TEST crypto_tests[] =
{
	{ "Legacy DES algorithm", DES_example, NULL },
	{ "TDES algorithm", TDES_example, NULL },
	{ "RSA algorithm", RSA_example, NULL },
	{ "AES algorithm", AES_example, NULL },
	{ "Diffie-Hellman", DH_example, NULL },
	{ "OAEP test", OAEP_example, NULL },
	{ "DSA test", DSA_example, NULL },
	{ "HMAC test", HMAC_example, NULL },
	{ "CMAC test", CMAC_example, NULL },
};

typedef struct tag_DES_TEST {
	uint8_t key[8];
	uint8_t data[8];
	uint8_t result[8];
} DES_TEST;

typedef struct tag_TDES_TEST {
	uint8_t key[16];
	uint8_t data[8];
	uint8_t result[8];
} TDES_TEST;

typedef struct tag_RSA_TEST {
	uint8_t data[4];
	long public_exponent;
	size_t bits;
} RSA_TEST;

typedef struct tag_AES_TEST {
	uint8_t key[32];
	uint16_t bits;
	uint8_t data[16];
	uint8_t result[16];
} AES_TEST;

typedef struct tag_HMAC_TEST {
	uint8_t key[256];
	size_t key_len;
	uint8_t data[512];
	size_t data_len;
	uint8_t digest[256];
	size_t digest_len;
} HMAC_TEST;

typedef struct tag_CMAC_TEST {
	uint8_t key[256];
	size_t key_len;
	uint8_t data[256];
	size_t data_len;
	uint8_t digest[256];
	size_t digest_len;
} CMAC_TEST;

/* DES test vectors are taken from NIST SP 500-20e 1980, sampled from a much longer test set.
 * The very charming legacy publication can be found here:
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nbsspecialpublication500-20e1980.pdf
 */
DES_TEST des_tests [] = {
	{ { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, { 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 }, {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{ { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, { 0xF1, 0x5D, 0x0F, 0x28, 0x6B, 0x65, 0xBD, 0x28 }, {0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
	{ { 0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, {0x95, 0xA8, 0xD7, 0x28, 0x13, 0xDA, 0xA9, 0x4D} },
	{ { 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, {0x46, 0x15, 0xAA, 0x1D, 0x33, 0xE7, 0x2F, 0x10} },
	{ { 0x7C, 0xA1, 0x10, 0x45, 0x4A, 0x1A, 0x6E, 0x57 }, { 0x01, 0xA1, 0xD6, 0xD0, 0x39, 0x77, 0x67, 0x42 }, {0x69, 0x0F, 0x5B, 0x0D, 0x9A, 0x26, 0x93, 0x9B} }
};

TDES_TEST tdes_tests[] = {
{ { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, { 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 }, {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
{ { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, { 0xF1, 0x5D, 0x0F, 0x28, 0x6B, 0x65, 0xBD, 0x28 }, {0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} },
{ { 0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, {0x95, 0xA8, 0xD7, 0x28, 0x13, 0xDA, 0xA9, 0x4D} },
{ { 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, {0x46, 0x15, 0xAA, 0x1D, 0x33, 0xE7, 0x2F, 0x10} },
{ { 0x7C, 0xA1, 0x10, 0x45, 0x4A, 0x1A, 0x6E, 0x57, 0x7C, 0xA1, 0x10, 0x45, 0x4A, 0x1A, 0x6E, 0x57 }, { 0x01, 0xA1, 0xD6, 0xD0, 0x39, 0x77, 0x67, 0x42 }, {0x69, 0x0F, 0x5B, 0x0D, 0x9A, 0x26, 0x93, 0x9B} }
};

RSA_TEST rsa_tests[] = {
	{{ 0xDE, 0xAD, 0xBE, 0xEF }, RSA_3, 1984},
	{{ 0xDE, 0xAD, 0xBE, 0xEF }, RSA_3, 1024},
	{{ 0xDE, 0xAD, 0xBE, 0xEF }, RSA_F4,2048},
//	{{ 0xDE, 0xAD, 0xBE, 0xEF }, RSA_3, 4096}
};


/*
 * Test vectors sampled from NIST AESAVS, https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers
 * */
AES_TEST aes_tests[] =
{
	{ { 0x10, 0xa5, 0x88, 0x69, 0xd7, 0x4b, 0xe5, 0xa3, 0x74, 0xcf, 0x86, 0x7c, 0xfb, 0x47, 0x38, 0x59}, 128,
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	  { 0x6d, 0x25, 0x1e, 0x69, 0x44, 0xb0, 0x51, 0xe0, 0x4e,0xaa, 0x6f, 0xb4,0xdb, 0xf7, 0x84, 0x65 } },
	{ { 0xfe, 0xbd, 0x9a, 0x24, 0xd8, 0xb6, 0x5c, 0x1c, 0x78, 0x7d, 0x50, 0xa4, 0xed, 0x36, 0x19, 0xa9 }, 128,
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	  { 0xf4, 0xa7, 0x0d, 0x8a, 0xf8, 0x77, 0xf9, 0xb0, 0x2b, 0x4c, 0x40, 0xdf, 0x57, 0xd4, 0x5b, 0x17 } },
	{ { 0xe9, 0xf0, 0x65, 0xd7, 0xc1, 0x35, 0x73, 0x58, 0x7f, 0x78, 0x75, 0x35, 0x7d, 0xfb, 0xb1, 0x6c,
		0x53, 0x48, 0x9f, 0x6a, 0x4b, 0xd0, 0xf7, 0xcd }, 192,
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	  { 0x09, 0x56, 0x25, 0x9c, 0x9c, 0xd5, 0xcf, 0xd0, 0x18, 0x1c, 0xca, 0x53, 0x38, 0x0c, 0xde, 0x06 } },
	{ { 0xc8, 0x8f, 0x5b, 0x00, 0xa4, 0xef, 0x9a, 0x68, 0x40, 0xe2, 0xac, 0xaf, 0x33, 0xf0, 0x0a, 0x3b, 0xdc, 0x4e, 0x25, 0x89, 0x53,
				0x03, 0xfa, 0x72 }, 192,
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	  { 0xa6, 0x7c, 0xf3, 0x33, 0xb3, 0x14, 0xd4, 0x11, 0xd3, 0xc0, 0xae, 0x6e, 0x1c, 0xfc, 0xd8, 0xf5 } },
	{ { 0xc4,0x7b,0x02,0x94,0xdb,0xbb,0xee,0x0f,0xec,0x47,0x57,0xf2,0x2f,0xfe,0xee,0x35,0x87,
			0xca,0x47,0x30,0xc3,0xd3,0x3b,0x69,0x1d,0xf3,0x8b,0xab,0x07,0x6b,0xc5,0x58 }, 256,
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	  { 0x46,0xf2,0xfb,0x34,0x2d,0x6f,0x0a,0xb4,0x77,0x47,0x6f,0xc5,0x01,0x24,0x2c,0x5f } },
	{ { 0xfc,0xa0,0x2f,0x3d,0x50,0x11,0xcf,0xc5,0xc1,0xe2,0x31,0x65,0xd4,0x13,0xa0,0x49,0xd4,0x52,0x6a,
			0x99,0x18,0x27,0x42,0x4d,0x89,0x6f,0xe3,0x43,0x5e,0x0b,0xf6,0x8e }, 256,
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
	  { 0x17,0x9a,0x49,0xc7,0x12,0x15,0x4b,0xbf,0xfb,0xe6,0xe7,0xa8,0x4a,0x18,0xe2,0x20 } }
};

/*
 * Test vectors sampled from NIST HMAC AVS, https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication
 * */

HMAC_TEST hmac_tests[] = {
	{ { 0x82,0xf3,0xb6,0x9a,0x1b,0xff,0x4d,0xe1,0x5c,0x33 }, 10,
		{ 0xfc, 0xd6, 0xd9, 0x8b, 0xef, 0x45, 0xed, 0x68, 0x50, 0x80, 0x6e,
				0x96, 0xf2, 0x55, 0xfa, 0x0c, 0x81, 0x14, 0xb7, 0x28, 0x73,
				0xab, 0xe8, 0xf4, 0x3c, 0x10, 0xbe, 0xa7, 0xc1, 0xdf, 0x70,
				0x6f, 0x10, 0x45, 0x8e, 0x6d, 0x4e, 0x1c, 0x92, 0x01, 0xf0,
				0x57, 0xb8, 0x49, 0x2f, 0xa1, 0x0f, 0xe4, 0xb5, 0x41, 0xd0,
				0xfc, 0x9d, 0x41, 0xef, 0x83, 0x9a, 0xcf, 0xf1, 0xbc, 0x76,
				0xe3, 0xfd, 0xfe, 0xbf, 0x22, 0x35, 0xb5, 0xbd, 0x03, 0x47,
				0xa9, 0xa6, 0x30, 0x3e, 0x83, 0x15, 0x2f, 0x9f, 0x8d, 0xb9,
				0x41, 0xb1, 0xb9, 0x4a, 0x8a, 0x1c, 0xe5, 0xc2, 0x73, 0xb5,
				0x5d, 0xc9, 0x4d, 0x99, 0xa1, 0x71, 0x37, 0x79, 0x69, 0x23,
				0x41, 0x34, 0xe7, 0xda, 0xd1, 0xab, 0x4c, 0x8e, 0x46, 0xd1,
				0x8d, 0xf4, 0xdc, 0x01, 0x67, 0x64, 0xcf, 0x95, 0xa1, 0x1a,
				0xc4, 0xb4, 0x91, 0xa2, 0x64, 0x6b, 0xe1 }, 128,
		{ 0x1b, 0xa0, 0xe6, 0x6c, 0xf7, 0x2e, 0xfc, 0x34, 0x92, 0x07 }, 10
	},
	{
		{ 0x47,0x66,0xe6,0xfe,0x5d,0xff,0xc9,0x8a,0x5c,0x50 }, 10,
		{
		0xd6, 0x8b, 0x82, 0x8a, 0x15, 0x3f, 0x51, 0x98, 0xc0, 0x05, 0xee, 0x36,
		0xc0, 0xaf, 0x2f, 0xf9, 0x2e, 0x84, 0x90, 0x75, 0x17, 0xf0, 0x1d, 0x9b,
		0x7c, 0x79, 0x93, 0x46, 0x9d, 0xf5, 0xc2, 0x10, 0x78, 0xfa, 0x35, 0x6a,
		0x8c, 0x97, 0x15, 0xec, 0xe2, 0x41, 0x4b, 0xe9, 0x4e, 0x10, 0xe5, 0x47,
		0xf3, 0x2c, 0xbb, 0x8d, 0x05, 0x82, 0x52, 0x3e, 0xd3, 0xbb, 0x00, 0x66,
		0x04, 0x6e, 0x51, 0x72, 0x20, 0x94, 0xaa, 0x44, 0x53, 0x3d, 0x2c, 0x87,
		0x6e, 0x82, 0xdb, 0x40, 0x2f, 0xbb, 0x00, 0xa6, 0xc2, 0xf2, 0xcc, 0x34,
		0x87, 0x97, 0x3d, 0xfc, 0x16, 0x74, 0x46, 0x3e, 0x81, 0xe4, 0x2a, 0x39,
		0xd9, 0x40, 0x29, 0x41, 0xf3, 0x9b, 0x5e, 0x12, 0x6b, 0xaf, 0xe8, 0x64,
		0xea, 0x16, 0x48, 0xc0, 0xa5, 0xbe, 0x0a, 0x91, 0x26, 0x97, 0xa8, 0x7e,
		0x4f, 0x8e, 0xab, 0xf7, 0x9c, 0xbf, 0x13, 0x0e }, 128,
		{ 0x00,0x7e,0x45,0x04,0x04,0x1a,0x12,0xf9,0xe3,0x45 }, 10
	},
	{
		{ 0xab,0x69,0x2b,0x9e,0x0d,0x9c,0xc9,0x63,0x27,0x54 }, 10,
		{ 0x49, 0x86,
		0x7d, 0xfd, 0x01, 0x5a, 0x50, 0xdf, 0x8c, 0x67, 0x61, 0x41, 0xee, 0xef,
		0x02, 0xfa, 0x2c, 0x34, 0x75, 0x15, 0xbb, 0x25, 0x02, 0x8d, 0x39, 0x3d,
		0x47, 0x55, 0x5b, 0xa9, 0xd0, 0x9b, 0x27, 0xa9, 0xe7, 0x4e, 0x63, 0x38,
		0xad, 0xde, 0x4d, 0xef, 0x6a, 0x43, 0x8c, 0x27, 0x22, 0x40, 0x67, 0x5e,
		0x69, 0xe9, 0x35, 0xdc, 0x77, 0x63, 0x14, 0x95, 0x7f, 0xeb, 0xde, 0x52,
		0x3d, 0x19, 0x59, 0x0c, 0xcf, 0x66, 0xae, 0x98, 0xc5, 0xed, 0x1d, 0x8a,
		0x7b, 0x6e, 0xee, 0x53, 0xa7, 0x98, 0xab, 0xac, 0x2e, 0x88, 0x8c, 0x38,
		0x3c, 0x8d, 0x33, 0x64, 0x93, 0x2e, 0x99, 0x93, 0x23, 0x6e, 0x49, 0x78,
		0xdb, 0x4e, 0xcc, 0xc2, 0xc0, 0x94, 0x64, 0xff, 0x3c, 0xcb, 0xfd, 0xba,
		0xb8, 0x8b, 0x60, 0xe7, 0x6d, 0xfa, 0xaa, 0x82, 0x76, 0x93, 0xfc, 0x72,
		0x2a, 0x26, 0x75, 0xb3, 0xaa, 0x20 }, 128,
		{ 0x6a,0x31,0xdd,0xba,0xfa,0x48,0x6d,0x1a,0x84,0x7e,0x0b,0x1a }, 12
	}
};

CMAC_TEST cmac_tests[] = {
	{ { 0xf7,0xf9,0x22,0xc8,0x67,0x06,0x27,0x7a,0x4e,0x98,0xd2,0x8e,0x11,0x97,0x41,0x3b }, 16,
	  { 0x33,0xce,0x44,0xbd,0xb1,0xea,0x6f,0xff,0xe5,0xa2,0x90,0x04,0xe2,0xcb,0xf6,0x6c }, 16,
	  { 0xb8,0x76,0x83,0x55,0x64,0x4d,0xf5,0xa9,0xfd,0xff,0x2d,0xef,0x76,0x3f,0x63 }, 15
	},
	{ { 0x77,0xa7,0x7f,0xaf,0x29,0x0c,0x1f,0xa3,0x0c,0x68,0x3d,0xf1,0x6b,0xa7,0xa7,0x7b }, 16,
	  { 0x02, 0x06, 0x83, 0xe1, 0xf0, 0x39, 0x2f, 0x4c, 0xac,
		0x54, 0x31, 0x8b, 0x60, 0x29, 0x25, 0x9e, 0x9c, 0x55, 0x3d, 0xbc, 0x4b,
		0x6a, 0xd9, 0x98, 0xe6, 0x4d, 0x58, 0xe4, 0xe7, 0xdc, 0x2e, 0x13 }, 32,
		{ 0xfb,0xfe,0xa4,0x1b }, 4
	}
};

void DES_example() {
	for (size_t i = 0; i <sizeof(des_tests)/sizeof(des_tests[0]); i++) {

		DES_TEST *p = des_tests+i;
		uint8_t output[8];

		/* output the test data */
		print_test_step(i+1, "Single DES test");
		print_array("\t Input: ", p->data, 8, "\n");
		print_array("\t Key: ", p->key, 8, "\n");

		/* Allocating key schedule. This variable is as sensitive as the key itself and must be purged for safety once not in use */
		DES_key_schedule des_key_schedule;
		/* We can now set the key. There are two options, checked and unchecked. For the purpose
		 * of the demo, we will use unchecked, since the test vector contains weak keys */
		DES_set_key_unchecked((DES_cblock *)p->key, &des_key_schedule);

		/* with the DES_set_key, the result, if not 0, has the following meaning:
		 * -1 means wrong parity
		 * -2 means weak key */

		/* perform the encryption */
		DES_ecb_encrypt((DES_cblock*)&p->data, (DES_cblock*)output, &des_key_schedule, DES_ENCRYPT);
		print_array("\t Output: ", output, 8, "");
		if (!memcmp(output, p->result, 8))
			printf(" - valid\n");
		else
			printf(" - invalid\n");
	}
}

void TDES_example() {
	for (size_t i = 0; i <sizeof(tdes_tests)/sizeof(tdes_tests[0]); i++) {

		TDES_TEST *p = tdes_tests+i;
		uint8_t output[8];

		/* output the test data */
		print_test_step(i+1, "Triple DES test");
		print_array("\t Input: ", p->data, 8, "\n");
		print_array("\t Key: ", p->key, 16, "\n");

		/* Allocating key schedule. This variable is as sensitive as the key itself and must be purged for safety once not in use */
		DES_key_schedule des_key_schedule1, des_key_schedule2;
		/* We can now set the key. There are two options, checked and unchecked. For the purpose
		 * of the demo, we will use unchecked. Each key part goes into a separate key schedule */
		DES_set_key_unchecked((DES_cblock *) p->key, &des_key_schedule1);
		DES_set_key_unchecked((DES_cblock *) (p->key+8), &des_key_schedule2);

		/* with the DES_set_key, the result, if not 0, has the following meaning:
		 * -1 means wrong parity
		 * -2 means weak key */

		/* perform the encryption. Each key schedule is referenced separately */
		DES_ecb2_encrypt((DES_cblock*)&p->data, (DES_cblock*)output, &des_key_schedule1, &des_key_schedule2, DES_ENCRYPT);
		print_array("\t Output: ", output, 8, "");
		if (!memcmp(output, p->result, 8))
			printf(" - valid\n");
		else
			printf(" - invalid\n");
	}
}

void RSA_example(){
	for (size_t i =0; i<sizeof(rsa_tests)/sizeof(RSA_TEST); i++) {
		print_test_step(i+1, "RSA test with a key generation");
		RSA_TEST *p = rsa_tests +i;
		uint8_t test_encrypted[4096];
		uint8_t test_decrypted[4096];
		char error_message_buffer[4096];
		unsigned long error_code = 0;
		/* declaring variables */
		/* basic i/o handle */
		BIO* bio = NULL;
		/* holder for the public exponent. This is usually a small fixed pre-agreed number, most frequently 3 or 65537 */
		BIGNUM *public_exponent = NULL;
		/* holder for all RSA key parts */
		RSA *rsa = NULL;

		/* Initialize the basic i/o abstraction of the SSL library */
		/* In this case, we are going to use memory only. Real-life implementations
		 * can use sockets/files/file descriptors etc.
		 */
		bio = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
		if (!bio) goto cleanup;

		/* Create RSA keys. Note: in real-life implementations this should be done with secure heap instead */

		/* First we initiate the BIGNUM structure to hold the public exponent part*/
		public_exponent = BN_new();
		if (BN_set_word(public_exponent, RSA_3)!=ERR_LIB_NONE)
			goto cleanup;

		/* Initialize the RSA structure */
		rsa = RSA_new();
		if (!rsa) goto cleanup;

		/* Generate a key pair. The random number generator must be seeded before this step with RAND_seed
		 * from a good entropy source such as user mouse movements.
		 *  */
		if (RSA_generate_key_ex(rsa, p->bits, public_exponent, NULL)!=ERR_LIB_NONE)
			goto cleanup;

		/* In case an existing key needs to be used, it should be loaded from a place.
		 * If a custom mechanism is used,  RSA_set0_key(r, n, e, d) will place the key
		 * with modulus n, public e and private d in the RSA structure r for the further use.
		 *
		 * Alternatively, PEM_read_bio_... functions should be used to read/write files in the PEM format.
		 *
		 */

		printf("Successfully generated a keypair\n");
		RSA_print(bio, rsa, 4);

		print_array("Original value: ", p->data, sizeof( p->data), "\n");

		/* Test encryption. The RSA_NO_PADDING is not secure and is not for use in production*/
		int len=RSA_public_encrypt(sizeof( p->data),  p->data, test_encrypted, rsa, RSA_NO_PADDING);

		if (len==-1)
			goto cleanup;

		print_array("Encrypted value: ", test_encrypted, len, "\n");

		/* test decryption */
		len = RSA_private_decrypt(len, test_encrypted, test_decrypted, rsa, RSA_NO_PADDING);
		if (len==-1)
			goto cleanup;

		print_array("Decrypted value: ", test_decrypted, len, "\n");
cleanup:
		/* Handle errors */
		error_code = ERR_get_error();
		if (error_code) {
			ERR_error_string(error_code, error_message_buffer);
			printf("ERROR: %s\n", error_message_buffer);
		}
		/* Free memory */
		/* OpenSSL free functions do nothing if the parameter is null so it is safe to call them w/o checking for NULL */
		BIO_free_all(bio);
		BN_free(public_exponent);
		RSA_free(rsa);
	}
}

void AES_example() {
	for (size_t i =0; i<sizeof(aes_tests)/sizeof(AES_TEST); i++) {
		print_test_step(i+1, "AES test");

		uint8_t output[16];
		AES_TEST *p = aes_tests + i;

		/* Separate methods for encryption and decryption */
		AES_KEY enc_key;
		AES_set_encrypt_key(p->key, p->bits, &enc_key);

		AES_KEY dec_key;
		AES_set_decrypt_key(p->key, p->bits, &dec_key);

		print_array("\t Input data: ", p->data, 16, "\n");
		print_array("\t Key: ", p->key, p->bits>>3, "\n");
		AES_ecb_encrypt(p->data, output, &enc_key, AES_ENCRYPT);
		print_array("\t Output: ", output, 16, "");
		if (!memcmp(output, p->result, 16))
			printf(" - valid\n");
		else
			printf(" - invalid\n");

	}
}

void DH_example() {

	/* Allocate the DH structures */
	DH* dh_a = DH_new();
	DH* dh_b = DH_new();

	/* This is for test printout purposes */
	BIO *bio = NULL;

	/* Since all of these are either taken from or passed to DH functions, the
	 * memory management will be handled by the encapsulating structure. That is,
	 * if a BIGNUM was set into a DH, freeing the DH will take care of the BIGNUM
	 */

	/* BIGNUMs to store the domain parameters*/
	BIGNUM *p = NULL, *g = NULL;
	/* BIGNUMs for the public and private keys of both sides */
	BIGNUM *pubkey_a = NULL, *privkey_a = NULL;
	BIGNUM *pubkey_b = NULL, *privkey_b = NULL;

	/* Memory for the computed keys */
	uint8_t *key_a = NULL, *key_b = NULL;

	/* Initializing secure heap, this should normally be done once */
	CRYPTO_secure_malloc_init(4096<<1, 4096);

	print_test_step(1, "Generating Diffie-Hellman domain parameters");

	/* Generating domain parameters. The random number generator must be seeded before this step with RAND_seed
	 * from a good entropy source such as user mouse movements. For high bit values, this can be REALLY slow.
	 *  */
	if (!DH_generate_parameters_ex(dh_a, 32, DH_GENERATOR_5, NULL))
		goto cleanup;

	/* q is optional */
	DH_get0_pqg(dh_a, (const BIGNUM **)&p,  NULL , (const BIGNUM **)&g);
	printf("\tSide A has generated domain parameters\n");

	printf("\tPrime p: ");
	fflush(stdout); /* Better formatted output*/

	bio = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
	BN_print(bio, p);

	printf("\n\tGenerator g: ");
	fflush(stdout);
	BN_print(bio, g);
	printf("\n");

	print_test_step(2, "Generating side A keys");
	if (!DH_generate_key(dh_a))
		goto cleanup;

	DH_get0_key(dh_a, (const BIGNUM**)&pubkey_a, (const BIGNUM**)&privkey_a);

	printf("\n\tSide A public key: ");
	fflush(stdout);
	BN_print(bio, pubkey_a);

	printf("\n\tSide A private key: ");
	fflush(stdout);
	BN_print(bio, privkey_a);

	/* To communicate the values, they need to be pulled out of BIGNUMs first. This
	 * is easiest done by allocating BN_num_bytes(x) memory and then using BN_bin2bn().
	 * Alternatively, bn2hex() will allocate memory and put there a hexadecimal string
	 * representation of the BIGNUM (the memory will have to be freed with OPENSSL_free()).
	 */
	print_test_step(3, "Importing domain parameters on side B");
	/* The BN_dup is done to avoid double memory freeing when dh_a and dh_b are freed */
	DH_set0_pqg(dh_b, BN_dup(p), NULL, BN_dup(g));

	/* Checking the values */
	int codes = 0;
	DH_check(dh_b, &codes);
	if (codes) /* problems found */
		goto cleanup;
	/* Generating the side B keys */
	if (!DH_generate_key(dh_b))
		goto cleanup;
	printf("\t Domain parameters imported successfully\n");

	print_test_step(4, "Generating keys on side B");
	DH_get0_key(dh_b, (const BIGNUM**)&pubkey_b, (const BIGNUM**)&privkey_b);

	printf("\n\tSide B public key: ");
	fflush(stdout);
	BN_print(bio, pubkey_b);

	printf("\n\tSide B private key: ");
	fflush(stdout);
	BN_print(bio, privkey_b);

	print_test_step(5, "Deriving shared key on side B");
	key_b = CRYPTO_secure_malloc(DH_size(dh_b), __FILE__, __LINE__);
	/* Computing the key from side B's DH structure and side A's public key */
	int key_b_size = DH_compute_key(key_b, pubkey_a, dh_b);
	if (key_b_size<0)
		goto cleanup;

	print_array("\tSide B computed key: ", key_b, key_b_size, "\n");

	print_test_step(6, "Deriving shared key on side A");
	key_a = CRYPTO_secure_malloc(DH_size(dh_a), __FILE__, __LINE__);
	/* Computing the key from side A's DH structure and side B's public key */
	int key_a_size = DH_compute_key(key_a, pubkey_b, dh_a);
	if (key_a_size<0)
		goto cleanup;
	print_array("\tSide A computed key: ", key_a, key_a_size, "\n");

	print_test_step(7, "Comparing keys");
	if (!memcmp(key_a, key_b, key_a_size))
		printf("\tThe keys are equal\n");
	else
		printf("\tThe keys are not equal, something is wrong\n");

cleanup:
	/* These two structures should be purged if the secure heap is not used*/
	if (dh_a)
		DH_free(dh_a);
	if (dh_b)
		DH_free(dh_b);
	if (bio)
		BIO_free(bio);
	if (key_a)
		CRYPTO_secure_free(key_a, __FILE__, __LINE__);
	if (key_b)
		CRYPTO_secure_free(key_b, __FILE__, __LINE__);
	/* shut down the secure heap */
	CRYPTO_secure_malloc_done();
}

void OAEP_example() {

	uint8_t test_padded[4096];

	uint8_t buffer[4096];

	char error_message_buffer[4096];
	unsigned long error_code = 0;
	/* the source length is 4 bytes, the hash is 20 bytes. We need 2 hash values + 2 sentinel bytes, i.e.
	 * total of 42+4 = 46 bytes of length. We will ask to pad for 4 more bytes.
	 */
	int hash_len = 20; /* SHA-1 */
	int total_length = sizeof(rsa_tests[0].data) + 2*hash_len /* SHA-1 hash */ + 2 /* sentinels */ + 4;

	print_test_step(1, "Padding the input data");
	print_array("\tInput data: ", rsa_tests[0].data, sizeof(rsa_tests[0].data), "\n");

	if (!RSA_padding_add_PKCS1_OAEP(test_padded, total_length, rsa_tests[0].data, sizeof(rsa_tests[0].data), NULL, 0))
		goto cleanup;
	print_array("\tPadded output: ", test_padded, total_length, "\n");
	print_test_step(2, "Analyzing the padding");
	if (*test_padded) { /* something is wrong */
		printf("\tFirst byte is not 00, something is off\n");
		goto cleanup;
	}

	printf("\tFirst byte is 00\n");
	print_array("\tThe masked data block is ", test_padded+hash_len+1, total_length-hash_len-1, "\n");
	/* Using the trailing bytes as the seed for the mask of hash_len length */
	if (PKCS1_MGF1( buffer, hash_len, test_padded+hash_len+1, total_length-hash_len-1, EVP_sha1())<0)
		goto cleanup;

	print_array("\tThe mask for the seed is ", buffer, hash_len, "\n");
	print_test_step(2, "Recovering the seed");
	xor_array(test_padded+1, buffer, test_padded+1, hash_len);
	print_array("\tThe data after unmasking the seed:", test_padded, total_length, "\n");

	print_test_step(3, "Recovering the padded data");
	/* Using the trailing bytes as the seed for the mask of hash_len length */
	if (PKCS1_MGF1(buffer, total_length-hash_len-1, test_padded+1, hash_len, EVP_sha1())<0)
		goto cleanup;
	printf("\tThe mask recovered\n");
	xor_array(test_padded+hash_len+1, buffer, test_padded+hash_len+1, total_length-hash_len-1);
	print_array("\tThe recovered data part: ", test_padded+hash_len+1, total_length-hash_len-1, "\n");
	print_array("\t\tLabel hash: ", test_padded+hash_len+1, hash_len, "\n");
	print_array("\t\tPadded data: ", test_padded+2*hash_len+1, total_length-2*hash_len-1, "\n");
	int sentinel_pos = (uint8_t*)memchr(test_padded+2*hash_len+1, 0x01, total_length-2*hash_len-1) - (test_padded+2*hash_len+1);
	printf("\t\tSentinel is in position %d\n", sentinel_pos+1);
	print_array("\t\tOriginal data: ", test_padded+2*hash_len+1+sentinel_pos+1, total_length-2*hash_len-1-sentinel_pos-1, "\n");

cleanup:
	/* Handle errors */
	error_code = ERR_get_error();
	if (error_code) {
		ERR_error_string(error_code, error_message_buffer);
		printf("ERROR: %s\n", error_message_buffer);
	}
}

void DSA_example() {

	/* DSA structures for the algorithm data for the two parties */
	DSA *dsa_a = NULL, *dsa_b = NULL;
	/* BIGNUM pointers for domain parameters */
	BIGNUM *p = NULL, *q = NULL, *g = NULL;

	/* BIGNUM pointers for keys parameters */
	BIGNUM *public_key = NULL, *private_key = NULL;

	/* This is for test printout purposes */
	BIO *bio = NULL;

	uint8_t * sigbuff = NULL;

	dsa_a = DSA_new();
	print_test_step(1, "Generating domain parameters on side A");
	if (!DSA_generate_parameters_ex(dsa_a,
			0, /* the bits parameter is set to the default of 160 */
			NULL, 0, NULL, NULL, NULL))
		goto cleanup;

	DSA_get0_pqg(dsa_a, (const BIGNUM**)&p, (const BIGNUM**)&q, (const BIGNUM**)&g);
	bio = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);

	printf("\tPrime p: ");
	fflush(stdout); /* Better formatted output*/
	BN_print(bio, p);

	printf("\n\tDivisor q: ");
	fflush(stdout); /* Better formatted output*/
	BN_print(bio, q);

	printf("\n\tGenerator g: ");
	fflush(stdout); /* Better formatted output*/
	BN_print(bio, g);
	printf("\n");

	print_test_step(2, "Generating keys on side A");
	if (!DSA_generate_key(dsa_a)) goto cleanup;

	DSA_get0_key(dsa_a, (const BIGNUM**)&public_key, (const BIGNUM**)&private_key);

	printf("\tPublic key: ");
	fflush(stdout); /* Better formatted output*/
	BN_print(bio, public_key);
	printf("\n\tPrivate key: ");
	fflush(stdout); /* Better formatted output*/
	BN_print(bio, private_key);
	printf("\n");

	/* The signature is supposed to be on the message digest, not the full message. For
	 * the sake of simplicity we sign a 4-byte data sequence from an RSA test instead
	 */
	print_test_step(3, "Computing signature");
	sigbuff = (uint8_t*)malloc(DSA_size(dsa_a));
	unsigned int siglen;
	DSA_sign(0, rsa_tests[0].data, sizeof(rsa_tests[0].data), sigbuff, &siglen, dsa_a);

	print_array("\tSignature: ", sigbuff, siglen, "\n");


	dsa_b = DSA_new();
	print_test_step(4, "Importing domain parameters on side B");
	if (!DSA_set0_pqg(dsa_b, p, q, g)) goto cleanup;

	/* Only the public key is being set */
	if (!DSA_set0_key(dsa_b, public_key, NULL)) goto cleanup;

	print_test_step(5, "Validating signature");
	if (DSA_verify(0, rsa_tests[0].data, sizeof(rsa_tests[0].data), sigbuff, siglen, dsa_b) <0) {
		printf("\tVerification failed, something is wrong\n");
		goto cleanup;
	}

	printf("\tSignature is verified");

cleanup:
	if (dsa_a) DSA_free(dsa_a);
	if (bio) BIO_free(bio);
	if (sigbuff) free(sigbuff);
}


void HMAC_example() {
	for (size_t i=0; i < sizeof(hmac_tests)/sizeof(hmac_tests[0]); i++) {
		print_test_step(i+1, "HMAC test");
		HMAC_TEST *p = hmac_tests + i;
		uint8_t output[4096];
		unsigned int out_len;

		/* EVP_*() functions return pointers to various hash function, in this case, we will use SHA-1 */
		/* Note that the HMAC function always returns the full hash output length. If less bytes are required,
		 * it is up to the invoking code to truncate the output.
		 */
		HMAC(EVP_sha1(), p->key, p->key_len, p->data, p->data_len, output, &out_len);

		print_array("\tOutput digest: ", output, p->digest_len, " - ");

		if (!memcmp(output, p->digest, p->digest_len))
			printf("Valid");
		else
			printf("Invalid");

	}
}

void CMAC_example() {
	CMAC_CTX * cmac_ctx = NULL;

	cmac_ctx = CMAC_CTX_new();

	for (size_t i=0; i < sizeof(cmac_tests)/sizeof(cmac_tests[0]); i++) {
		print_test_step(i+1, "CMAC test");
		CMAC_TEST *p = cmac_tests + i;
		uint8_t output[4096];
		size_t out_len;

		print_test_step(1, "Initializing CMAC context");
		/*
		 * Initializing CMAC context.
		 */
		if (!CMAC_Init(cmac_ctx, p->key, p->key_len, EVP_aes_128_cbc(), NULL)) goto cleanup;

		print_test_step(2, "Updating CMAC context with data");
		/*
		 * CMAC_Update places a chunk of data in the CMAC context
		 */
		if (!CMAC_Update(cmac_ctx, p->data, p->data_len)) goto cleanup;

		print_test_step(3, "Finalizing the digest");

		if (!CMAC_Final(cmac_ctx, output, &out_len)) goto cleanup;

		print_array("\tOutput digest: ", output, p->digest_len, " - ");

		if (!memcmp(output, p->digest, p->digest_len))
			printf("Valid");
		else
			printf("Invalid");
	}
cleanup:
	if (cmac_ctx) CMAC_CTX_free(cmac_ctx);
}

int main (void) {
	for (size_t c = 0; c< sizeof(crypto_tests)/sizeof(TEST); c++)
		run_test(crypto_tests+c);

}

