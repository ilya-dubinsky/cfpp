#include "jose.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include "test_io.h"

/* Examples below taken from RFC 7516 */
uint8_t rsa_pub_key[] = { 0xa1, 0xa8, 0x54, 0x22, 0x85, 0xb0, 0xd0, 0xad, 0x2e,
		0xb0, 0xa3, 0x6e, 0x39, 0x1e, 0x87, 0xe3, 0x09, 0x1f, 0xe2, 0x80, 0x54,
		0x5c, 0x74, 0xf1, 0x46, 0xf8, 0x1b, 0xe3, 0xc1, 0x3e, 0x05, 0x5b, 0xf1,
		0x91, 0xe0, 0xcd, 0x8d, 0xb0, 0xb8, 0x85, 0xef, 0x2b, 0x51, 0x67, 0x09,
		0xa1, 0x99, 0x9d, 0xb3, 0x68, 0x7b, 0x33, 0xbd, 0x22, 0x98, 0x45, 0x61,
		0x45, 0x4e, 0x5d, 0x8c, 0x83, 0x57, 0xb6, 0xa9, 0x65, 0x5c, 0x8e, 0x03,
		0x16, 0xa7, 0x08, 0xd4, 0x38, 0x23, 0x4f, 0xd2, 0xde, 0xc0, 0xd0, 0xfc,
		0x31, 0x6d, 0x8a, 0xad, 0xfd, 0xd2, 0xa6, 0xc9, 0x3f, 0x66, 0x4a, 0x05,
		0x9e, 0x29, 0x5a, 0x90, 0x6c, 0xa0, 0x4f, 0x0a, 0x59, 0xde, 0xe7, 0xac,
		0x1f, 0xe3, 0xc5, 0x00, 0x13, 0x48, 0x51, 0x8a, 0x4e, 0x88, 0xdd, 0x79,
		0x76, 0xc4, 0x11, 0x92, 0x0a, 0xf4, 0xbc, 0x48, 0x71, 0x37, 0xdd, 0xa2,
		0xd9, 0xab, 0x1b, 0x39, 0xe9, 0xd2, 0x65, 0xec, 0x9a, 0xc7, 0x38, 0x8a,
		0xef, 0x65, 0x30, 0xc6, 0xba, 0xca, 0xa0, 0x4c, 0x6f, 0xea, 0x47, 0x39,
		0xb7, 0x05, 0xd3, 0xab, 0x88, 0x7e, 0x40, 0x28, 0x4b, 0x3a, 0x59, 0xf4,
		0xfe, 0x6b, 0x54, 0x67, 0x07, 0xec, 0x45, 0xa3, 0x12, 0xb4, 0xfb, 0x3a,
		0x99, 0x2e, 0x97, 0xae, 0x0c, 0x67, 0xc5, 0xb5, 0xa1, 0xa2, 0x37, 0xfa,
		0xeb, 0x7b, 0x6e, 0x11, 0x0b, 0x9e, 0x18, 0x2f, 0x85, 0x08, 0xc7, 0xeb,
		0x6b, 0x7e, 0x82, 0xf6, 0x49, 0xc3, 0x14, 0x6c, 0xca, 0xb0, 0xd6, 0xbb,
		0x2d, 0x92, 0xb6, 0x76, 0x36, 0x20, 0xc8, 0x3d, 0xc9, 0x47, 0xf3, 0x01,
		0xff, 0x83, 0x54, 0x25, 0x6f, 0xd3, 0xa8, 0xe4, 0x2d, 0xc0, 0x76, 0x1b,
		0xc5, 0xeb, 0xe8, 0x24, 0x0a, 0xe6, 0xf8, 0xbe, 0x52, 0xb6, 0x8c, 0x23,
		0xcc, 0x6c, 0xbe, 0xfd, 0xba, 0xba, 0x1b };

uint8_t ec_x[] = { 0x4d, 0x4b, 0x42, 0x43, 0x54, 0x4e, 0x49, 0x63, 0x4b, 0x55,
		0x53, 0x44, 0x69, 0x69, 0x31, 0x31, 0x79, 0x53, 0x73, 0x33, 0x35, 0x32,
		0x36, 0x69, 0x44, 0x5a, 0x38, 0x41, 0x69, 0x54, 0x6f, 0x37, 0x54, 0x75,
		0x36, 0x4b, 0x50, 0x41, 0x71, 0x76, 0x37, 0x44, 0x34 };
uint8_t ec_y[] = { 0xe0, 0x4b, 0x65, 0xe9, 0x24, 0x56, 0xd9, 0x88, 0x8b, 0x52,
		0xb3, 0x79, 0xbd, 0xfb, 0xd5, 0x1e, 0xe8, 0x69, 0xef, 0x1f, 0x0f, 0xc6,
		0x5b, 0x66, 0x59, 0x69, 0x5b, 0x6c, 0xce, 0x08, 0x17, 0x23 };

typedef struct tagJWE_TEST { /* Note: this fits only for RSA_OAEP tests with the public key above */
	uint8_t enc_algorithm;
	uint8_t * payload;
	size_t payload_len;
	uint8_t *cek;
	size_t cek_len;
	uint8_t *iv;
	size_t iv_len;
	uint8_t *result_payload;
	size_t result_payload_len;
	uint8_t *result_mac;
	size_t result_mac_len;
} JWE_TEST;

static uint8_t rfc_7516_test_payload_gcm[] = { 84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105,
		103, 110, 32, 111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101,
		110, 99, 101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119,
		108, 101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
		110, 97, 116, 105, 111, 110, 46 };

static uint8_t test_payload_hmac[] = { 76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
		   112, 114, 111, 115, 112, 101, 114, 46 };

static uint8_t rfc_7516_test_cek_gcm[] = { 177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255,
		107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46,
		122, 234, 64, 252 };

static uint8_t test_cek_hmac[] = { 4, 211, 31, 197, 84, 157, 252, 254,
		11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9,
		219, 200, 177, 0, 240, 143, 156, 44, 207 };

static uint8_t rfc_7516_test_iv_gcm [] = {227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219};

static uint8_t test_iv_hmac[] = { 3, 22, 60, 12, 43, 67, 104, 105, 108,
		108, 105, 99, 111, 116, 104, 101 };

static uint8_t rfc_7516_test_result_enc_payload_gcm [] = {229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
		   233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
		   104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
		   123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
		   160, 109, 64, 63, 192};

static uint8_t test_result_enc_payload_hmac[] = { 0x78, 0x9C, 0x99, 0x5B, 0x5A,
		0x07, 0xE9, 0x38, 0x5F, 0xDE, 0x6D, 0xD9, 0x86, 0x3A, 0x66, 0x2E };


static uint8_t rfc_7516_test_result_mac_gcm [] = {92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
		   210, 145};

static uint8_t test_result_mac_hmac[] = {83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
		   194, 85};

JWE_TEST jwe_tests[] = {
	{
		JOSE_AES_128_GCM, 		/* algorithm*/
		rfc_7516_test_payload_gcm, 		/* test payload from RFC 7516 */
		sizeof(rfc_7516_test_payload_gcm),
		rfc_7516_test_cek_gcm, 			/* test CEK from RFC 7516 */
		sizeof(rfc_7516_test_cek_gcm),
		rfc_7516_test_iv_gcm,			/* test IV from RFC 7516 */
		sizeof(rfc_7516_test_iv_gcm),
		rfc_7516_test_result_enc_payload_gcm,
		sizeof(rfc_7516_test_result_enc_payload_gcm),
		rfc_7516_test_result_mac_gcm,
		sizeof(rfc_7516_test_result_mac_gcm)
	},
	{
		JOSE_AES_128_CBC_HS_256, 		/* algorithm*/
		test_payload_hmac, 		/* test payload */
		sizeof(test_payload_hmac),
		test_cek_hmac, 			/* test CEK */
		sizeof(test_cek_hmac),
		test_iv_hmac,					/* test IV  */
		sizeof(test_iv_hmac),
		test_result_enc_payload_hmac,
		sizeof(test_result_enc_payload_hmac),
		test_result_mac_hmac,
		sizeof(test_result_mac_hmac)
	}
};

void test_jwk_rsa () {
	RSA_PARAMS p;
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();

	BN_set_word(e, RSA_F4);
	BN_bin2bn(rsa_pub_key, sizeof(rsa_pub_key), n);

	p.n = n;
	p.e = e;

	char* jose = jose_create_jwk(JOSE_KEY_TYPE_RSA, JOSE_KEY_USE_ENC, NULL, &p);
	printf("%s\n", jose);
	free (jose);

	if (n) BN_free(n);
	if (e) BN_free(e);
}

void test_jwk_ec() {
	EC_PARAMS q;

	BIGNUM *x = BN_bin2bn(ec_x, sizeof(ec_x), NULL);
	BIGNUM *y = BN_bin2bn(ec_y, sizeof(ec_y), NULL);
	q.x = x;
	q.y = y;
	q.curve = JOSE_KEY_EC_CURVE_P256;

	char * jose = jose_create_jwk(JOSE_KEY_TYPE_EC, JOSE_KEY_USE_NONE, NULL, &q);
	printf("%s\n", jose);
	free (jose);

	BN_free(x);
	BN_free(y);
}

void test_jwe( void * data) {
	/* Prepare the public RSA key */
	RSA_PARAMS rsa_params;
	BIGNUM *n = BN_bin2bn(rsa_pub_key, sizeof(rsa_pub_key), NULL);

	BIGNUM *e = BN_new();
	BN_set_word(e, RSA_F4);

	rsa_params.n = n;
	rsa_params.e = e;

	JWE_TEST *p  = (JWE_TEST*) data;

	print_array("\tInput payload:", p->payload, p->payload_len, "\n");
	print_array("\tExpected encrypted payload:", p->result_payload, p->result_payload_len,
			"\n\tNote: valid only if the RFC_5716_TEST #define is on\n");
	print_array("\tExpected output signature:", p->result_mac, p->result_mac_len, "\n");

	char *jose = jose_create_jwe(JOSE_RSA_OAEP_256, p->enc_algorithm,
			p->cek, p->cek_len, &rsa_params,
			p->iv, p->iv_len, p->payload, p->payload_len);
	printf("\n\nThe output:\n\t%s\n", jose);

	if (jose) free (jose);

	BN_free(n);
	BN_free(e);
}

TEST jose_tests[] = {
	{ "JWK for an RSA public key", test_jwk_rsa, NULL },
	{ "JWK for an EC public key", test_jwk_ec, NULL },
	{ "JWE for RSA OAEP and AES-256 in GCM mode", test_jwe, &jwe_tests[0] },
	{ "JWE for RSA OAEP and AES-256 with H256", test_jwe, &jwe_tests[1] },
};


int main(void) {
	for (size_t c = 0; c< sizeof(jose_tests)/sizeof(TEST); c++)
		run_test(jose_tests+c);

}
