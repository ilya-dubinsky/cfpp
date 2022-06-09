#ifndef __CFPP_EMV_H_
#define __CFPP_EMV_H_

#include <stdlib.h>

#include "crypto.h"

#define EMV_SIGNATURE_B 0x6A
#define EMV_SIGNATURE_E 0xBC

#define EMV_HASH_SIZE 20

#define EMV_ATC_LENGTH 2

#define EMV_ERROR -1
#define EMV_SUCCESS 0

typedef struct tag_ISSUER_PK_DETAILS_HEADER {
	uint8_t sentinel;
	uint8_t certificate_format;
	uint8_t issuer_identifier[4];
	uint8_t certificate_expiration[2];
	uint8_t certificate_serial[3];
	uint8_t hash_algo;
	uint8_t issuer_pk_algo;
	uint8_t issuer_pk_len;
	uint8_t issuer_pk_exponent_len;
} ISSUER_PK_DETAILS_HEADER;

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
		size_t issuer_pk_remainder_len,  uint32_t issuer_pk_exponent, uint8_t *recovered_key_buf, ISSUER_PK_DETAILS_HEADER* details_header);

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
		uint8_t *encryption_key, size_t encryption_key_len, int algorithm, uint8_t *output, size_t output_len);

int derive_icc_session_key(uint8_t *icc_master_key,
		size_t icc_master_key_length, int algorithm, uint8_t *atc, uint8_t *output,
		size_t output_len);
#endif /* EMV_H_ */
