#ifndef __CFPP_EMV_H_
#define __CFPP_EMV_H_

#include <stdlib.h>

#include "crypto.h"

#include <openssl/rsa.h>

#define EMV_SIGNATURE_B 0x6A
#define EMV_SIGNATURE_E 0xBC

#define EMV_HASH_SIZE 20

#define EMV_ATC_LENGTH 2

#define EMV_ERROR -1
#define EMV_SUCCESS 0

#define EMV_MAX_CA_KEY_SIZE 248 /* according to the standard, max len of the CA PK is 248 */

#define EMV_MAX_ISS_KEY_LEN (EMV_MAX_CA_KEY_SIZE-36)
#define EMV_MAX_ICC_KEY_LEN (EMV_MAX_CA_KEY_SIZE-42)

#define EMV_LARGE_BUFFER 4096

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

typedef struct tag_ICC_PK_DETAILS_HEADER {
	uint8_t sentinel;
	uint8_t certificate_format;
	uint8_t applicaton_pan[10];
	uint8_t certificate_expiration[2];
	uint8_t certificate_serial[3];
	uint8_t hash_algo;
	uint8_t icc_pk_algo;
	uint8_t icc_pk_len;
	uint8_t icc_pk_exponent_len;
} ICC_PK_DETAILS_HEADER;

typedef struct tag_SDA_DETAILS_HEADER {
	uint8_t sentinel;
	uint8_t sda_format;
	uint8_t hash_algo;
	uint8_t data_auth_code [2];
} SDA_DETAILS_HEADER;

typedef struct tag_DDA_DETAILS_HEADER {
	uint8_t sentinel;
	uint8_t dda_format;
	uint8_t hash_algo;
	uint8_t dd_len;
} DDA_DETAILS_HEADER;


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
int emv_recover_issuer_public_key(uint8_t ca_pk_idx, uint8_t *issuer_pk_cert, size_t issuer_pk_cert_len,
		uint8_t *issuer_pk_remainder, size_t issuer_pk_remainder_len,  uint32_t issuer_pk_exponent,
		uint8_t *recovered_key_buf, ISSUER_PK_DETAILS_HEADER* details_header);

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
		uint8_t * output, ICC_PK_DETAILS_HEADER *header, uint8_t * static_data, size_t static_data_len);

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
		uint8_t * auth_data, size_t auth_data_len, SDA_DETAILS_HEADER * header);


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
		uint32_t icc_pk_exponent, uint8_t *term_data, size_t term_data_len, DDA_DETAILS_HEADER *dda_details);
/**
 * Derive ICC Master key from an IMK
 * @param unpacked_pan unpacked BCD pan
 * @param unpacked_pan_len length of the pan
 * @param unpacked_csn unpacked CSN
 * @param encryption_key encryption key
 * @param encryption_Key_len length of the encryption key
 * @param algorithm, ALGORITHM_TDES or ALGORITHM_AES
 * @param output output buffer
 * @param output_len output buffer length
 */
int emv_derive_icc_master_key(uint8_t *unpacked_pan, size_t unpacked_pan_len, uint8_t *unpacked_csn,
		uint8_t *encryption_key, size_t encryption_key_len, int algorithm, uint8_t *output, size_t output_len);

int emv_derive_icc_session_key(uint8_t *icc_master_key,
		size_t icc_master_key_length, int algorithm, uint8_t *atc, uint8_t *output, size_t output_len);


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
 * @param output_remainder_len Actual remainder length will be updated
 * @result EMV_SUCCESS if successful, EMV_ERROR otherwise
 */
int emv_sign_issuer_public_key(uint8_t ca_index, uint8_t * issuer_pk, uint32_t issuer_pk_exponent,
		ISSUER_PK_DETAILS_HEADER * issuer_details, uint8_t * output_cert, size_t* output_cert_len,
		uint8_t * output_remainder, size_t* output_remainder_len);

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
int emv_sign_icc_public_key(uint8_t * icc_pub_key, size_t cc_pub_key_len,
		uint32_t issuer_pk_exponent,  uint8_t * issuer_priv_key, size_t issuer_priv_key_len,
		uint8_t * icc_pk, uint32_t icc_pk_exponent,
		ICC_PK_DETAILS_HEADER * icc_details, uint8_t *auth_data, size_t auth_data_len,
		uint8_t * output_cert,
		uint8_t * output_remainder, size_t* output_remainder_len);

/**
 * Signs the static data for SDA with the provided issuer key
 * @param issuer_pub_key Issuer public key (modulus)
 * @param issuer_pub_key_len Length of issuer public key
 * @param issuer_pk_exponent Exponent for the issuer public key
 * @param issuer_priv_key Issuer private key
 * @param issuer_priv_key_len Length of issuer private key
 * @param auth_data Additional authentication data
 * @param auth_data_len Length of the additional data
 * @param sda_details SDA details header
 * @output points to the output buffer
 * @result length of the SDA, or EMV_ERROR if an error has occurred
 */
int emv_sign_static_data(uint8_t * icc_pub_key, size_t cc_pub_key_len,
		uint32_t issuer_pk_exponent, uint8_t *issuer_priv_key, size_t issuer_priv_key_len,
		uint8_t *auth_data, size_t auth_data_len, SDA_DETAILS_HEADER *sda_details,
		uint8_t *output);


/**
 * Signs the dynamic data for DDA with the provided ICC key
 * @param icc_pub_key Issuer public key (modulus)
 * @param icc_pub_key_len Length of issuer public key
 * @param icc_pk_exponent Exponent for the issuer public key
 * @param icc_priv_key Issuer private key
 * @param icc_priv_key_len Length of issuer private key
 * @param icc_data ICC dynamic authentication data
 * @param term_data Terminal dynamic authentication data
 * @param term_data_len Length of the terminal additional data
 * @param dda_details DDA details header
 * @output points to the output buffer
 * @result length of the DDA, or EMV_ERROR if an error has occurred
 */
int emv_sign_dynamic_data(uint8_t * icc_pub_key, size_t icc_pub_key_len,
		uint32_t icc_pk_exponent, uint8_t *icc_priv_key, size_t icc_priv_key_len,
		uint8_t *icc_data, uint8_t *term_data, size_t term_data_len, DDA_DETAILS_HEADER *dda_details,
		uint8_t *output);


/* prints the issuer PK details header in a human-readable format */
void print_issuer_pk_details_header(ISSUER_PK_DETAILS_HEADER* header);

/* prints the ICC PK details header in a human-readable format */
void print_icc_pk_details_header(ICC_PK_DETAILS_HEADER * header);

#endif /* EMV_H_ */
