
#ifndef CFPP_SRC_DUKPT_H_
#define CFPP_SRC_DUKPT_H_

#include <stdlib.h>

#define DUKPT_SUCCESS 0
#define DUKPT_ERROR -1

#define DUKPT_DES_KSN_LEN 10
#define DUKPT_AES_KSN_LEN 12

#define DUKPT_DES_KEY_TYPE_PIN 		0
#define DUKPT_DES_KEY_TYPE_MAC_REQ  1
#define DUKPT_DES_KEY_TYPE_MAC_RES  2
#define DUKPT_DES_KEY_TYPE_ENC_REQ  3
#define DUKPT_DES_KEY_TYPE_ENC_RES  4

#define DUKPT_DES_VALID_KEY_TYPE(x) ((DUKPT_DES_KEY_TYPE_PIN<= (x)) && (DUKPT_DES_KEY_TYPE_ENC_RES >=(x)))

#define DUKPT_AES_TDES_2  0x0000
#define DUKPT_AES_TDES_3  0x0001
#define DUKPT_AES_AES_128 0x0002
#define DUKPT_AES_AES_192 0x0003
#define DUKPT_AES_AES_256 0x0004

#define DUKPT_AES_VALID_ALGO(x) ( (DUKPT_AES_TDES_2<=(x)) && (DUKPT_AES_AES_256>=(x)) )

#define DUKPT_AES_USAGE_INTERMEDIATE 	0x8000
#define DUKPT_AES_USAGE_INITIAL 		0x8001
#define DUKPT_AES_USAGE_KEK 			0x0002
#define DUKPT_AES_USAGE_PIN_ENC 		0x1000
#define DUKPT_AES_USAGE_MAC_GEN 		0x2000
#define DUKPT_AES_USAGE_MAC_VER 		0x2001
#define DUKPT_AES_USAGE_MAC_BOTH 		0x2002
#define DUKPT_AES_USAGE_DATA_ENC		0x3000
#define DUKPT_AES_USAGE_DATA_DEC 		0x3001
#define DUKPT_AES_USAGE_DATA_BOTH 		0x3002


/**
 * Derives the initial key.
 * @param bdk the Base Derivation Key
 * @param bdk_len the Base Derivation Key lenght
 * @param ksn the Key Serial Number
 * @param algorithm TDES or AES
 * @param output the output buffer
 */
int dukpt_derive_initial_key(uint8_t* bdk, size_t bdk_len, uint8_t * ksn, int algorithm, uint8_t * output);

/** Derives an intermediate key based on a KSN.
 * @param initial_key the IK. Assumed to be a double-length TDES key.
 * @param ksn the KSN. Assumed to be of the correct length.
 * @param output the output buffer. Assumed to be sufficient for a double-length TDES key.
 * @result DUKPT_SUCCESS or DUKPT_ERROR
 */
int dukpt_des_derive_intermediate_key (uint8_t * initial_key, uint8_t * ksn, uint8_t *output );

/** Generates a worker key from an intermediate key.
 * @param intermediate_key intermediate key, assumed a double-length TDES key
 * @param key_type type of key to generate
 * @output output buffer
 * @result DUKPT_SUCCESS if successful or DUKPT_ERROR otherwise
 */
int dukpt_des_derive_worker_key (uint8_t * intermediate_key, int key_type, uint8_t * output );

/** Derives the initial key based on the BDK.
 * @param base_key the input key
 * @param base_key_len the input key length
 * @param algo desired algorithm for the key
 * @param KSN the ksn
 * @param output buffer for the key output, size is according to the desired algorithm
 * @result actual key length if successful, DUKPT_ERROR otherwise
 */
int dukpt_aes_derive_initial_key(uint8_t *base_key, size_t base_key_len,
		uint16_t algo, uint8_t *ksn, uint8_t *output);

/** Derives an intermediate key based on a KSN.
 * @param initial_key the IK. Assumed to be an 128-bit AES key.
 * @param ksn the KSN. Assumed to be of the correct length.
 * @param output the output buffer. Assumed to be sufficient for an 128-bit AES key.
 * @result DUKPT_SUCCESS or DUKPT_ERROR
 */
int dukpt_aes_derive_intermediate_key (uint8_t * initial_key, uint8_t * ksn, uint8_t *output );

/**
 * Derives a worker key from AES 128 for an AES 128 encryption algorithm.
 * @param inter_key an intermediate key
 * @param usage key usage
 * @param ksn current ksn
 * @param output output buffer
 * @result actual key length or DUKPT_ERROR if derivation failed
 */
int dukpt_aes_derive_worker_key(uint8_t *inter_key, uint16_t usage, uint8_t *ksn, uint8_t *output);

#endif /* CFPP_SRC_DUKPT_H_ */
