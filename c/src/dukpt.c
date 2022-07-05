/*
 * dukpt.c
 *
 *  Created on: 26 Jun 2022
 *      Author: idubinsky
 */
#include "dukpt.h"
#include "crypto.h"
#include "bits.h"
#include "test_io.h"

#include <openssl/des.h>
#include <openssl/aes.h>

#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* remove this later */
typedef uint16_t __uint16_t;
typedef uint32_t __uint32_t;

#define DUKPT_KDF_VERSION 0x01

#define DUKPT_IS_DATA_ENC_KEY(x) ( DUKPT_DES_KEY_TYPE_ENC_REQ==(x) || DUKPT_DES_KEY_TYPE_ENC_RES==(x) )

#define DUKPT_AES_EXTRA_DATA_LEN 8

static int dukpt_des_derive_initial_key (uint8_t* bdk, uint8_t * ksn, uint8_t * output);

static uint8_t tdes_bdk_ik_key_variant[] = { 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00,
		0x00, 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00 };

static uint8_t tdes_pin_enc_variant[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };

static uint8_t tdes_mac_variant_req[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00 };

static uint8_t tdes_mac_variant_res[] = { 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00 };

static uint8_t tdes_data_enc_variant_req[] = { 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00 };

static uint8_t tdes_data_enc_variant_res[] = { 0x00, 0x00, 0x00, 0xFF, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00 };

typedef struct tagDUKPT_AES_KDF_INPUT {
	uint8_t version;
	uint8_t counter;
	uint8_t usage[2];
	uint8_t algorithm[2];
	uint8_t key_len[2];
	uint8_t ksn[DUKPT_AES_EXTRA_DATA_LEN];
} DUKPT_AES_KDF_INPUT;

static uint16_t aes_kdf_key_length[] = {
	16, /* DUKPT_AES_TDES_2  */
	24, /* DUKPT_AES_TDES_3  */
	16, /* DUKPT_AES_AES_128 */
	24, /* DUKPT_AES_AES_192 */
	32  /* DUKPT_AES_AES_256 */
};

static uint8_t* tdes_key_variants[] =
{
	tdes_pin_enc_variant, /* DUKPT_KEY_TYPE_PIN */
	tdes_mac_variant_req, /* DUKPT_KEY_TYPE_MAC_REQ */
	tdes_mac_variant_res, /* DUKPT_KEY_TYPE_MAC_RES */
	tdes_data_enc_variant_req, /* DUKPT_KEY_TYPE_ENC_REQ */
	tdes_data_enc_variant_res /* DUKPT_DES_KEY_TYPE_ENC_RES */
};

static int dukpt_des_derive_intermediate_key_step ( uint8_t * prev_key, uint8_t * ksn, uint8_t * output);

static int dukpt_aes_kdf(uint8_t *base_key, size_t base_key_len, uint16_t usage,
		uint16_t algo, uint8_t *ksn, uint8_t *output);
/**
 * Derives the initial key.
 * @param bdk the Base Derivation Key
 * @param bdk_len the Base Derivation Key lenght
 * @param ksn the Key Serial Number
 * @param algorithm TDES or AES
 * @param output the output buffer
 */
int dukpt_derive_initial_key(uint8_t* bdk, size_t bdk_len, uint8_t * ksn, int algorithm, uint8_t * output) {

	int result = DUKPT_ERROR;
	/* validate the inputs */
	if (! (bdk && bdk_len && ksn && output )) return DUKPT_ERROR;

	algorithm &= 0x1;

	if (ALGORITHM_TDES == algorithm && (TDES_KEY_LENGTH_2!= bdk_len)) return DUKPT_ERROR;

	if (ALGORITHM_TDES == algorithm)
		return dukpt_des_derive_initial_key(bdk, ksn, output);
	else
		return dukpt_aes_derive_initial_key(bdk, bdk_len, DUKPT_AES_AES_128, ksn, output);

	return result;
}

/** Derives an intermediate key based on a KSN.
 * @param initial_key the IK. Assumed to be a double-length TDES key.
 * @param ksn the KSN. Assumed to be of the correct length.
 * @param output the output buffer. Assumed to be sufficient for a double-length TDES key.
 * @result DUKPT_SUCCESS or DUKPT_ERROR
 */
int dukpt_des_derive_intermediate_key (uint8_t * initial_key, uint8_t * ksn, uint8_t *output ) {
	/* validate inputs */
	if ( !(initial_key&&ksn&&output)) return DUKPT_ERROR;

	uint8_t ksn_reg[DUKPT_DES_KSN_LEN];
	uint8_t current_key[TDES_KEY_LENGTH_2];

	memcpy(ksn_reg, ksn, DUKPT_DES_KSN_LEN);
	memcpy(current_key, initial_key, TDES_KEY_LENGTH_2);

	print_array("\tDeriving for KSN: ", ksn_reg, DUKPT_DES_KSN_LEN, "\n");
	/* prepare the shift register */
	uint8_t tc_staging[4];
	memcpy(tc_staging, ksn_reg+DUKPT_DES_KSN_LEN-4, 4);
	uint32_t shift_reg = ntohl(*((uint32_t*) (tc_staging)));

	shift_reg&= 0x001FFFFFL;

	/* reset the KSN to zero */
	ksn_reg[DUKPT_DES_KSN_LEN-1]=0;
	ksn_reg[DUKPT_DES_KSN_LEN-2]=0; /* 16 bit */
	ksn_reg[DUKPT_DES_KSN_LEN-3] &= 0xE0; /* 5 more bits */

	/* main derivation loop */
	while (shift_reg) {
		size_t msb = log2_32(shift_reg);
		size_t byte_idx = DUKPT_DES_KSN_LEN-1-(msb/8);
		size_t bit_idx = (msb %8);
		/* set the appropriate bit in the KSN */
		ksn_reg[byte_idx] |= (1<<bit_idx);
		/* clear the appropriate bit in the shift reg */
		shift_reg ^= 1L<<msb;

		print_array("\tDeriving for KSN: ", ksn_reg, DUKPT_DES_KSN_LEN, "\n");
		/* derive the intermediate key from the previous value */
		dukpt_des_derive_intermediate_key_step(current_key, ksn_reg, current_key);
		print_array("\tResulting key:    ", current_key, TDES_KEY_LENGTH_2, "\n");
	}

	memcpy(output, current_key, TDES_KEY_LENGTH_2);

	return DUKPT_SUCCESS;
}

/** Generates a worker key from an intermediate key.
 * @param intermediate_key intermediate key, assumed a double-length TDES key
 * @param key_type type of key to generate
 * @output output buffer
 * @result DUKPT_SUCCESS if successful or DUKPT_ERROR otherwise
 */
int dukpt_des_derive_worker_key (uint8_t * intermediate_key, int key_type, uint8_t * output ) {
	/* validate the inputs */
	if (! (intermediate_key && output)) return DUKPT_ERROR;

	if (!DUKPT_DES_VALID_KEY_TYPE(key_type)) return DUKPT_ERROR;

	uint8_t key_buffer[TDES_KEY_LENGTH_2];
	DES_key_schedule key1, key2;


	if (!DUKPT_IS_DATA_ENC_KEY(key_type)) {
		/* apply simple mask */
		xor_array(intermediate_key, tdes_key_variants[key_type], output, TDES_KEY_LENGTH_2);
	} else  {
		/* apply the variant */
		xor_array(intermediate_key, tdes_key_variants[key_type], key_buffer, TDES_KEY_LENGTH_2);

		DES_set_key_unchecked((const_DES_cblock*) key_buffer, &key1);
		DES_set_key_unchecked((const_DES_cblock*) (key_buffer +TDES_KEY_LENGTH_1), &key2);

		print_array("\t\tIntermediate key with a variant: ", key_buffer, TDES_KEY_LENGTH_2, "\n");

		memset(output, 0, TDES_KEY_LENGTH_2);
		/* encrypt each half of the key with itself */
		DES_ecb2_encrypt((const_DES_cblock* )key_buffer, (DES_cblock* )output,
				&key1, &key2, DES_ENCRYPT);
		DES_ecb2_encrypt((const_DES_cblock*)(key_buffer+TDES_KEY_LENGTH_1),
				(DES_cblock* )(output + TDES_KEY_LENGTH_1), &key1, &key2, DES_ENCRYPT);
	}

	PURGE(key_buffer);
	PURGE(key1);
	PURGE(key2);
	return DUKPT_SUCCESS;
}

/* performs a single step of an intermediate key derivation */
static int dukpt_des_derive_intermediate_key_step ( uint8_t * prev_key, uint8_t * ksn, uint8_t * output) {
	/* validate inputs */
	if (! (prev_key && ksn && output)) return DUKPT_ERROR;
	uint8_t crypto_reg1[TDES_BLOCK_SIZE];
	uint8_t crypto_reg2[TDES_BLOCK_SIZE];
	uint8_t key[TDES_KEY_LENGTH_2];

	memset(crypto_reg1, 0, TDES_BLOCK_SIZE);
	memset(crypto_reg2, 0, TDES_BLOCK_SIZE);

	DES_key_schedule des_key;

	memcpy(key, prev_key, TDES_KEY_LENGTH_2);

	print_array("\t\tLeft key half:  ", key, TDES_BLOCK_SIZE, "\n");
	print_array("\t\tRight key half: ", key+TDES_BLOCK_SIZE, TDES_BLOCK_SIZE, "\n");

	memcpy(crypto_reg1, ksn + (DUKPT_DES_KSN_LEN-TDES_BLOCK_SIZE), TDES_BLOCK_SIZE);

	print_array("\t\tRight KSN half: ", crypto_reg1, TDES_BLOCK_SIZE, "\n");
	/* the output key is derived by encrypting the 64 rightmost bits of KSN using the process below */

	/* left half of the KSN is XORed with the right half of the key and stored in crypto reg 2*/
	xor_array(crypto_reg1, key+TDES_BLOCK_SIZE, crypto_reg2, TDES_BLOCK_SIZE);
	print_array("\t\t(ccc): KSN XORed with key2: ", crypto_reg2, TDES_BLOCK_SIZE, "\n");

	/* crypto reg 2 is encrypted with left half of the key and stored in crypto reg 2 */
	DES_set_key_unchecked((const_DES_cblock*) key, &des_key);
	DES_ecb_encrypt((const_DES_cblock*) crypto_reg2, (DES_cblock*)crypto_reg2, &des_key, DES_ENCRYPT);
	print_array("\t\t(ddd): Encrypted with key1: ", crypto_reg2, TDES_BLOCK_SIZE, "\n");

	/* crypto reg 2 is XORed with the right half of the key and stored in crypto reg 2*/
	xor_array(crypto_reg2, key+TDES_BLOCK_SIZE, crypto_reg2, TDES_BLOCK_SIZE);
	print_array("\t\t(eee): XORed with key2:     ", crypto_reg2, TDES_BLOCK_SIZE, "\n");

	/* the key is masked with the variant */
	xor_array(key, tdes_bdk_ik_key_variant, key, TDES_KEY_LENGTH_2);
	print_array("\t\t(fff): Key XORed with mask: ", key, TDES_KEY_LENGTH_2, "\n");

	/* Crypto reg 1 is XORed with the right half of the key and stored in crypto reg 1 */
	xor_array(crypto_reg1, key+TDES_BLOCK_SIZE, crypto_reg1, TDES_BLOCK_SIZE);
	print_array("\t\t(ggg): Reg1 XOR with key2:  ", crypto_reg1, TDES_BLOCK_SIZE, "\n");

	/* crypto reg 1 is encrypted with key1 */
	DES_set_key_unchecked((const_DES_cblock*) key, &des_key);
	DES_ecb_encrypt((const_DES_cblock*)crypto_reg1, (DES_cblock*)crypto_reg1, &des_key, DES_ENCRYPT);
	print_array("\t\t(hhh): Reg1 enc.with key1:  ", crypto_reg1, TDES_BLOCK_SIZE, "\n");

	/* crypto reg 1 is XORed with key 2 and stored in reg 1 */
	xor_array(crypto_reg1, key+TDES_BLOCK_SIZE, crypto_reg1, TDES_BLOCK_SIZE);
	print_array("\t\t(iii): Reg1 xored with key2:  ", crypto_reg1, TDES_BLOCK_SIZE, "\n");

	memcpy(output, crypto_reg1, TDES_BLOCK_SIZE);
	memcpy(output+TDES_BLOCK_SIZE, crypto_reg2, TDES_BLOCK_SIZE);

	PURGE(crypto_reg1);
	PURGE(crypto_reg2);
	PURGE(des_key);
	return DUKPT_SUCCESS;
}

/** Derives the initial key based on the BDK.
 * @param base_key the input key
 * @param base_key_len the input key length
 * @param algo desired algorithm for the key
 * @param KSN the ksn
 * @param output buffer for the key output, size is according to the desired algorithm
 * @result actual key length if successful, DUKPT_ERROR otherwise
 */
int dukpt_aes_derive_initial_key(uint8_t *base_key, size_t base_key_len,
		uint16_t algo, uint8_t *ksn, uint8_t *output) {
	return dukpt_aes_kdf(base_key, base_key_len, DUKPT_AES_USAGE_INITIAL,
			algo, ksn, output);
}

/** Derives an intermediate key based on a KSN.
 * @param initial_key the IK. Assumed to be an 128-bit AES key.
 * @param ksn the KSN. Assumed to be of the correct length.
 * @param output the output buffer. Assumed to be sufficient for an 128-bit AES key.
 * @result DUKPT_SUCCESS or DUKPT_ERROR
 */
int dukpt_aes_derive_intermediate_key (uint8_t * initial_key, uint8_t * ksn, uint8_t *output ) {
	/* validate inputs */
	if ( !(initial_key&&ksn&&output)) return DUKPT_ERROR;

	int klen = DUKPT_ERROR;

	uint8_t ksn_reg[DUKPT_AES_KSN_LEN];
	uint8_t current_key[AES_KEY_LENGTH_1];

	memcpy(ksn_reg, ksn, DUKPT_AES_KSN_LEN);
	memcpy(current_key, initial_key, AES_KEY_LENGTH_1);

	print_array("\tDeriving for KSN: ", ksn_reg, DUKPT_AES_KSN_LEN, "\n");
	/* prepare the shift register */
	uint8_t tc_staging[4];
	memcpy(tc_staging, ksn_reg+DUKPT_AES_KSN_LEN-4, 4);
	uint32_t shift_reg = ntohl(*((uint32_t*) (tc_staging)));

	memset(ksn_reg + (DUKPT_AES_KSN_LEN-4), 0, 4); /* last 4 bytes of the KSN are set to 0 */

	/* main derivation loop */
	while (shift_reg) {
		size_t msb = log2_32(shift_reg);
		size_t byte_idx = DUKPT_AES_KSN_LEN-1-(msb/8);
		size_t bit_idx = (msb %8);
		/* set the appropriate bit in the KSN */
		ksn_reg[byte_idx] |= (1<<bit_idx);
		/* clear the appropriate bit in the shift reg */
		shift_reg ^= 1L<<msb;

		print_array("\tDeriving for KSN: ", ksn_reg, DUKPT_AES_KSN_LEN, "\n");
		/* derive the intermediate key from the previous value */
		klen = dukpt_aes_kdf(current_key, AES_KEY_LENGTH_1,
				DUKPT_AES_USAGE_INTERMEDIATE, DUKPT_AES_AES_128, ksn_reg,
				current_key);
		print_array("\tResulting key:    ", current_key, klen, "\n");
	}

	memcpy(output, current_key, AES_KEY_LENGTH_1);

	return klen;
}

/**
 * Derives a worker key from AES 128 for an AES 128 encryption algorithm.
 * @param inter_key an intermediate key
 * @param usage key usage
 * @param ksn current ksn
 * @param output output buffer
 * @result actual key length or DUKPT_ERROR if derivation failed
 */
int dukpt_aes_derive_worker_key(uint8_t *inter_key,
		uint16_t usage, uint8_t *ksn, uint8_t *output) {
	/* validate inputs */
	if (! (inter_key && ksn && output)) return DUKPT_ERROR;

	return dukpt_aes_kdf(inter_key, AES_KEY_LENGTH_1, usage, DUKPT_AES_AES_128, ksn, output);
}


/** Derives an AES DUKPT key.
 * @param base_key the input key
 * @param base_key_len the input key length
 * @param usage desired usage of the key
 * @param algo desired algorithm for the key
 * @param KSN the ksn
 * @param output buffer for the key output, size is according to the desired algorithm
 * @result actual key length if successful, DUKPT_ERROR otherwise
 */
static int dukpt_aes_kdf(uint8_t *base_key, size_t base_key_len, uint16_t usage,
		uint16_t algo, uint8_t *ksn, uint8_t *output) {
	int result = DUKPT_ERROR;
	/* validate inputs */
	if (! (base_key && base_key_len && ksn && output)) return DUKPT_ERROR;

	if (! DUKPT_AES_VALID_ALGO(algo)) return DUKPT_ERROR;

	DUKPT_AES_KDF_INPUT kdf_input;
	uint8_t output_buffer[AES_KEY_LENGTH_3];
	uint16_t klen = aes_kdf_key_length[algo];

	/* prepare the KDF input */
	kdf_input.version = DUKPT_KDF_VERSION;

	*(uint16_t*)(&kdf_input.usage) = htons(usage);
	*(uint16_t*)(&kdf_input.algorithm) = htons(algo);
	*(uint16_t*)(&kdf_input.key_len) = htons(klen*8);

	print_array("\t\tKSN: ", ksn, DUKPT_AES_KSN_LEN, "\n");
	print_array("\t\tKey: ", base_key, base_key_len, "\n");

	/* the additional data is either left or right 8 bytes of the KSN*/
	if ( DUKPT_AES_USAGE_INITIAL == usage)
		memcpy(&kdf_input.ksn, ksn, DUKPT_AES_EXTRA_DATA_LEN);
	else
		memcpy(&kdf_input.ksn, ksn+DUKPT_AES_KSN_LEN-DUKPT_AES_EXTRA_DATA_LEN, DUKPT_AES_EXTRA_DATA_LEN);

	AES_KEY aes_key;

	AES_set_encrypt_key(base_key, base_key_len*8, &aes_key);
	/* count iterations */
	size_t iters = (klen/AES_BLOCK_SIZE) + !!(klen%AES_BLOCK_SIZE);
	for (uint8_t c = 1; c<=iters; c++) {
		kdf_input.counter = c;
		print_array("\t\tKDF input data: ", (uint8_t*) &kdf_input, sizeof(DUKPT_AES_KDF_INPUT), "\n");
		AES_ecb_encrypt((const unsigned char*)&kdf_input, output_buffer + (c-1)*AES_BLOCK_SIZE, &aes_key, AES_ENCRYPT);
	}

	memcpy(output, output_buffer, klen);

	result = klen;

	PURGE(aes_key);
	return result;
}

static int dukpt_des_derive_initial_key (uint8_t* bdk, uint8_t * ksn, uint8_t * output) {
	int result = DUKPT_ERROR;
	if (! (bdk && ksn && output)) return DUKPT_ERROR;

	uint8_t ksn_buffer[DUKPT_DES_KSN_LEN];
	uint8_t bdk_buffer[TDES_KEY_LENGTH_2];

	DES_key_schedule des_key1, des_key2;

	/* copy the KSN and reset its 21 least significant bits */
	memcpy(ksn_buffer, ksn, DUKPT_DES_KSN_LEN);
	ksn[DUKPT_DES_KSN_LEN] = 0;
	ksn[DUKPT_DES_KSN_LEN-1] = 0;
	ksn[DUKPT_DES_KSN_LEN-2] &= 0xE0;
	print_array("\tKey:            ", bdk, TDES_KEY_LENGTH_2, "\n");
	print_array("\tKSN:            ", ksn, DUKPT_DES_KSN_LEN, "\n");

	/* encrypt the KSN using triple DES with the BDK */
	DES_set_key_unchecked((const_DES_cblock*) bdk, &des_key1);
	DES_set_key_unchecked((const_DES_cblock*) (bdk+TDES_KEY_LENGTH_1), &des_key2);

	DES_ecb2_encrypt( (const_DES_cblock*) ksn, (DES_cblock*)output, &des_key1, &des_key2, DES_ENCRYPT );

	print_array("\tIK First half:  ", output, TDES_BLOCK_SIZE, "\n");
	/* copy and mask the BDK */
	memcpy( bdk_buffer, bdk, TDES_KEY_LENGTH_2);
	xor_array(bdk_buffer, tdes_bdk_ik_key_variant, bdk_buffer, TDES_KEY_LENGTH_2);
	print_array("\tVariant:        ", bdk_buffer, TDES_KEY_LENGTH_2, "\n");
	DES_set_key_unchecked((const_DES_cblock*) bdk_buffer, &des_key1);
	DES_set_key_unchecked((const_DES_cblock*) (bdk_buffer+TDES_KEY_LENGTH_1), &des_key2);

	/* encrypt the KSN using triple DES with the BDK */
	DES_ecb2_encrypt( (const_DES_cblock*) ksn, (DES_cblock*)(output+TDES_BLOCK_SIZE), &des_key1, &des_key2, DES_ENCRYPT );
	print_array("\tIK Second half: ", output+TDES_BLOCK_SIZE, TDES_BLOCK_SIZE, "\n");

	result = TDES_KEY_LENGTH_2;

	PURGE(ksn_buffer);
	PURGE(bdk_buffer);
	PURGE(des_key1);
	PURGE(des_key2);

	return result;
}
