#include "pin.h"

#include "bits.h"
#include "test_io.h"
#include "payments.h"
#include "crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/des.h>

static size_t pin_block_size[] = {TDES_BLOCK_SIZE, TDES_BLOCK_SIZE, TDES_BLOCK_SIZE, TDES_BLOCK_SIZE, 2*AES_BLOCK_SIZE};

/* Returns the PIN block size, or 0 if the format is invalid.
 * For format 4, the size is doubled due to the need to perform a CBC encryption.
 * @param format the format code
 * @result PIN block size in bytes
 */
size_t get_pin_block_size(int format){
	if (!VALID_PIN_BLOCK_FORMAT(format)) return 0;
	return pin_block_size [format];
}

/**
 * Prepares a pin block of the given format. The PIN block is written in a packed form
 * into the output variable.
 *
 * In case of PIN block format 4, two separate blocks are returned (they will have to be CBC encrypted)
 * @param format PIN block format, 0 to 4
 * @pin	PIN value, unpacked BCD
 * @pin_len PIN length
 * @pan PAN value, unpacked BCD
 * @pan_len PAN length
 * @unique_id unique transaction ID PIN block format 1. If NULL, ignored for format 1.
 * @unique_id_len length of the unique ID
 * @output pointer to the output buffer which must be of MAX_PIN_BLOCK_SIZE
 * @result 0 if successful.
 */
int make_pin_block (int format, uint8_t * pin, size_t pin_len, uint8_t * pan, size_t pan_len,
		uint8_t * unique_id, size_t unique_id_len, uint8_t * output) {
	/* validate the input */
	if (!VALID_PIN_BLOCK_FORMAT(format)) return PIN_ERROR;

	if (PIN_BLOCK_FORMAT_1!=format && PIN_BLOCK_FORMAT_2!=format) {
		if (!(pan && pan_len)) return PIN_ERROR;
	 	if (!VALID_PAN_LENGTH(pan_len)) return PIN_ERROR;
	}

	if (!(pin && pin_len && output)) return PIN_ERROR;

	if (pin_len > MAX_PIN_LENGTH) return PIN_ERROR;

	uint8_t buffer1[2*AES_BLOCK_SIZE], buffer2[2*AES_BLOCK_SIZE];

	memset(buffer1, 0, 2*AES_BLOCK_SIZE);
	memset(buffer2, 0, 2*AES_BLOCK_SIZE);

	size_t offset = 2;
	/* prepare buffer1 */
	buffer1[0] = format;
	buffer1[1] = pin_len;

	memcpy(buffer1+offset, pin, pin_len);
	offset += pin_len;

	/* format 1, if unique ID is provided */
	if (PIN_BLOCK_FORMAT_1==format && unique_id && unique_id_len) {
		size_t len = 2*AES_BLOCK_SIZE - offset;
		len = len>unique_id_len? unique_id_len:len;
		memcpy(buffer1+offset, unique_id, len);
		offset += len;
	}

	/* padding */
	switch (format){
		case PIN_BLOCK_FORMAT_0:
		case PIN_BLOCK_FORMAT_2:
			/* padding is with 0xF */
			memset(buffer1+offset, 0xF, 2*AES_BLOCK_SIZE-offset);
			break;
		case PIN_BLOCK_FORMAT_1:
		case PIN_BLOCK_FORMAT_3:
			/* padding is random */
			RAND_priv_bytes(buffer1+offset,2*AES_BLOCK_SIZE-offset);
			break;
		case PIN_BLOCK_FORMAT_4:
			/* this one is special */
			if (offset<2*TDES_BLOCK_SIZE) {
				memset(buffer1+offset, 0xA, 2*TDES_BLOCK_SIZE);
				offset = 2*TDES_BLOCK_SIZE;
			}
			RAND_priv_bytes(buffer1+offset, 2*AES_BLOCK_SIZE-offset);
			break;
	}
	print_array("\tBuffer 1: ", buffer1, 2*AES_BLOCK_SIZE, "\n");

	if (PIN_BLOCK_FORMAT_4!=format) {
		/* PIN block formats 0-3 can be made via XOR with the second block, which will
		 * simply have to be all zeros if the format is 1 or 2.
		 */

		/* If the format isn't 2, PAN is mandatory */
		if (PIN_BLOCK_FORMAT_1!=format && PIN_BLOCK_FORMAT_2!=format) {
			/* copy the last 12 digits of the PAN without the check digit */
			memcpy(buffer2+4, pan+(pan_len-13), PAN_BLOCK_LEN_0123);
		}
	} else {
		/* second block of format 4 has the structure LPPPPPPPPP0000, where
		 * L is the PAN length-12, PPPP are the PAN digits and the rest is the zero-
		 * padding.
		 */
		buffer2[0] = pan_len-12;
		memcpy(buffer2+1, pan, pan_len);
	}
	print_array("\tBuffer 2: ", buffer2, 32, "\n");

	if (PIN_BLOCK_FORMAT_4 == format) {
		/* simply pack the two buffers into the output */
		pack_bcd(buffer1, 2*AES_BLOCK_SIZE, output, AES_BLOCK_SIZE, PAD_RIGHT);
		pack_bcd(buffer2, 2*AES_BLOCK_SIZE, output+AES_BLOCK_SIZE, AES_BLOCK_SIZE, PAD_RIGHT);
		print_array("\t\tBlock 1: ", output, AES_BLOCK_SIZE, "\n");
		print_array("\t\tBlock 2: ", output+AES_BLOCK_SIZE, AES_BLOCK_SIZE, "\n");
	}
	else {
		uint8_t block1[8], block2[8];
		pack_bcd(buffer1, 2*TDES_BLOCK_SIZE, block1, TDES_BLOCK_SIZE, PAD_RIGHT);
		pack_bcd(buffer2, 2*TDES_BLOCK_SIZE, block2, TDES_BLOCK_SIZE, PAD_RIGHT);
		print_array("\t\tBlock 1: ", block1, TDES_BLOCK_SIZE, "\n");
		print_array("\t\tBlock 2: ", block2, TDES_BLOCK_SIZE, "\n");
		xor_array(block1, block2, output, TDES_BLOCK_SIZE);
	}

	return PIN_OK;
}
/**
 * Encrypts a format 4 block formerly prepared by make_pin_block.
 * @param key AES key
 * @param key_size AES key size, bytes
 * @param input the two parts of the pin block in a single array
 * @param output the output buffer, must be of at least 16 bytes long
 * @result PIN_OK if ok, PIN_ERROR if not.
 */
int encrypt_format_4_block( uint8_t* key, size_t key_size, uint8_t * input, uint8_t* output ) {
	AES_KEY enc_key;
	int result = PIN_ERROR;
	/* The IV for this encryption is all zero*/
	uint8_t iv[AES_BLOCK_SIZE];
	memset(iv, 0, AES_BLOCK_SIZE);

	if (! (key&& key_size && input && output)) return PIN_ERROR;

	if (!VALID_AES_KEY_SIZE(key_size)) return PIN_ERROR;

	/* attempt to initialize the key schedule. From this point onwards, the memory must be cleansed */
	if (AES_set_encrypt_key(key, key_size*8, &enc_key) <0) goto cleanup;

	print_array("\t\tCBC input block: ", input, 2*AES_BLOCK_SIZE, "\n");
	print_array("\t\tCBC IV: ", iv, AES_BLOCK_SIZE, "\n");
	/* perform encryption */
	AES_cbc_encrypt(input, output, 2* AES_BLOCK_SIZE, &enc_key, iv, AES_ENCRYPT);
	print_array("\t\tCBC Output: ", output, AES_BLOCK_SIZE, "\n");

	result = PIN_OK;
cleanup:
	/* clean up the enc_key due to sensitivity */
	PURGE(enc_key);
	return result;
}

/**
 * Decrypts a format 4 block. Returns only the first chunk of it.
 * @param key AES key
 * @param key_size AES key size, bytes
 * @param pan the PAN
 * @param pan_len PAN length
 * @param input the pin block in a single array
 * @param output the output buffer, must be of at least 16 bytes long
 * @result PIN_OK if ok, PIN_ERROR if not.
 */
int decrypt_format_4_block ( uint8_t* key, size_t key_size, uint8_t* pan, size_t pan_len, uint8_t * input, uint8_t* output) {
	int result = PIN_ERROR;
	/* validate the input */
	if (!(key && key_size && pan && pan_len && input && output)) return PIN_ERROR;

	if (!VALID_PAN_LENGTH(pan_len)) return PIN_ERROR;
	if (!VALID_AES_KEY_SIZE(key_size)) return PIN_ERROR;

	AES_KEY dec_key;
	/* prepare for decryption */
	if (AES_set_decrypt_key(key, key_size*8, &dec_key) <0) goto cleanup;

	/* prepare block 2*/
	uint8_t block2_buffer[2*AES_BLOCK_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];

	uint8_t enc_input_buffer[2*AES_BLOCK_SIZE];

	memset( block2_buffer, 0, 2*AES_BLOCK_SIZE);
	memset( iv, 0, AES_BLOCK_SIZE );
	memcpy(enc_input_buffer, input, AES_BLOCK_SIZE);

	block2_buffer[0] = pan_len -12;
	memcpy(block2_buffer+1, pan, pan_len);

	pack_bcd(block2_buffer, 2*AES_BLOCK_SIZE, enc_input_buffer+AES_BLOCK_SIZE, AES_BLOCK_SIZE, PAD_RIGHT);
	/* Decryption. The IV is zeros. The block 2 (constructed from the PAN) is appended to the ciphertext
	 * and the result is decrypted using AES in the CBC mode. */
	AES_cbc_encrypt(enc_input_buffer, output, 2*AES_BLOCK_SIZE, &dec_key, iv, AES_DECRYPT);

	result = PIN_OK;

cleanup:
	PURGE(dec_key);
	return result;
}

/** Encrypts the key under the KEK, applying a variant.
 *  A single-byte variant is assumed for the encryption. The variant array has up to three positions. The kek is
 *  a double TDES key. The input key is a double or a triple TDES key.
 *  @param key the key to encrypt
 *  @param key_len length of the input key to encrypt. It can be either double or triple TDES length.
 *  @kek the key encryption key, always a double TDES key
 *  @variant the variant table, three bytes, applied to the first byte of the second half of the kek
 *  @output the output buffer, must contain the same bytes as key_len
 *  @result PIN_OK on success, PIN_ERROR on failure
 */
int encrypt_key_variant( uint8_t * key, uint8_t key_len, uint8_t *kek, uint8_t* variant, uint8_t* output ) {
	int result = PIN_ERROR;
	/* validate inputs */
	if (!(key && key_len && kek && variant && output )) return PIN_ERROR;

	if (TDES_KEY_LENGTH_2!=key_len & TDES_KEY_LENGTH_3!=key_len) return PIN_ERROR;
 	DES_key_schedule kek_ks[2];

 	/* the first key half is unchanged by this version of variants*/
 	DES_set_key_unchecked((DES_cblock*)kek, &(kek_ks[0]));

 	print_array("\t\tKEK prior to variants: ", kek, TDES_KEY_LENGTH_2, "\n");

 	for (size_t i=0; i< key_len/TDES_KEY_LENGTH_1; i++) {
 		/* apply variant to the first byte of the second half of the key */
 		kek[TDES_KEY_LENGTH_1]^=variant[i];
 		print_array("\t\tKEK after applying the variant: ", kek, TDES_KEY_LENGTH_2, "\n");
 		/* Initiate key schedule */
 		DES_set_key_unchecked((DES_cblock*)kek, &(kek_ks[1]));
 		/* Encrypt the appropriate block */
 		DES_ecb2_encrypt( (DES_cblock*) (key+TDES_BLOCK_SIZE*i), (DES_cblock*) (output+TDES_BLOCK_SIZE*i), kek_ks, kek_ks+1, DES_ENCRYPT);
 		/* remove variant from the first byte of the second half of the key */
 		kek[TDES_KEY_LENGTH_1]^=variant[i];
 	}
 	result = PIN_OK;

	PURGE(kek_ks[0]);
	PURGE(kek_ks[1]);
	return result;
}
