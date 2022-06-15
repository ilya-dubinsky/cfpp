#ifndef CFPP_PIN_H_
#define CFPP_PIN_H_

#include <stdlib.h>

#define PIN_BLOCK_FORMAT_0 0
#define PIN_BLOCK_FORMAT_1 1
#define PIN_BLOCK_FORMAT_2 2
#define PIN_BLOCK_FORMAT_3 3
#define PIN_BLOCK_FORMAT_4 4

#define PIN_OK 0
#define PIN_ERROR -1

#define VALID_PIN_BLOCK_FORMAT(x) ((x)>= PIN_BLOCK_FORMAT_0 && (x) <=PIN_BLOCK_FORMAT_4)

#define MAX_PIN_BLOCK_SIZE 32
#define MAX_PIN_LENGTH 12

#define PAN_BLOCK_LEN_0123 12

/* Returns the PIN block size, or 0 if the format is invalid.
 * For format 4, the size is doubled due to the need to perform a CBC encryption.
 * @param format the format code
 * @result PIN block size in bytes
 */
size_t get_pin_block_size(int format);

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
		uint8_t * unique_id, size_t unique_id_len, uint8_t * output);


/**
 * Encrypts a format 4 block formerly prepared by make_pin_block.
 * @param key AES key
 * @param key_size AES key size, bytes
 * @param input the two parts of the pin block in a single array
 * @param output the output buffer, must be of at least 16 bytes long
 * @result PIN_OK if ok, PIN_ERROR if not.
 */
int encrypt_format_4_block( uint8_t* key, size_t key_size, uint8_t * input, uint8_t* output );

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
int decrypt_format_4_block ( uint8_t* key, size_t key_size, uint8_t* pan, size_t pan_len, uint8_t * input, uint8_t* output);

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
int encrypt_key_variant( uint8_t * key, uint8_t key_len, uint8_t *kek, uint8_t* variant, uint8_t* output );

#endif /* SRC_PIN_H_ */
