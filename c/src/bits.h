#ifndef __CFPP_BITS_H
#define __CFPP_BITS_H

#include <stdlib.h>
#include <openssl/crypto.h>


#define BITS_ERROR -1
#define BITS_SUCCESS 0

#define PAD_LEFT 1
#define PAD_RIGHT 0

#define PARITY_ODD 1
#define PARITY_EVEN 0

#define PURGE(x) OPENSSL_cleanse((uint8_t*)&(x), sizeof(x))

#define BASE64_LEN(x)  ((x)*4/3 + (4-((x)%3)))

#define BASE64_NO_PADDING 0
#define BASE64_PADDING 1
/**
 * Count trailing zero bits of a byte value.
 * @param v the byte value
 * @result number of trailing zero bits, or 8 if the value ==0
 */
size_t count_trailing_zero_bits_8 (uint8_t v);

/**
 * Count trailing zero bits of a 16-bit value.
 * @param v the 16-bit value
 * @result number of trailing zero bits, or 16 if the value ==0
 */
size_t count_trailing_zero_bits_16 (uint16_t v);

/**
 * Count trailing zero bits of a 32-bit value.
 * @param v the 32-bit value
 * @result number of trailing zero bits, or 32 if the value ==0
 */
size_t count_trailing_zero_bits_32 (uint32_t v);

/**
 * Compute the most significant bit of the 8-bit value (log2)
 * @param v the 8-bit value
 * @result the most significant bit value
 */
size_t log2_8 (uint8_t v);

/**
 * Compute the most significant bit of the 16-bit value (log2)
 * @param v the 16-bit value
 * @result the most significant bit value
 */
size_t log2_16 (uint16_t v);

/**
 * Compute the most significant bit of the 32-bit value (log2)
 * @param v the 32-bit value
 * @result the most significant bit value
 */
size_t log2_32(uint32_t v);

/**
 * Calculate even parity bit of an 8-bit value
 * @param v 8-bit value
 * @result 1 if the number of set bits in v is odd
 */
size_t even_parity_8 (uint8_t v);

/**
 * Calculate even parity bit of an 16-bit value
 * @param v 16-bit value
 * @result 1 if the number of set bits in v is odd
 */
size_t even_parity_16 (uint16_t v);

/**
 * Calculate even parity bit of an 16-bit value
 * @param v 32-bit value
 * @result 1 if the number of set bits in v is odd
 */
size_t even_parity_32 (uint32_t v);

/**
 * Calculate bit cardinality of the value
 * @param v input value
 * @result number of set bits
 */
size_t bit_cardinality_8(uint8_t v);

/**
 * Calculate bit cardinality of the value
 * @param v input value
 * @result number of set bits
 */
size_t bit_cardinality_16(uint16_t v);

/**
 * Calculate bit cardinality of the value
 * @param v input value
 * @result number of set bits
 */
size_t bit_cardinality_32(uint32_t v);

/**
 * Decimalize the input vector. Note: the input value is a packed BCD (nibble per digit), the output
 * 	value is unpacked BCD (byte per digit)
 * 	@param vector Input vector (packed BCD)
 * 	@param input_len Input vector length in nibbles (!!!)
 * 	@param output Output array
 * 	@param output_len Output array length in bytes
 * 	@result Returns count of digits decimalized if successful, or -1 in case of an error
 */
int decimalize_vector( uint8_t * vector, size_t input_len_n, uint8_t * output, size_t output_len_b);

/**
 * XOR two arrays and place the result in the output. Output can be equal to one of the arrays
 * @param vector1 first array
 * @param vector2 second array
 * @param output output array
 * @param len lengthm identical for all three, in bytes
 * @result 0 if successful or -1 otherwise
 */
int xor_array (uint8_t * vector1, uint8_t * vector2, uint8_t * output, size_t len);

/**
 * Packs decimal digits into a packed BCD byte array
 * @param input input array
 * @param input_len_n input length in nibbles
 * @param output output array
 * @param output_len_b output length in bytes
 * @param pad_left 1 to pad left, 0 to pad right (use PAD_LEFT and PAD_RIGHT)
 * @result 0 if successful or -1 otherwise
 */
int pack_bcd(uint8_t *input, size_t input_len_n, uint8_t* output, size_t output_len_b, int pad_left) ;

/*
 * Fixes parity bits of the byte array.
 * @param input input array
 * @param input_len input length in bytes
 * @param is_odd_parity PARITY_ODD if the desired parity is odd, PARITY_EVEN otherwise
 */
int fix_parity(uint8_t *input, size_t input_len, uint8_t is_odd_parity);

/**
 * Calculates the Luhn check digit of an unpacked BCD array.
 * @param input the input array
 * @param input_len length of the input
 * @result luhn checksum digit as a byte
 */
uint8_t luhn_check_digit(uint8_t *input, size_t input_len);

/**
 * Produces base64-encoded value, populated in the output buffer provided by the caller
 * @param input The input binary array
 * @param input_len Length of the input
 * @param output buffer to store the output
 * @result returns the actual output length, or BITS_ERROR in case of an error
 */
size_t base64url_encode( uint8_t* input, size_t input_len, char* output, int padding);

/*
 * Rewrites a memory area repeatedly with varying bitmasks
 * @param array the address of the array to purge
 * @len size of the array
 */
void purge_array(uint8_t* array, size_t len);
#endif
