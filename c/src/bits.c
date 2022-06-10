#include "bits.h"

#include <stdio.h>
#include <string.h>


/* The macro is not ensuring types, so it is for internal use only */
#define PACK_BCD(x,y)  (( ((x)&0xF)<<4) | ((y)&0xF))


/**
 * Count trailing zero bits of a byte value.
 * @param v the byte value
 * @result number of trailing zero bits, or 8 if the value ==0
 */
size_t count_trailing_zero_bits_8 (uint8_t v) {
	/* Turn v from xxxx1000 into 00001000 by using two's complement.
	 * The -v is in fact ~v+1 by definition of two's complement.
	 * 		~v turns xxxx1000 into XXXX0111, where X=~x.
	 * 		Adding 1 turns the result into XXXX1000 where X=~x
	 * Finally, ANDing it with the original value yields 00001000, since X&x=0
	 */
	v &= -v;
	/* maximum of 8 zeroes for v==0*/
	size_t c = 8;
	/* if v is not zero, set all bits of c to 1 */
	if (v) c--;
	/* descend through the tree, unsetting bits of c as needed */
	if (v & 0x0F) c -=4; /* the mask is 00001111, distinguishing nibbles of the byte */
	if (v & 0x33) c -=2; /* the mask is 00110011, distinguishing the rightmost two bits of each nibble */
	if (v & 0x55) c -=1; /* the mask is 01010101, distinguishing the bits of the bit pair */
	return c;
}


/**
 * Count trailing zero bits of a 16-bit value.
 * @param v the 16-bit value
 * @result number of trailing zero bits, or 16 if the value ==0
 */
size_t count_trailing_zero_bits_16 (uint16_t v) {
	/* Turn v from xxxx1000 into 00001000 by using two's complement.
	 */
	v &= -v;
	/* maximum of 16 zeroes for v==0*/
	size_t c = 16;
	/* if v is not zero, set all bits of c to 1 */
	if (v) c--;
	/* descend through the tree, unsetting bits of c if needed */
	if (v & 0x00FF) c -=8;
	if (v & 0x0F0F) c -=4;
	if (v & 0x3333) c -=2;
	if (v & 0x5555) c -=1;
	return c;
}

/**
 * Count trailing zero bits of a 32-bit value.
 * @param v the 32-bit value
 * @result number of trailing zero bits, or 32 if the value ==0
 */
size_t count_trailing_zero_bits_32 (uint32_t v) {
	/* Turn v from xxxx1000 into 00001000 by using two's complement.
	 */
	v &= -v;
	/* maximum of 32 zeroes for v==0*/
	size_t c = 32;
	/* if v is not zero, set all bits of c to 1 */
	if (v) c--;
	/* descend through the tree, unsetting bits of c if needed */
	if (v & 0x0000FFFF) c -=16;
	if (v & 0x00FF00FF) c -=8;
	if (v & 0x0F0F0F0F) c -=4;
	if (v & 0x33333333) c -=2;
	if (v & 0x55555555) c -=1;
	return c;
}

/**
 * Compute the most significant bit of the 8-bit value (log2)
 * @param v the 8-bit value
 * @result the most significant bit value
 */
size_t log2_8 (uint8_t v) {
	const uint8_t b[] = {0x2, 0xC, 0xF0};
	const size_t S[] = {1, 2, 4};
	int i;

	size_t r = 0; // result of log2(v) will go here
	for (i = 2; i >= 0; i--) {
		if (v & b[i]) {
			v >>= S[i];
			r |= S[i];
		}
	}
	return r;
}

/**
 * Compute the most significant bit of the 16-bit value (log2)
 * @param v the 16-bit value
 * @result the most significant bit value
 */
size_t log2_16 (uint16_t v) {
	const uint16_t b[] = {0x2, 0xC, 0xF0, 0xFF00};
	const size_t S[] = {1, 2, 4, 8};
	int i;

	size_t r = 0; // result of log2(v) will go here
	for (i = 3; i >= 0; i--) {
		if (v & b[i]) {
			v >>= S[i];
			r |= S[i];
		}
	}
	return r;
}

/**
 * Compute the most significant bit of the 32-bit value (log2)
 * @param v the 32-bit value
 * @result the most significant bit value
 */
size_t log2_32(uint32_t v) {
	const uint32_t b[] = {0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000};
	const size_t S[] = {1, 2, 4, 8, 16};
	int i;

	size_t r = 0; // result of log2(v) will go here
	for (i = 4; i >= 0; i--) {
		if (v & b[i]) {
			v >>= S[i];
			r |= S[i];
		}
	}
	return r;
}

/**
 * Calculate bit cardinality of the value
 * @param v input value
 * @result number of set bits
 */
size_t bit_cardinality_8(uint8_t v) {
	size_t c; // c accumulates the total bits set in v
	for (c = 0; v; c++) {
		v &= v - 1; // clear the least significant bit set
	}
	return c;
}

/**
 * Calculate bit cardinality of the value
 * @param v input value
 * @result number of set bits
 */
size_t bit_cardinality_16(uint16_t v) {
	uint8_t *vp = (uint8_t*)&v;
	return bit_cardinality_8(vp[0])+bit_cardinality_8(vp[1]);
}

/**
 * Calculate bit cardinality of the value
 * @param v input value
 * @result number of set bits
 */
size_t bit_cardinality_32(uint32_t v) {
	uint16_t *vp = (uint16_t*)&v;
	return bit_cardinality_16(vp[0])+bit_cardinality_16(vp[1]);
}

/**
 * Calculate even parity bit of an 8-bit value
 * @param v 8-bit value
 * @result 1 if the number of set bits in v is odd
 */
size_t even_parity_8 (uint8_t v) {
	size_t p;
	v ^=v>>4; 	/* Shorten the value of v to a nibble while preserving parity */
	v &= 0xf;   /* cut off the upper nibble as it is no longer needed */
	p = (0x6996 >> v) &1; /* use the magic number 0x6996 as the lookup table with 16 entries */
	return p;
}

/**
 * Calculate even parity bit of an 16-bit value
 * @param v 16-bit value
 * @result 1 if the number of set bits in v is odd
 */
size_t even_parity_16 (uint16_t v) {
	size_t p;
	v ^=v>>8;	/* Shorten the value of v to a byte while preserving parity */
	v ^=v>>4; 	/* Shorten the value of v to a nibble while preserving parity */
	v &= 0xf;   /* cut off the upper nibble as it is no longer needed */
	p = (0x6996 >> v) &1; /* use the magic number 0x6996 as the lookup table with 16 entries */
	return p;
}


/**
 * Calculate even parity bit of an 16-bit value
 * @param v 32-bit value
 * @result 1 if the number of set bits in v is odd
 */
size_t even_parity_32 (uint32_t v) {
	size_t p;
	v ^=v>>16;	/* Shorten the value of v to a 16-bit word while preserving parity */
	v ^=v>>8;	/* Shorten the value of v to a byte while preserving parity */
	v ^=v>>4; 	/* Shorten the value of v to a nibble while preserving parity */
	v &= 0xf;   /* cut off the upper nibble as it is no longer needed */
	p = (0x6996 >> v) &1; /* use the magic number 0x6996 as the lookup table with 16 entries */
	return p;
}

/**
 * Decimalize the input vector. Note: the input value is a packed BCD (nibble per digit), the output
 * 	value is unpacked BCD (byte per digit)
 * 	@param vector Input vector (packed BCD)
 * 	@param input_len Input vector length in nibbles (!!!)
 * 	@param output Output array
 * 	@param output_len Output array length in bytes
 * 	@result Returns count of digits decimalized if successful, or -1 in case of an error
 */
int decimalize_vector( uint8_t * vector, size_t input_len_n, uint8_t * output, size_t output_len_b) {
	/* validate inputs */
	if (!( vector && input_len_n && output && output_len_b) )
		return BITS_ERROR;
	if (output_len_b > input_len_n<<1)
		return BITS_ERROR;
	/* initialize the decimal digit counter and start scanning the input vector */
	size_t out_p = 0;
	size_t input_p = 0;
	/* for the second scan, the values will be adjusted by subtracting 10.
	 * This var is also used to track the current range of digits on which we're looking
	 */
	int adjustment = 0;

	while (out_p < output_len_b && adjustment < 20) {

		/* extract the nibble */
		/* tricks here:
		 * 	- byte offset is the nibble offset >>1
		 * 	- we take nibble offset modulo 2 and subtract it from 1, so that even offsets
		 * 	  give us 1 and not 0
		 * 	- we multipy the offset by 4, and this is the number of bits by which to shift
		 * 	  right the byte
		 * 	- finally, AND with 0xF to trim the upper half of the byte, and we're done
		 */
		uint8_t b = (vector[input_p>>1])>>((1-(input_p %2))*4) & 0xF;

		if (b >= adjustment && b < adjustment+10) /* valid digit found */
			output[out_p++] = b-adjustment;

		input_p++;

		if (input_p == input_len_n) { /* check if the scan is complete and if so, restart with adjustment */
			adjustment += 10;
			input_p = 0;
		}
	}
	return out_p;

}

/**
 * XOR two arrays and place the result in the output. Output can be equal to one of the arrays
 * @param vector1 first array
 * @param vector2 second array
 * @param output output array
 * @param len lengthm identical for all three, in bytes
 * @result 0 if successful or -1 otherwise
 */
int xor_array (uint8_t * vector1, uint8_t * vector2, uint8_t * output, size_t len) {
	if (!(vector1 && vector2 && output && len))
		return BITS_ERROR;

	for (size_t i=0; i< len; i++)
		output[i]=vector1[i]^vector2[i];

	return BITS_SUCCESS;
}

/**
 * Packs decimal digits into a packed BCD byte array
 * @param input input array
 * @param input_len_n input length in nibbles
 * @param output output array
 * @param output_len_b output length in bytes
 * @param pad_left 1 to pad left, 0 to pad right (use PAD_LEFT and PAD_RIGHT)
 * @result 0 if successful or -1 otherwise
 */
int pack_bcd(uint8_t *input, size_t input_len_n, uint8_t* output, size_t output_len_b, int pad_left) {
	if (!(input && input_len_n && output && output_len_b))
		return BITS_ERROR;

	/* Initialize the output vector */
	memset(output, 0, output_len_b );

	int padding_n = output_len_b*2 - input_len_n;
	if (padding_n<0) padding_n=0; /* if there are too many nibbles, there is no padding */

	/* these are the two pointers, one scans the source nibbles, the other - the target bytes */
	size_t source_p_n = 0;
	size_t target_p_b = 0;

	/* variables for individual digits */
	uint8_t digit1, digit2;

	if (pad_left) { /* skip whole bytes from the left */
		target_p_b += padding_n>>1;
		if (padding_n%2)
			/* there is an odd number of nibbles, need to pack one nibble with a leading zero*/
			output[target_p_b++] = PACK_BCD(0, input[source_p_n++]);
	}

	/* from this point on, we just need to pack as many remaining nibbles as we can */

	while (source_p_n < input_len_n && target_p_b < output_len_b) {
		/* since source_p_n hasn't reached end of the input vector, there is at least one
		 * more nibble to pack at this point, we pack it and advance the source counter
		 */
		digit1 = input[source_p_n++];

		/* we check if there is a second nibble to pack */
		if (source_p_n<input_len_n)
			digit2 = input[source_p_n++]; /* and if there is, we use it and advance the source counter */
		else
			digit2 = 0; /* if there isn't we're padding right with a zero - this won't happen if we padded left already */

		output[target_p_b++]= PACK_BCD( digit1, digit2); /* finally, put the packed digits into the target array*/
	}

	return BITS_SUCCESS;
}


/**
 * Fixes parity bits of the byte array.
 * @param input input array
 * @param input_len input length in bytes
 * @param is_odd_parity PARITY_ODD if the desired parity is odd, PARITY_EVEN otherwise
 */
int fix_parity(uint8_t *input, size_t input_len, uint8_t is_odd_parity) {
	if (!(input && input_len))
		return BITS_ERROR;

	is_odd_parity &= 0x1; /* we only need the least significant bit */

	for (size_t i = 0; i<input_len; i++) {
		/* If the even_parity returns false, the parity of the byte is odd. XOR the original byte with it, and the lsb is
		 * flipped so that the overall parity is even. Now, XOR with the is_odd_parity flag. If it was false, the parity
		 * stays even. Otherwise, the parity is flipped to odd and we're done.
		 */
		input[i] ^= (0x1 & (even_parity_8(input[i])^is_odd_parity));
	}
	return BITS_SUCCESS;
}

/**
 * Calculates the Luhn check digit of an unpacked BCD array.
 * @param input the input array
 * @param input_len length of the input
 * @result luhn checksum digit as a byte
 */
uint8_t luhn_check_digit(uint8_t *input, size_t input_len) {
	/* input validation */
	if (! (input && input_len))
		return BITS_ERROR;
	uint8_t result = 0;
	for (size_t i = 0; i<input_len; i++) {
		/* start scanning from the rightmost digit to the leftmost */
		uint8_t temp = input[input_len-i-1];
		/* odd position means that i%2==0, since the rightmost digit is position 1*/
		if ( i%2 ==0) {
			/* double the value */
			temp *=2;
			/* if the value is more than 10, replace with the sum of digits */
			if (temp > 9) {
				temp = (temp %10) + (temp/10);
			}
		}
		result += temp;
	}

	return result==0 ? 0 : 10 - result % 10;
}

static char base64_url_encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G',
		'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
		'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
		'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
		'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-',
		'_', '=' };

/**
 * Produces base64-encoded value, populated in the output buffer provided by the caller
 * @param input The input binary array
 * @param input_len Length of the input
 * @param output buffer to store the output
 * @result returns the actual output length, or BITS_ERROR in case of an error
 */
size_t base64url_encode( uint8_t* input, size_t input_len, char* output) {
	/* Input validation */
	if (!(output && input && input_len))
		return BITS_ERROR;
	size_t padding = (3-input_len%3)%3; /* padding is 1 if the remainder is 2, 2 if 1 and 0 otherwise */

	size_t output_ptr = 0;
	size_t input_ptr = 0;
	while (input_ptr < input_len) {
		uint8_t temp = 0;

		/* first byte is always available, taking the most significant 6 bits */
		output[output_ptr++] = base64_url_encoding_table[input[input_ptr]>>2];

		/* taking the 2 least significant bits to the second chunk */
		temp = (input[input_ptr++] & 0x3) << 4;
		if (input_ptr == input_len) {
			// we're done
			output[output_ptr++] = base64_url_encoding_table[temp];
			break;
		}
		/* taking the 4 msbs to the 2nd chunk byte */
		temp |= (input[input_ptr] >> 4);
		output[output_ptr++] = base64_url_encoding_table[temp];

		/* taking the 4 lsbs to the 3rd chunk */
		temp = (input[input_ptr++] & 0xf) << 2;
		if (input_ptr == input_len) {
			/* we're done again */
			output[output_ptr++] = base64_url_encoding_table[temp];
			break;
		}

		/* taking the 2 msbs to the 3rd chunk */
		temp |= (input[input_ptr] >> 6);
		output[output_ptr++] = base64_url_encoding_table[temp];
		/* taking the remaining 6 bits to the 4th chunk */
		output[output_ptr++] = base64_url_encoding_table[input[input_ptr++] & 0x3F];

	}
	/* pad */
	for (; padding>0; padding--)
		output[output_ptr++] = base64_url_encoding_table[0x40];
	return output_ptr;
}

/**
 * Returns a mask for memory cleanup
 * @param seed - a seed value for the bit mask
 * @result returns the 8-bit mask to use
 */
static uint8_t get_purge_mask(int seed) {
	/* This is best reimplemented with a PRF */
	uint8_t masks[] = { 0xAA, 0x55, 0xC0, 0x33};
	return masks[seed %4];
}

/*
 * Rewrites a memory area repeatedly with varying bitmasks
 * @param array the address of the array to purge
 * @len size of the array
 */
void purge_array(uint8_t* array, size_t len) {
	if (!(array&&len)) return;
	for (int m = 0; m<4; m++)
		for (size_t i = 0; i<len; i++)
			array[i] = get_purge_mask(m);
}
