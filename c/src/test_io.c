#include <stdio.h>
#include <string.h>

#include "test_io.h"

#define BAR_SIZE 60

/**
 * Print out the count least significant bits of the byte
 * @param byte the byte to print
 * @param count the number of lsb to print
 */
void print_bits(uint8_t byte, size_t count) {
#ifndef CFPP_SUPPRESS_IO
	/* Check the boundary conditions */
	if (!count || count > 8)
		return;
	/* Initialize the mask */
	uint8_t mask = 0x1<<--count;

	/* loop through bits left to right, shifting the mask right */
	do {
		printf("%1u", (byte & mask)!=0 );
		mask >>=1;
	} while (mask !=0);
#endif
}

/**
 * Print out the count least significant bits of the 16-bit word
 * in the in-memory order
 * @param value the word to print
 * @count count of bits to print
 */
void print_bits_16(uint16_t value, size_t count) {
#ifndef CFPP_SUPPRESS_IO
	if (!count || count >16)
		return;

	if (count >8) {
		print_bits( (uint8_t) value, count-8);
		printf(" ");
		count -=8;
	}

	print_bits( *((uint8_t*)&value+1), count);
#endif
}

/**
 * Print out the count least significant bits of the 32-bit word
 * in the in-memory order
 * @param value the word to print
 * @count count of bits to print
 */
void print_bits_32(uint32_t value, size_t count) {
#ifndef CFPP_SUPPRESS_IO
	if (!count || count >32)
		return;

	if (count >16) {
		print_bits_16( (uint16_t) value, count-16);
		printf(" ");
		count -= 16;
	}

	print_bits_16( *((uint16_t*)&value+1), count);
#endif
}

/**
 * Print out the array of bytes of the specified length
 * @param header string to print before the array
 * @param array the array to print out
 * @param length length of the array
 * @param trailer string to print after the array
 */
void print_array(char * header, uint8_t * array, size_t length, char * trailer) {
#ifndef CFPP_SUPPRESS_IO
	if (!array || length <=0) return;
	printf("%s", header);
	for (size_t i=0; i<length; i++){
		printf("%02X", array[i]);
		if (i%2==1) printf(" ");
	}
	printf("%s", trailer);
#endif
}

/**
 * Internal function to print out a character
*/

static void repeat_char(char c, size_t n) {
	for (size_t i=0; i<n; i++)
		printf("%c", c);
}

/**
 * Internal function to print out a horizontal separator bar of BAR_SIZE equal signs
*/
static void print_bar() {
	repeat_char('=', BAR_SIZE);
	printf("\n");
}

/**
 * Prints a (hopefully) nice header for a test.
 * @param test_name name of the test
 */
void print_test_header ( char * test_name ) {
#ifndef CFPP_SUPPRESS_IO
	if (!test_name) return;
	printf("\n");
	print_bar();
	/* center the test name */
	size_t name_len = strlen(test_name);
	size_t padding = name_len >= BAR_SIZE-8 ? 0: (BAR_SIZE-8-name_len)>>1;
	printf ("!");
	repeat_char(' ', padding);
	printf("Test: %s", test_name);
	repeat_char(' ', padding + (name_len%2));
	printf ("!\n");
	print_bar();
	printf("\n");
#endif
}

/**
 * Prints a nice header for a test step
 * @param test step number
 * @param test step name
 */
void print_test_step ( size_t test_step, char * test_step_name ) {
	size_t underline_len = strlen(test_step_name) + 18;
	printf("\nTest step: %3lu    %s\n", test_step, test_step_name);
	repeat_char('-', underline_len);
	printf("\n");
}
/**
 * Prints a (hopefully) nice footer for a test.
 * @param test_name name of the test
 */
void print_test_footer( char * test_name ) {
#ifndef CFPP_SUPPRESS_IO
	if (!test_name) return;
	printf("\n");
	print_bar();
	printf("\n");
#endif
}

/**
 * Runs the test.
 * @param test structure pointer
 */
void run_test(TEST *test) {
	if (!(test && test->test_name && test->test_func)) return;

	print_test_header(test->test_name);
	test->test_func(test->args);
	print_test_footer(test->test_name);
}
