#ifndef __CFPP_IO_H
#define __CFPP_IO_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/** The functions in this module are used to print out intermediate steps
 *  of various functions and examples provided elsewhere.
 *
 *  To suppress output, uncomment the following line
 */

/* #define CFPP_SUPPRESS_IO */

/**
 * Print out the count least significant bits of the byte
 * @param byte the byte to print
 * @param count the number of lsb to print
 */
void print_bits(uint8_t byte, size_t count);

/**
 * Print out the count least significant bits of the 16-bit word
 * in the in-memory order
 * @param value the word to print
 * @count count of bits to print
 */
void print_bits_16(uint16_t value, size_t count);

/**
 * Print out the count least significant bits of the 32-bit word
 * in the in-memory order
 * @param value the word to print
 * @count count of bits to print
 */
void print_bits_32(uint32_t value, size_t count);

/**
 * Print out the array of bytes of the specified length
 * @param header string to print before the array
 * @param array the array to print out
 * @param length length of the array
 * @param trailer string to print after the array
 */
void print_array(char * header, uint8_t * array, size_t length, char * trailer);

/**
 * Prints a (hopefully) nice header for a test.
 * @param test_name name of the test
 */
void print_test_header ( char * test_name );

/**
 * Prints a (hopefully) nice footer for a test.
 * @param test_name name of the test
 */
void print_test_footer( char * test_name );

/** simple function pointer for test run */
typedef void (*test_f)(void*);

typedef struct tagTEST {
	char * test_name;
	test_f test_func;
	void * args;
} TEST;

/**
 * Runs the test.
 * @param test structure pointer
 */
void run_test(TEST *);

/**
 * Prints a nice header for a test step
 * @param test step number
 * @param test step name
 */
void print_test_step ( size_t test_step, char * test_step_name );

#endif
