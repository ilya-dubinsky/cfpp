#include "test_io.h"
#include "bits.h"

#include <stdio.h>
#include <string.h>

void test_lsb();
void test_parity();
void test_cardinality();
void test_msb();
void test_luhn();
void test_base64();

TEST bit_tests[] =
{
	{
		"Least significant bit",
		test_lsb,
		NULL
	},
	{
		"Even parity",
		test_parity,
		NULL
	},
	{
		"Bit cardinality",
		test_cardinality,
		NULL
	},
	{
		"Most significant bit",
		test_msb,
		NULL
	},
	{
		"LUHN test",
		test_luhn,
		NULL
	},
	{
		"Base64Url test",
		test_base64,
		NULL
	}
};

void test_lsb() {
	uint8_t test_8 = 0xC4;
	uint16_t test_16 = 0xF5D8;
	uint32_t test_32 = 0xDEADBEA0;
	print_test_step(1, "Zero value");
	printf("Input value: ");
	print_bits_16(0, 16);
	printf ("\nTrailing zero bits: %lu\n",count_trailing_zero_bits_16(0) );

	print_test_step(2, "Byte value");
	printf("Input value: 0x%02X ", test_8);
	print_bits(test_8, 8);
	printf ("\nTrailing zero bits: %lu\n",count_trailing_zero_bits_8(test_8) );

	print_test_step(3, "16-bit value");
	printf("Input value: 0x%04X ", test_16);
	print_bits_16(test_16, 16);
	printf ("\nTrailing zero bits: %lu\n",count_trailing_zero_bits_16(test_16) );

	print_test_step(4, "32-bit value");
	printf("Input value: 0x%08X ", test_32);
	print_bits_32(test_32, 32);
	printf ("\nTrailing zero bits: %lu\n",count_trailing_zero_bits_32(test_32) );

	print_test_step(5, "0xFF value");
	printf("Input value: 0x%04X ", 0xFFFF);
	print_bits_16(0xFFFF, 16);
	printf ("\nTrailing zero bits: %lu\n",count_trailing_zero_bits_16(0xFFFF) );
}

void test_parity() {
	uint8_t test_odd = 0xDA;
	uint8_t test_even = 0xDB;
	uint32_t test_odd_32 = 0xDEADBEEE;
	uint32_t test_even_32 = 0xBEEFDEAD;
	print_test_step(1, "Zero value");
	printf("Input value:  0x%02X ", 0);
	print_bits(0,8);
	printf("\nParity value: %zu\n", even_parity_8(0));

	print_test_step(2, "All bits set");
	printf("Input value:  0x%02X ", 0xFF);
	print_bits(0xFF,8);
	printf("\nParity value: %zu\n", even_parity_8(0xFF));

	print_test_step(3, "8-bit odd parity value");
	printf("Input value:  0x%02X ", test_odd);
	print_bits(test_odd,8);
	printf("\nParity value: %zu\n", even_parity_8(test_odd));

	print_test_step(4, "8-bit even parity value");
	printf("Input value:  0x%02X ", test_even);
	print_bits(test_even,8);
	printf("\nParity value: %zu\n", even_parity_8(test_even));

	print_test_step(5, "32-bit odd parity value");
	printf("Input value:  0x%08X ", test_odd_32);
	print_bits_32(test_odd_32,32);
	printf("\nParity value: %zu\n", even_parity_32(test_odd_32));

	print_test_step(6, "32-bit odd parity value");
	printf("Input value:  0x%08X ", test_even_32);
	print_bits_32(test_even_32,32);
	printf("\nParity value: %zu\n", even_parity_32(test_even_32));
}

void test_cardinality() {
	uint8_t test_1 = 0x80;
	uint8_t test_2 = 0xA3;
	uint16_t test_16 = 0x80A3;
	uint32_t test_32 = 0x92DE80A3;

	print_test_step(1, "Zero value");
	printf("Input value:  0x%02X ", 0);
	print_bits(0,8);
	printf("\nCardinality value: %zu\n", bit_cardinality_8(0));

	print_test_step(2, "Non-zero byte value");
	printf("Input value:  0x%02X ", test_1);
	print_bits(test_1,8);
	printf("\nCardinality value: %zu\n", bit_cardinality_8(test_1));

	print_test_step(3, "Non-zero byte value");
	printf("Input value:  0x%02X ", test_2);
	print_bits(test_2,8);
	printf("\nCardinality value: %zu\n", bit_cardinality_8(test_2));

	print_test_step(4, "Non-zero 16-bit value");
	printf("Input value:  0x%04X ", test_16);
	print_bits_16(test_16,16);
	printf("\nCardinality value: %zu\n", bit_cardinality_16(test_16));

	print_test_step(5, "Non-zero 32-bit value");
	printf("Input value:  0x%08X ", test_32);
	print_bits_32(test_32,32);
	printf("\nCardinality value: %zu\n", bit_cardinality_32(test_32));
}

void test_msb() {
	uint8_t test_8 = 0x34;
	uint16_t test_16 = 0x65D8;
	uint32_t test_32 = 0x2EADBEA0;
	print_test_step(1, "Zero value");
	printf("Input value: ");
	print_bits_16(0, 16);
	printf ("\nMost significant bit: %lu\n",log2_16(0) );

	print_test_step(2, "Byte value");
	printf("Input value: 0x%02X ", test_8);
	print_bits(test_8, 8);
	printf ("\nMost significant bit: %lu\n",log2_8(test_8) );

	print_test_step(3, "16-bit value");
	printf("Input value: 0x%04X ", test_16);
	print_bits_16(test_16, 16);
	printf ("\nMost significant bit: %lu\n",log2_16(test_16) );

	print_test_step(4, "32-bit value");
	printf("Input value: 0x%08X ", test_32);
	print_bits_32(test_32, 32);
	printf ("\nMost significant bit: %lu\n",log2_32(test_32) );

	print_test_step(5, "0xFF value");
	printf("Input value: 0x%04X ", 0xFFFF);
	print_bits_16(0xFFFF, 16);
	printf ("\nMost significant bit: %lu\n",log2_16(0xFFFF) );
}

typedef struct tagLUHN_PAN {
	uint8_t pan[20];
	uint8_t pan_len;
} LUHN_PAN;

LUHN_PAN luhn_pans [] = {
	{
		{ 4, 5, 8, 0 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,8 ,1 ,3 },
		15
	},
	{
		{ 3, 5, 7, 6},
		4
	}
};

void test_luhn() {
	for (size_t i =0; i<sizeof(luhn_pans)/sizeof(luhn_pans[0]); i++) {
		LUHN_PAN *p = luhn_pans + i;
		print_test_step(i+1, "Luhn value calculation");
		print_array("\tInput value: ", p->pan, p->pan_len, "\n");
		printf("\tLUHN digit: %1d", luhn_check_digit(p->pan, p->pan_len));
	}
}

typedef struct tag_BASE64_TEST {
	uint8_t data[64];
	uint8_t len;
	char * result;
} BASE64_TEST;

BASE64_TEST base64_tests[] = {
	{
		{ 0x20 },
		1,
		"IA=="
	},
	{
		{0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e},
		6,
		"FPucA9l-"
	},
	{
		{0x66, 0x6f, 0x6f, 0x62},
		4,
		"Zm9vYg=="
	},
	{
		{0x66, 0x6f, 0x6f, 0x62, 0x61},
		5,
		"Zm9vYmE="
	}
};

void test_base64() {

	char out_buffer[4096];
	for (size_t i =0; i<sizeof(base64_tests)/sizeof(base64_tests[0]); i++) {
		BASE64_TEST *p = base64_tests + i;
		print_test_step(i+1, "Base64 calculation");
		print_array("\tInput value: ", p->data, p->len, "\n");
		memset(out_buffer, 0, sizeof(out_buffer));
		base64url_encode(p->data, p->len, out_buffer, BASE64_PADDING);
		printf("\tBase64 output %s", out_buffer);
		if (!strcmp(out_buffer, p->result))
			printf(" - valid\n");
		else
			printf(" - invalid\n");
	}
}

int main (void) {
	for (size_t c = 0; c< sizeof(bit_tests)/sizeof(TEST); c++)
		run_test(bit_tests+c);
}
