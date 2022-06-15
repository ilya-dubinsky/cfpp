#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test_io.h"

#include "payments.h"
#include "pin.h"
#include "crypto.h"

void test_pin_block_format();
void test_pin_block_format4();
void test_variant();

TEST pin_tests[] = {
		{ "PIN block formats",
		test_pin_block_format,
		NULL },
		{ "PIN block format 4 encryption/decryption",
		test_pin_block_format4,
		NULL },
		{ "Variant TDES key encryption",
			test_variant,
			NULL
		}

};

typedef struct tagPIN_BLOCK_FORMAT_TEST {
	int format;
	uint8_t pin[MAX_PIN_LENGTH];
	size_t pin_len;
	uint8_t pan[MAX_PAN_LENGTH];
	size_t pan_len;
	uint8_t unique_id[256];
	size_t unique_id_len;
	uint8_t result[MAX_PIN_BLOCK_SIZE];
} PIN_BLOCK_FORMAT_TEST;

typedef struct tagPIN_BLOCK_FORMAT4_TEST {
	uint8_t pin[MAX_PIN_LENGTH];
	size_t pin_len;
	uint8_t pan[MAX_PAN_LENGTH];
	size_t pan_len;
	uint8_t key[AES_KEY_LENGTH_3];
	size_t key_len;
} PIN_BLOCK_FORMAT4_TEST;

typedef struct tagVARIANT_KEY_TEST {
	uint8_t key[TDES_KEY_LENGTH_3];
	uint8_t key_len;
	uint8_t kek[TDES_KEY_LENGTH_2];
	uint8_t variants[3];
	uint8_t output[TDES_KEY_LENGTH_3];
} VARIANT_KEY_TEST;

PIN_BLOCK_FORMAT_TEST pin_block_format_tests[] = {
	{ 0,
	  { 1,2,3,4}, 4,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  {0}, 0,
	  { 0x04,0x12,0x00,0xA9,0x87,0x6F,0xED,0xCB }
	},
	{ 0,
	  { 1,2,3,4, 5}, 5,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  {0}, 0,
	  { 0x05,0x12,0x00,0x09,0x87,0x6F,0xED,0xCB }
	},
	{ 1,
	  { 1,2,3,4, 5}, 5,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  {2,2,3,4}, 4,
	  { 0 } /* padding is random so no way to predict */
	},
	{ 1,
	  { 1,2,3,4, 5}, 5,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  { 0 }, 0,
	  { 0 } /* padding is random so no way to predict */
	},	{ 2,
	  { 1,2,3,4, 5}, 5,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  {2,2,3,4}, 4,
	  { 0x25, 0x12, 0x34, 0x5F, 0xFF ,0xFF, 0xFF, 0xFF } /* padding is random so no way to predict */
	},
	{ 2,
	  { 1,2,3,4, 5}, 5,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  {2,2,3,4}, 4,
	  { 0x25, 0x12, 0x34, 0x5F, 0xFF ,0xFF, 0xFF, 0xFF } /* padding is random so no way to predict */
	},
	{ 3,
	  { 1,2,3,4, 5}, 5,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  {2,2,3,4}, 4,
	  { 0x25, 0x12, 0x34, 0x5F, 0xFF ,0xFF, 0xFF, 0xFF } /* padding is random so no way to predict */
	},
	{ 4,
	  { 1,2,3,4, 5}, 5,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  {2,2,3,4}, 4,
	  { 0x45,0x12,0x34,0x5A,0xAA,0xAA,0xAA,0xAA,0xFB,0x1B,0x8F,0x4D,0xB0,0x6C,0xC4,0xF5,0x40,0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x50,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }
 /* padding is random so no way to predict */
	},
};

PIN_BLOCK_FORMAT4_TEST format4_tests [] = {
	{ { 1,2,3,4, 5}, 5,
	  { 0,1,2,3, 4,5,6,7, 8,9,0,1, 2,3,4,5}, 16,
	  { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, }, 16
	}
};

VARIANT_KEY_TEST variant_tests [] = { {
	{ 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF}, 16,
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
	{ 0xA6, 0xED, 0xB2},
	{ 0x26,0xCF,0xD1,0xD3,0x93,0xA1,0x8B,0x79,0x26,0xCF,0xD1,0xD3,0x93,0xA1,0x8B,0x79 } },
	{
		{ 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF}, 24,
		{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{ 0xA6, 0xED, 0xB2},
		{ 0x26,0xCF,0xD1,0xD3,0x93,0xA1,0x8B,0x79,0x26,0xCF,0xD1,0xD3,0x93,0xA1,0x8B,0x79,0x26,0xCF,0xD1,0xD3,0x93,0xA1,0x8B,0x79 } }
};

void test_pin_block_format() {

	for (size_t i = 0; i<sizeof(pin_block_format_tests)/sizeof(PIN_BLOCK_FORMAT_TEST); i++) {
		PIN_BLOCK_FORMAT_TEST *p = pin_block_format_tests+i;
		uint8_t output[256];

		print_test_step(i+1, "PIN block generation test");
		printf("\tPIN block format: %d\n", p->format);
		print_array("\tUnpacked PIN: ", p->pin, p->pin_len, "\n");
		print_array("\tUnpacked PAN: ", p->pan, p->pan_len, "\n");
		print_array("\tUnpacked Unique ID: ",  p->unique_id, p->unique_id_len, "\n");
		make_pin_block(p->format, p->pin, p->pin_len, p->pan, p->pan_len, p->unique_id, p->unique_id_len, output);
		print_array("\tActual output: ", output, get_pin_block_size(p->format), "");
		if (!memcmp(p->result, output, get_pin_block_size(p->format)))
			printf(" valid\n");
		else
			printf(" invalid\n");
	}
}

void test_pin_block_format4() {

	for (size_t i = 0; i<sizeof(format4_tests)/sizeof(PIN_BLOCK_FORMAT4_TEST); i++) {
		PIN_BLOCK_FORMAT4_TEST *p = format4_tests+i;
		uint8_t output1[256];

		print_test_step(1, "Prepare PIN block");
		print_array("\tUnpacked PIN: ", p->pin, p->pin_len, "\n");
		print_array("\tUnpacked PAN: ", p->pan, p->pan_len, "\n");
		make_pin_block(PIN_BLOCK_FORMAT_4, p->pin, p->pin_len, p->pan, p->pan_len, NULL, 0, output1);

		print_array("\tPIN block output: ", output1, get_pin_block_size(PIN_BLOCK_FORMAT_4), "\n");

		print_test_step(2, "Encrypt PIN block");
		uint8_t encrypted[AES_BLOCK_SIZE];
		encrypt_format_4_block(p->key, p->key_len, output1, encrypted);
		print_array("\tEncrypted PIN block: ", encrypted, AES_BLOCK_SIZE, "\n");
		uint8_t decrypted[AES_BLOCK_SIZE];
		decrypt_format_4_block(p->key, p->key_len, p->pan, p->pan_len, encrypted, decrypted);
		print_array("\tDecrypted PIN block: ", decrypted, AES_BLOCK_SIZE, "\n");
	}
}

void test_variant() {

	for (size_t i = 0; i<sizeof(variant_tests)/sizeof(VARIANT_KEY_TEST); i++) {
		VARIANT_KEY_TEST *p = variant_tests+i;
		uint8_t output[TDES_KEY_LENGTH_2];

		print_test_step(1, "Encrypting the key");
		encrypt_key_variant(p->key, p->key_len, p->kek, p->variants, output);

		print_array("\tEncrypted key: ", output, p->key_len, "");

		if (!memcmp(output, &p->output, p->key_len))
			printf(" valid");
		else
			printf(" invalid");
	}
}

int main(void) {
	for (size_t c = 0; c< sizeof(pin_tests)/sizeof(TEST); c++)
		run_test(pin_tests+c);
}
