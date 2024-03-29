/*
 */

#include "tr31.h"
#include "test_io.h"
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct tag_TR31_DERIVATION_BASE_TEST {
	uint8_t counter;
	uint16_t key_usage;
	uint16_t algorithm;
} TR31_DERIVATION_BASE_TEST;

typedef struct tag_TR31_VARIANT_DERIVATION_TEST {
	uint8_t key_usage;
	uint8_t kbpk [TDES_KEY_LENGTH_3];
	size_t kbpk_len;
	uint8_t output [TDES_KEY_LENGTH_3];
} TR31_VARIANT_DERIVATION_TEST;

typedef struct tag_TR31_BINDING_DERIVATION_TEST {
	uint16_t key_usage;
	uint16_t derivation_algorithm;
	uint8_t kbpk [AES_KEY_LENGTH_3];
	size_t kbpk_len;
	uint8_t result[AES_KEY_LENGTH_3];
	size_t result_len;
} TR31_BINDING_DERIVATION_TEST;

TR31_DERIVATION_BASE_TEST derivation_base_tests [] ={
	{ 0x01, TR31_KEY_USAGE_ENC,TR31_ALGO_2TDEA },
	{ 0x02, TR31_KEY_USAGE_MAC,TR31_ALGO_3TDEA },
	{ 0x03, TR31_KEY_USAGE_ENC,TR31_ALGO_AES128 },
	{ 0x04, TR31_KEY_USAGE_MAC,TR31_ALGO_AES192 },
	{ 0x05, TR31_KEY_USAGE_MAC,TR31_ALGO_AES256 }
};

/* Test cases from the ANSI TR-31 standard */
TR31_VARIANT_DERIVATION_TEST variant_tests [] = {
	{ TR31_KEY_USAGE_ENC,
		{ 0x89,0xE8,0x8C,0xF7,0x93,0x14,0x44,0xF3,0x34,0xBD,0x75,0x47,0xFC,0x3F,0x38,0x0C }, 16,
		{ 0xCC,0xAD,0xC9,0xB2,0xD6,0x51,0x01,0xB6,0x71,0xF8,0x30,0x02,0xB9,0x7A,0x7D,0x49 }
	},
	{ TR31_KEY_USAGE_ENC,
		{ 0xB8,0xED,0x59,0xE0,0xA2,0x79,0xA2,0x95,0xE9,0xF5,0xED,0x79,0x44,0xFD,0x06,0xB9 }, 16,
		{ 0xFD,0xA8,0x1C,0xA5,0xE7,0x3C,0xE7,0xD0,0xAC,0xB0,0xA8,0x3C,0x01,0xB8,0x43,0xFC }
	},
	{ TR31_KEY_USAGE_MAC,
		{ 0x89,0xE8,0x8C,0xF7,0x93,0x14,0x44,0xF3,0x34,0xBD,0x75,0x47,0xFC,0x3F,0x38,0x0C }, 16,
		{ 0xC4,0xA5,0xC1,0xBA,0xDE,0x59,0x09,0xBE,0x79,0xF0,0x38,0x0A,0xB1,0x72,0x75,0x41 }
	},
	{ TR31_KEY_USAGE_MAC,
		{ 0xB8,0xED,0x59,0xE0,0xA2,0x79,0xA2,0x95,0xE9,0xF5,0xED,0x79,0x44,0xFD,0x06,0xB9 }, 16,
		{ 0xF5,0xA0,0x14,0xAD,0xEF,0x34,0xEF,0xD8,0xA4,0xB8,0xA0,0x34,0x09,0xB0,0x4B,0xF4 }
	}

};

/* Test cases from the ANSI TR-31 standard */
TR31_BINDING_DERIVATION_TEST binding_tests [] = {
	{ TR31_KEY_USAGE_ENC, TR31_ALGO_2TDEA,
		{ 0xDD,0x75,0x15,0xF2,0xBF,0xC1,0x7F,0x85,0xCE,0x48,0xF3,0xCA,0x25,0xCB,0x21,0xF6 }, 16,
		{ 0x69,0x88,0x32,0xF8,0x77,0x8A,0x7C,0xFC,0xBC,0x79,0x55,0x9D,0xAB,0x07,0xB8,0x8A }, 16
	},
	{ TR31_KEY_USAGE_MAC, TR31_ALGO_2TDEA,
		{ 0xDD,0x75,0x15,0xF2,0xBF,0xC1,0x7F,0x85,0xCE,0x48,0xF3,0xCA,0x25,0xCB,0x21,0xF6 }, 16,
		{ 0xDD,0x6C,0xEE,0xC1,0x78,0x2D,0x84,0x53,0x67,0x1B,0xF8,0x35,0x8A,0xF9,0xDB,0x47 }, 16
	},
	{ TR31_KEY_USAGE_ENC, TR31_ALGO_2TDEA,
		{ 0x1D,0x22,0xBF,0x32,0x38,0x7C,0x60,0x0A,0xD9,0x7F,0x9B,0x97,0xA5,0x13,0x11,0xAC }, 16,
		{ 0xBC,0xE8,0xE2,0xAD,0x5D,0x44,0x89,0xFD,0x0E,0xA5,0x23,0x6A,0x88,0x4D,0xAC,0x58 }, 16
	},
	{ TR31_KEY_USAGE_MAC, TR31_ALGO_2TDEA,
		{ 0x1D,0x22,0xBF,0x32,0x38,0x7C,0x60,0x0A,0xD9,0x7F,0x9B,0x97,0xA5,0x13,0x11,0xAC }, 16,
		{ 0x1F,0x9B,0x2B,0xDA,0xF9,0x69,0xC7,0xB8,0xB6,0xC9,0x33,0xAC,0x7B,0x9C,0x68,0x94 }, 16
	},
	{ TR31_KEY_USAGE_ENC, TR31_ALGO_AES256,
		{ 0x88, 0xE1, 0xAB, 0x2A, 0x2E,
				0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C,
				0xC8, 0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05,
				0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6 }, 32,
		{ 0x39, 0x6C,
		0x93, 0x82, 0xA6, 0xE2, 0xE6, 0x6A, 0x08, 0x87, 0x74, 0xE1,
		0xD6, 0xE4, 0x65, 0x41, 0xF5, 0xEA, 0xD6, 0x7D, 0x72, 0x04,
		0xF8, 0xDD, 0x0D, 0x7A, 0xE8, 0xFD, 0xA3, 0x34, 0xD3, 0xAC }, 32
	},
	{ TR31_KEY_USAGE_MAC,  TR31_ALGO_AES256,
		{ 0x88, 0xE1, 0xAB, 0x2A, 0x2E,
				0x3D, 0xD3, 0x8C, 0x1F, 0xA0, 0x39, 0xA5, 0x36, 0x50, 0x0C,
				0xC8, 0xA8, 0x7A, 0xB9, 0xD6, 0x2D, 0xC9, 0x2C, 0x01, 0x05,
				0x8F, 0xA7, 0x9F, 0x44, 0x65, 0x7D, 0xE6 }, 32,
		{ 0x4E, 0xF2, 0x43, 0x17,
				0x69, 0x62, 0x13, 0x84, 0x04, 0x51, 0x89, 0x07, 0x56,
				0x75, 0x7E, 0x57, 0x3E, 0x06, 0x73, 0x48, 0x38, 0x88,
				0xF9, 0xB7, 0xF9, 0xB7, 0x51, 0x78, 0x27, 0xF9, 0x50,
				0x22 }, 32
	}
};

void test_derivation_base( void* );
void test_variant_derivation(  );
void test_binding( void* );

TEST tr31_tests [] = {
	{ "derivation base, double-length DES", test_derivation_base, &derivation_base_tests[0]	},
	{ "derivation base, triple-length DES", test_derivation_base, &derivation_base_tests[1]	},
	{ "derivation base, AES 128", test_derivation_base, &derivation_base_tests[2]	},
	{ "derivation base, AES 192", test_derivation_base, &derivation_base_tests[3]	},
	{ "derivation base, AES 256", test_derivation_base, &derivation_base_tests[4]	},
	{ "Variant derivation", test_variant_derivation, NULL },
	{ "Binding derivation, 2TDES encryption", test_binding, &binding_tests[0]},
	{ "Binding derivation, 2TDES MAC", test_binding, &binding_tests[1]},
	{ "Binding derivation, 2TDES encryption", test_binding, &binding_tests[2]},
	{ "Binding derivation, 2TDES MAC", test_binding, &binding_tests[3]},
	{ "Binding derivation, AES encryption", test_binding, &binding_tests[4]},
	{ "Binding derivation, AES MAC", test_binding, &binding_tests[5]},
};

void test_derivation_base( void* input ) {
	TR31_DERIVATION_BASE_TEST *p = (TR31_DERIVATION_BASE_TEST*) input;
	TR31_KEY_DERIVATION_BASE base;

	tr31_prepare_key_derivation(&base, p->counter, p->key_usage, p->algorithm);
	print_array("Key derivation base: ", (uint8_t*)&base, TR31_KEY_DERIVATION_BASE_SIZE, "\n");
}

void test_binding(  void * input ) {
	TR31_BINDING_DERIVATION_TEST *p = (TR31_BINDING_DERIVATION_TEST*) input;
	uint8_t output[AES_KEY_LENGTH_3];

	memset(output, 0xFF, AES_KEY_LENGTH_3);

	printf("\tKey usage: %s\n", tr31_usage[p->key_usage]);
	printf("\tDerivation algorithm: %s\n", tr31_algorithm_name[p->derivation_algorithm]);
	print_array("\tKBPK: ", p->kbpk, p->kbpk_len, "\n");
	tr31_derive_binding(p->key_usage, p->derivation_algorithm, p->kbpk, output);
	print_array("\tOutput: ", output, p->result_len, "");
	if (!memcmp(output, p->result, p->result_len ))
		printf(" valid\n");
	else
		printf(" invalid\n");
}

void test_variant_derivation( void ) {
	for (size_t i = 0; i < sizeof(variant_tests)/sizeof(TR31_VARIANT_DERIVATION_TEST); i++) {
		uint8_t output[TDES_KEY_LENGTH_3];
		TR31_VARIANT_DERIVATION_TEST *p = variant_tests +i;

		print_array("KBPK: " , p->kbpk, p->kbpk_len, "\n");
		tr31_derive_variant(p->kbpk, p->kbpk_len, p->key_usage, output);
		print_array("Output: ", output, p->kbpk_len, "");

		if (!memcmp(output, p->output, p->kbpk_len))
			printf(" valid\n");
		else
			printf(" invalid\n");
	}
}

int main (void) {

	for (size_t c = 0; c< sizeof(tr31_tests)/sizeof(TEST); c++)
		run_test(tr31_tests+c);


}
