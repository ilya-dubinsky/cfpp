#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test_io.h"

#include "bits.h"
#include "payments.h"

void test_decimalization();
void test_cvv();
void test_pvv();

TEST magstripe_tests[] =
{
	{
		"Decimalization",
		test_decimalization,
		NULL
	},
	{
		"CVV",
		test_cvv,
		NULL
	},
	{
		"PVV",
		test_pvv,
		NULL
	}
};


/** Tests decimalization */
typedef struct tagDECIMALIZATION_TEST {
	uint8_t input_vector[64];
	size_t input_len;
	size_t output_len;
} DECIMALIZATION_TEST;

DECIMALIZATION_TEST decimalization_tests []  = {
		{
				{0xEF, 0x11, 0xCD, 0x12},
				8,
				3
		},
		{
				{0xFE, 0x4A, 0xCD, 0x2B},
				8,
				3
		},
		{
				{0xDE, 0xAD, 0xBE, 0xEF},
				8,
				10
		},
		{
				{0xB3, 0xAB, 0xAF, 0xDF, 0x8B, 0x26, 0x83, 0xC7},
				16,
				3
		}
};

void test_decimalization() {
	for (size_t i =0; i<sizeof(decimalization_tests)/sizeof(decimalization_tests[0]); i++) {
		uint8_t output[64];
		memset(output, 0, 10);
		DECIMALIZATION_TEST *p = decimalization_tests+i;
		print_test_step(i+1, "Decimalization test");
		int r = decimalize_vector(p->input_vector, p->input_len, output, p->output_len);
		printf("Digits extracted: %d\n", r);
		print_array("Test input vector:", p->input_vector, p->input_len>>1, "\n");
		print_array("Decimalized value:", output, r, "\n");
		printf("\n");
	}
}


typedef struct tag_CVV_TEST {
	uint8_t pan[16];
	uint8_t expiry[4];
	uint8_t service_code[3];
	uint8_t output_cvv[3];
} CVV_TEST;

CVV_TEST cvv_tests[] = {
		{
				{ 0x4, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5 },
				{ 0x8, 0x7, 0x0, 0x1 },
				{ 0x1, 0x0, 0x1 },
				{ 0x5, 0x6, 0x1 }
		},
		{
				{ 0x4, 0x9, 0x9, 0x9, 0x9, 0x8, 0x8, 0x8, 0x8, 0x7, 0x7, 0x7, 0x7, 0x0, 0x0, 0x0 },
				{ 0x9, 0x1, 0x0, 0x5 },
				{ 0x1, 0x1, 0x1 },
				{ 0x2, 0x4, 0x5 }
		},
		{
				{ 0x4, 0x6, 0x6, 0x6, 0x6, 0x5, 0x5, 0x5, 0x5, 0x4, 0x4, 0x4, 0x4, 0x1, 0x1, 0x1 },
				{ 0x9, 0x2, 0x0, 0x6 },
				{ 0x1, 0x2, 0x0 },
				{ 0x6, 0x6, 0x4 }
		},
		{
				{ 0x4, 0x3, 0x3, 0x3, 0x3, 0x2, 0x2, 0x2, 0x2, 0x1, 0x1, 0x1, 0x1, 0x2, 0x2, 0x2 },
				{ 0x9, 0x3, 0x0, 0x7 },
				{ 0x1, 0x4, 0x1 },
				{ 0x3, 0x8, 0x2 }
		}
};

uint8_t cvv_key_a[]={0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
uint8_t cvv_key_b[]={0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};

/** Tests cvv generation */
void test_cvv() {

	print_array("Test CVK A: ", cvv_key_a, sizeof(cvv_key_a), "\n");
	print_array("Test CVK B: ", cvv_key_b, sizeof(cvv_key_b), "\n");

	for (size_t i = 0; i <sizeof(cvv_tests)/sizeof(cvv_tests[0]); i++) {
		CVV_TEST *p = cvv_tests+i;
		uint8_t output[3];
		uint8_t output_packed[2];


		print_test_step(i+1, "CVV test");
		printf("Unpacked input data:\n");
		print_array("\t PAN: ", p->pan, 16, "\n");
		print_array("\t Expiry: ", p->expiry, 4, "\n");
		print_array("\t Service code: ", p->service_code, 3, "\n");


		compute_cvv( p->pan, 16, p->expiry, p->service_code, cvv_key_a, cvv_key_b, output, 3);
		pack_bcd(output, 3, output_packed, 2, PAD_LEFT);
		print_array("CVV result: ", output_packed, 2, " ");

		if (!memcmp(output, p->output_cvv, 3))
			printf(" - valid\n");
		else
			printf(" - invalid\n");
	}
	printf("\n");
}


uint8_t pvv_key_a[]={0x23,0x32,0x20,0xCC,0xDD,0xCC,0x32,0x23};
uint8_t pvv_key_b[]={0x15,0xC4,0x4C,0x2A,0x51,0xA2,0xDF,0xFD};

typedef struct tag_PVV_TEST {
	uint8_t pan[20];
	uint8_t pan_length;
	uint8_t pin[4];
	uint8_t pvki;
	uint8_t pvv[4];
} PVV_TEST;

PVV_TEST pvv_tests[]={
		{
				{4,4,4,4,3,3,3,3,2,2,2,2,1,1,1,1},
				16,
				{1,2,3,4},
				1,
				{7,2,1,1}
		},
		{
				{4,4,4,4,8,8,8,8,1,1,1,1,2,2,2,2,3,3,3},
				19,
				{1,2,3,4},
				1,
				{7,6,4,0}
		}
};

void test_pvv(){
	print_array("Test PVK A: ", pvv_key_a, sizeof(cvv_key_a), "\n");
	print_array("Test PVK B: ", pvv_key_b, sizeof(cvv_key_b), "\n");
	for (size_t i = 0; i <sizeof(pvv_tests)/sizeof(pvv_tests[0]); i++) {
		PVV_TEST *p = pvv_tests+i;
		uint8_t output[4];
		uint8_t output_packed[2];

		print_test_step(i+1, "PVV test");
		printf("Unpacked input data:\n");
		print_array("\t PAN: ", p->pan, p->pan_length, "\n");
		print_array("\t PIN: ", p->pin, 4, "\n");
		printf("\t PVKI: %d\n", p->pvki);

		compute_pvv( p->pan, p->pan_length, p->pin, p->pvki, pvv_key_a, pvv_key_b, output);

		pack_bcd(output, 4, output_packed, 2, PAD_LEFT);
		print_array("PVV result: ", output_packed, 2, " ");

		if (!memcmp(output, p->pvv, 4))
			printf(" - valid\n");
		else
			printf(" - invalid\n");


	}

}


int main(void) {
	for (size_t c = 0; c< sizeof(magstripe_tests)/sizeof(TEST); c++)
		run_test(magstripe_tests+c);

}
