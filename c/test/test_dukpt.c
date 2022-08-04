#include "dukpt.h"
#include "test_io.h"
#include "crypto.h"

#include <stdlib.h>
#include <string.h>

uint8_t tdes_bdk_ansi[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE,
		0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
uint8_t aes_bdk_ansi[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1,
		0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1 };


uint8_t tdes_ksn_ansi[] = { 0xFF, 0xFF, 0x98, 0x76, 0x54, 0x32, 0x10, 0xE0,
		0x00, 0x00 };


uint8_t tdes_bdk[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x22, 0x33, 0x44, 0x55, 0xDE,
		0xAD, 0xBE, 0xEF, 0x22, 0x33, 0x44, 0x55 };
uint8_t aes_bdk[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x22, 0x33, 0x44, 0x55, 0xDE,
		0xAD, 0xBE, 0xEF, 0x22, 0x33, 0x44, 0x55, 0xDE, 0xAD, 0xBE, 0xEF, 0x22, 0x33, 0x44, 0x55, 0xDE,
		0xAD, 0xBE, 0xEF, 0x22, 0x33, 0x44, 0x55 };
uint8_t tdes_ksn[] = { 0xFF, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x22, 0x33, 0x44,
		0x55 };

uint8_t __attribute__ ((aligned(4))) aes_ksn_ansi[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00,
		0x00, 0x00, 0x00 };

typedef struct tagTDES_TEST {
	uint8_t * bdk;
	uint8_t * initial_ksn;
} TDES_TEST;

typedef struct tagAES_TEST {
	uint8_t * bdk;
	size_t bdk_len;
	uint8_t * initial_ksn;
} AES_TEST;

AES_TEST aes_tests[] = {
	{ aes_bdk_ansi, sizeof(aes_bdk_ansi), aes_ksn_ansi},
	{ aes_bdk, sizeof(aes_bdk), aes_ksn_ansi }
};

TDES_TEST tdes_tests[] = {
	{tdes_bdk_ansi, tdes_ksn_ansi},
	{tdes_bdk, tdes_ksn}
};

static char* tdes_worker_key_names [] = {
	"PIN encryption", /* DUKPT_KEY_TYPE_PIN 	*/
	"MAC (request)",  /* DUKPT_KEY_TYPE_MAC_REQ */
	"MAC (response)", /* DUKPT_KEY_TYPE_MAC_RES */
	"Data encryption" /* DUKPT_KEY_TYPE_ENC_REQ */
};



void dukpt_tdes_test (void * data) {
	TDES_TEST * p = (TDES_TEST*) data;

	uint8_t ik[TDES_KEY_LENGTH_2];
	print_test_step(1, "Deriving IK");
	dukpt_derive_initial_key(p->bdk, TDES_KEY_LENGTH_2, p->initial_ksn, ALGORITHM_TDES, ik);
	print_array("IK: ", ik, TDES_KEY_LENGTH_2, "\n");

	p->initial_ksn[7]&=0xE0;
	p->initial_ksn[8]=0;
	p->initial_ksn[9]=0x1;

	print_array("\n\n\t\t\tKSN: ", p->initial_ksn, DUKPT_DES_KSN_LEN, "\n");
	print_test_step(2, "Deriving Intermediate Key for KSN 1");
	uint8_t interkey[TDES_KEY_LENGTH_2];
	dukpt_des_derive_intermediate_key( ik, p->initial_ksn, interkey);
	print_array("Resulting key: ", interkey, TDES_KEY_LENGTH_2, "\n");
	print_array("\n\n\t\t\tKSN: ", p->initial_ksn, DUKPT_DES_KSN_LEN, "\n");


	print_test_step(3, "Deriving Intermediate Key for KSN 0xA");

	p->initial_ksn[9]=0xB;
	print_array("\n\n\t\t\tKSN: ", p->initial_ksn, DUKPT_DES_KSN_LEN, "\n");

	dukpt_des_derive_intermediate_key( ik, p->initial_ksn, interkey);
	print_array("Resulting key: ", interkey, TDES_KEY_LENGTH_2, "\n");


	uint8_t worker_key [TDES_KEY_LENGTH_2];
	for (size_t i=0; i<sizeof(tdes_worker_key_names)/sizeof(char*); i++) {

		print_test_step(4+i, tdes_worker_key_names[i]);
		dukpt_des_derive_worker_key(interkey, i, worker_key);
		print_array("\t\tWorker key: ", worker_key, TDES_KEY_LENGTH_2, "\n");
	}
}


void dukpt_aes_test(void* data) {
	AES_TEST *p = (AES_TEST*)data;

	uint8_t ik [AES_KEY_LENGTH_1];
	memset(ik, 0, AES_KEY_LENGTH_1);
	int klen = 0;
	print_array("\n\n\t\tKSN: ", aes_ksn_ansi, DUKPT_AES_KSN_LEN, "\n");

	print_test_step(1, "Derive initial key");

	klen = dukpt_derive_initial_key(p->bdk, p->bdk_len, p->initial_ksn,  ALGORITHM_AES, ik);
	if (klen>0)
		print_array( "Result: ", ik, klen, "\n");

	print_test_step(2, "Derive an intermediate key for KSN 1");
	p->initial_ksn[11]=0x1;

	uint8_t inter_key[AES_KEY_LENGTH_1];

	klen = dukpt_aes_derive_intermediate_key(ik, p->initial_ksn, inter_key);

	print_test_step(3, "Derive an intermediate key for KSN 5");
	p->initial_ksn[11]=0x5;

	klen = dukpt_aes_derive_intermediate_key(ik, p->initial_ksn, inter_key);
	if (klen>0)
		print_array("Result: ", inter_key, klen, "\n");

	print_test_step(4, "Derive a PIN encryption key for KSN 5");
	uint8_t worker_key[AES_KEY_LENGTH_1];

	klen = dukpt_aes_derive_worker_key(inter_key, DUKPT_AES_USAGE_PIN_ENC, p->initial_ksn, worker_key);
	if (klen>0)
		print_array("Result: ", worker_key, klen, "\n");

	p->initial_ksn[11]=0x0;

}

TEST dukpt_tests[] = {
	{"DUKPT TDES ANSI test", dukpt_tdes_test, &(tdes_tests[0])},
	{"DUKPT TDES book test", dukpt_tdes_test, &(tdes_tests[1])},
	{"DUKPT AES ANSI test", dukpt_aes_test, &(aes_tests[0])},
	{"DUKPT AES book test", dukpt_aes_test, &(aes_tests[1])}
};

int main (void) {

	for (size_t c = 0; c< sizeof(dukpt_tests)/sizeof(TEST); c++)
		run_test(dukpt_tests+c);
}
