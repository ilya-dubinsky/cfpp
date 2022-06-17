#include <stdlib.h>
#include <string.h>

#include "payments.h"
#include "bits.h"
#include "test_io.h"

#include <openssl/des.h>
#include <openssl/err.h>


/**
 * Computes the CVV value
 * @param pan input PAN, as an array of unpacked BCD
 * @param pan_length PAN length
 * @param expiry Expiry date, unpacked BCD array of 4 positions
 * @param service_code Service code, unpacked BCD array of 3 positions
 * @param cvk_a first half of the CVV key, 8 bytes
 * @param cvk_b second half of the CVV key, 8 bytes
 * @param output Pointer to store the unpacked CVV
 * @param output_len size of the desired output CVV
 * @result 0 for success, -1 for failure
 */
int compute_cvv( uint8_t * pan, size_t pan_length, uint8_t * expiry, uint8_t * service_code, uint8_t* cvk_a, uint8_t* cvk_b,
		uint8_t * output, size_t output_len) {

	/* error code for OpenSSL operations */
	unsigned long error_code;

	int result = PAYMENTS_ERROR;

	/* initial value check */
	if (! (pan && pan_length && expiry && service_code && cvk_a && cvk_b && output && output_len ))
		return PAYMENTS_ERROR;
	/* more validations of length here: */
	if (!VALID_PAN_LENGTH(pan_length))
		return PAYMENTS_ERROR;

	/* copy and initialize keys. The keys WONT be checked for weakness or for parity */
	DES_key_schedule key_a, key_b;

	DES_set_key_unchecked( (const_DES_cblock *)cvk_a, &key_a);
	DES_set_key_unchecked( (const_DES_cblock *)cvk_b, &key_b);

	/* initialize the input values */
	DES_cblock input1;
	memset(&input1, 0, 8);
	DES_cblock input2;
	memset(&input2, 0, 8);

	/* prepare the input value for step 1 */
	if (pack_bcd(pan, pan_length, input1, 8, PAD_RIGHT) <0)
		goto cleanup;

	print_array("\t Input for step 1: ", input1, sizeof(input1), "\n");
	/* encrypt, single DES, with key a */
	DES_ecb_encrypt(&input1, &input1, &key_a, 1);
	print_array("\t Output of step 1: ", input1, sizeof(input1), "\n");

	error_code = ERR_get_error();
	if (error_code)
		goto cleanup;

	/* combine the expiry and service code into one array for the ease of packing */
	uint8_t step2_unpacked[7];
	memcpy(step2_unpacked, expiry, 4);
	memcpy(step2_unpacked+4, service_code, 3);
	/* prepare the input value for step 2 */

	if (pack_bcd(step2_unpacked, 7, input2, 8, PAD_RIGHT)<0)
		goto cleanup;

	print_array("\t Second block prior to XOR: ", input2, sizeof(input2), "\n");
	/* xor input2 to input1 */
	if (xor_array((uint8_t*)&input1, (uint8_t*)&input2, (uint8_t*)&input1, 8)<0)
		goto cleanup;

	print_array("\t Value after XOR: ", input1, sizeof(input1), "\n");
	/* step 3 - 3DES encryption of the result in input1 */
	DES_ecb2_encrypt(&input1, &input1, &key_a, &key_b, DES_ENCRYPT);
	print_array("\t Value before decimalization: ", input1, sizeof(input1), "\n");

	error_code = ERR_get_error();
	if (error_code)
		goto cleanup;

	/* step 4 - decimalize */
	if (decimalize_vector((uint8_t*)&input1, 16, output, output_len)<0)
		goto cleanup;

	result = PAYMENTS_SUCCESS;
cleanup:
	PURGE(key_a);
	PURGE(key_b);
	PURGE(input1);
	PURGE(input2);
return result;
}

/**
 * Computes the PVV
 * @param pan the PAN, unpacked BCD. The last digit is assumed to be the check digit
 * @param pan_len pan size
 * @param pin unpacked BCD of the PIN, min 4 digits, only they are going to be used
 * @param pvki single digit PVKI
 * @param pvk_a PVK A key
 * @param pvk_b PVK B key
 * @param output target vector
 * @result 0 on success, -1 on failure.
 */
int compute_pvv (uint8_t * pan, size_t pan_len, uint8_t *pin, uint8_t pvki, uint8_t *pvk_a, uint8_t *pvk_b, uint8_t * output) {
	/* error code for OpenSSL operations */
	unsigned long error_code;
	int result = PAYMENTS_ERROR;

	/* validations */
	if (! (pan && pan_len && pin && pvk_a && pvk_b && output ))
		return PAYMENTS_ERROR;

	if (pan_len < 12)
		return PAYMENTS_ERROR;

	/* prepare the unpacked and the packed data vectors */
	uint8_t tsp[8];
	memset(tsp, 0, 8);

	uint8_t tsp_unpacked[16];
	memset(tsp_unpacked, 0, 16);

	/* copy last 11 digits of the PAN sans the check digit */
	memcpy (tsp_unpacked, pan + (pan_len-12), 11);
	/* copy the PVKI */
	tsp_unpacked[11]=pvki;
	/* copy the first 4 digits of the PIN */
	memcpy (tsp_unpacked+12, pin, 4);

	/* pack the BCD */
	pack_bcd(tsp_unpacked, 16, tsp, 8, PAD_RIGHT);
	print_array("\t Input value, packed: ", tsp, 8, "\n");

	/* prepare the DES key schedules */
	DES_key_schedule key_a, key_b;

	DES_cblock des_output;

	DES_set_key_unchecked( (const_DES_cblock *)pvk_a, &key_a);
	DES_set_key_unchecked( (const_DES_cblock *)pvk_b, &key_b);

	DES_ecb2_encrypt((DES_cblock *)tsp, &des_output, &key_a, &key_b, DES_ENCRYPT);
	print_array("\t Output after encryption: ", des_output, 8, "\n");

	error_code = ERR_get_error();
	if (error_code)
		goto cleanup;

	if (decimalize_vector(des_output, 16, output, 4)<0)
		goto cleanup;

	result = PAYMENTS_SUCCESS;

cleanup:
	PURGE(tsp_unpacked);
	PURGE(tsp);
	PURGE(des_output);
	PURGE(key_a);
	PURGE(key_b);
	return result;
}
