#ifndef __CFPP_PAYMENTS_H
#define __CFPP_PAYMENTS_H

#define MIN_PAN_LENGTH 13
#define MAX_PAN_LENGTH 19

#define CSN_LENGTH 2

#define VALID_PAN_LENGTH(x) ( (x)>=MIN_PAN_LENGTH && (x) <= MAX_PAN_LENGTH)

#define PAYMENTS_ERROR 	-1
#define PAYMENTS_SUCCESS 0


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
		uint8_t * output, size_t output_len);

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
int compute_pvv (uint8_t * pan, size_t pan_len, uint8_t *pin, uint8_t pvki, uint8_t *pvk_a, uint8_t *pvk_b, uint8_t * output);

#endif
