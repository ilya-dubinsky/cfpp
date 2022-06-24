#include "crypto.h"

#include <stdlib.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/**
 * Allocates and returns an RSA structure or NULL in case of an error. It is the caller's responsibility
 * to call RSA_free on the return value.
 *
 * @param n the modulus
 * @param n_len the modulus length
 * @param e the exponent
 * @param d the private key, can be NULL
 * @param d_len size of the private key, must be 0 if d is NULL
 * @result the RSA structure or NULL if an error occurred
 */
RSA *make_rsa_key( uint8_t n[], size_t n_len, uint32_t e, uint8_t d[], size_t d_len ) {
	/* validate the inputs */
	if (! (n&& n_len)) return NULL;
	/* allocate the RSA structure */
	RSA* retval = RSA_new();
	if (!retval) return retval;

	/* allocate the BIGNUMs */
	BIGNUM * bn_n = BN_bin2bn(n, n_len, NULL);
	if (!bn_n) goto cleanup;

	BIGNUM *bn_e = BN_new();
	if (!bn_e) goto cleanup;
	if (!BN_set_word(bn_e, e)) goto cleanup;

	BIGNUM *bn_d = NULL;

	if (d_len>0) {
		bn_d = BN_bin2bn(d, d_len, NULL);
		if (!bn_d) goto cleanup;
	}

	/* place the BIGNUMs in the key */
	if (RSA_set0_key(retval, bn_n, bn_e, bn_d)!=ERR_LIB_NONE) {
		/* setting the key failed */
		RSA_free(retval);
		return NULL;
	}

cleanup:
	if (retval == NULL)  {
		/* RSA structure wasn't formed, there was an error and we need to free the BIGNUM's */
		if (bn_n) BN_free(bn_n);
		if (bn_e) BN_free(bn_e);
		if (bn_d) BN_free(bn_d);
	}
	return retval;
}
