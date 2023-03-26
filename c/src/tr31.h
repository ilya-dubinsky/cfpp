
#ifndef CFPP_TR31_H_
#define CFPP_TR31_H_

#include <stdlib.h>
#include <stdint.h>

#define TR31_OK 0
#define TR31_ERROR -1

/* Definitions for key derivation */
/* Working key usage, encryption or MAC*/
#define TR31_KEY_USAGE_ENC 	0x0000
#define TR31_KEY_USAGE_MAC 	0x0001

#define TR31_SEPARATOR 		0x00

/* Key algorithm */
#define TR31_ALGO_2TDEA 	0x0000
#define TR31_ALGO_3TDEA 	0x0001
#define TR31_ALGO_AES128 	0x0002
#define TR31_ALGO_AES192 	0x0003
#define TR31_ALGO_AES256 	0x0004

#define VALID_KEY_USAGE(x) (TR31_KEY_USAGE_ENC == (x) || TR31_KEY_USAGE_MAC == (x) )
#define VALID_ALGORITHM(x) (( TR31_ALGO_2TDEA == (x) || \
			TR31_ALGO_3TDEA == (x) || \
			TR31_ALGO_AES128 == (x)|| \
			TR31_ALGO_AES192 == (x)|| \
			TR31_ALGO_AES256 == (x) ))

/* Definitions for key block header values */

/* Key block version, variants A, B, C, and D */
#define TR31_KB_VAR_A		0x41
#define TR31_KB_TDES_KD_B	0x42
#define TR31_KB_TDES_VAR_C	0x43
#define TR31_KB_AES_KD_D	0x44

/* Key block variant chars, encryption and MAC */
#define TR31_VAR_ENC_CHAR 0x45
#define TR31_VAR_MAC_CHAR 0x4D

/* Key usage values, these are for a future development */
#define TR31_USAGE_BDK			"B0" /* BDK Base Derivation Key */
#define TR31_USAGE_DUKPT_IK		"B1" /* Initial DUKPT Key */
#define TR31_USAGE_BK_VK		"B2" /* Base Key Variant Key */
#define TR31_USAGE_CVK			"C0" /* CVK Card Verification Key */
#define TR31_USAGE_SY_ENC		"D0" /* Symmetric Key for Data Encryption */
#define TR31_USAGE_ASY_ENC		"D1" /* Asymmetric Key for Data Encryption */
#define TR31_USAGE_DEC_ENC		"D2" /* Data Encryption Key for Decimalization Table */
#define TR31_USAGE_IMK_AC		"E0" /* EMV/chip Issuer Master Key: Application cryptograms */
#define TR31_USAGE_IMK_ENC		"E1" /* EMV/chip Issuer Master Key: Secure Messaging for Confidentiality */
#define TR31_USAGE_IMK_MAC		"E2" /* EMV/chip Issuer Master Key: Secure Messaging for Integrity */
#define TR31_USAGE_IMK_DAC		"E3" /* EMV/chip Issuer Master Key: Data Authentication Code */
#define TR31_USAGE_IMK_DYN		"E4" /* EMV/chip Issuer Master Key: Dynamic Numbers */
#define TR31_USAGE_IMK_PERS		"E5" /* EMV/chip Issuer Master Key: Card Personalization */
#define TR31_USAGE_IMK_MISC		"E6" /* EMV/chip Issuer Master Key: Other */
#define TR31_USAGE_IV			"I0" /* Initialization Vector (IV) */
#define TR31_USAGE_KEK			"K0" /* Key Encryption or wrapping */
#define TR31_USAGE_KBPK			"K1" /* TR-31 Key Block Protection Key */
#define TR31_USAGE_ASYM_KEK		"K2" /* TR-34 Asymmetric key */
#define TR31_USAGE_ASYM_KA		"K3" /* Asymmetric key for key agreement/key wrapping */
#define TR31_USAGE_MAC_0		"M0" /* ISO 16609 MAC algorithm 1 (using TDEA) */
#define TR31_USAGE_MAC_1		"M1" /* ISO 9797-1 MAC Algorithm 1 */
#define TR31_USAGE_MAC_2		"M2" /* ISO 9797-1 MAC Algorithm 2 */
#define TR31_USAGE_MAC_3		"M3" /* ISO 9797-1 MAC Algorithm 3 */
#define TR31_USAGE_MAC_4		"M4" /* ISO 9797-1 MAC Algorithm 4 */
#define TR31_USAGE_MAC_5		"M5" /* ISO 9797-1:1999 MAC Algorithm 5 */
#define TR31_USAGE_MAC_6		"M6" /* ISO 9797-1:2011 MAC Algorithm 5/CMAC */
#define TR31_USAGE_MAC_7		"M7" /* HMAC */
#define TR31_USAGE_MAC_8		"M7" /* ISO 9797-1:2011 MAC Algorithm 6 */
#define TR31_USAGE_PEK			"P0" /* PIN Encryption */
#define TR31_USAGE_ASYM_DS		"S0" /* Asymmetric key pair for digital signature */
#define TR31_USAGE_ASYM_CA		"S1" /* Asymmetric key pair, CA key */
#define TR31_USAGE_ASYM_MISC	"S2" /* Asymmetric key pair, nonX9.24 key */
#define TR31_USAGE_PV_MISC		"V0" /* PIN verification, KPV, other algorithm */
#define TR31_USAGE_PV_3624	 	"V1" /* PIN verification, IBM 3624 */
#define TR31_USAGE_PV_PVV	 	"V2" /* PIN Verification, VISA PVV */
#define TR31_USAGE_PV_X9132_1 	"V3" /* PIN Verification, X9.132 algorithm 1 */
#define TR31_USAGE_PV_X9132_2 	"V4" /* PIN Verification, X9.132 algorithm 2 */

/* Algorithms used by the protected key*/
#define TR31_ALG_AES 			'A'  /* AES */
#define TR31_ALG_DEA 			'D'  /* DEA */
#define TR31_ALG_EC 			'E'  /* Elliptic Curve */
#define TR31_ALG_HMAC 			'H'  /* HMAC */
#define TR31_ALG_RSA 			'R'  /* RSA */
#define TR31_ALG_DSA 			'S'  /* DSA */
#define TR31_ALG_TDEA 			'T'  /* TDES */

/* Mode of use of the protected key */
#define TR31_MOD_ENC_BOTH		'B'	/* Both Encrypt & Decrypt / Wrap & Unwrap */
#define TR31_MOD_SIG_BOTH		'S'	/* Both Generate & Verify */
#define TR31_MOD_ENC_DEC		'D'	/* Decrypt / Unwrap Only */
#define TR31_MOD_GEN			'G'	/* Generate Only */
#define TR31_MOD_NONE			'N'	/* No special restrictions (other than restrictions implied by the Key Usage) */
#define TR31_MOD_SIG			'S'	/* Signature Only */
#define TR31_MOD_SIG_DEC		'T'	/* Both Sign & Decrypt */
#define TR31_MOD_VERIFY			'V'	/* Verify Only */
#define TR31_MOD_DERIVE			'X'	/* Key used to derive other key(s) */
#define TR31_MOD_VARIANT		'Y'	/* Key used to create key variants */

/* Key version */
#define TR31_VER_NOT_USED		'0' /* Key versioning is not used for this key.*/
#define TR31_VER_COMPONENT		'c' /* The value carried in this key block is a component of a key. */

/* Exportability */
#define TR31_EXP_EXPORTABLE		'E' /* Exportable under a KEK in a form meeting the requirements of X9.24 Parts 1 or 2. */
#define TR31_EXP_NONEXPORTABLE	'N' /* Non-exportable by the receiver of the key block, or from storage. Does not preclude exporting keys derived from a non-exportable key.*/
#define TR31_EXP_SENSITIVE		'S'	/* Sensitive, Exportable under a KEK in a form not necessarily meeting the requirements of X9.24 Parts 1 or 2. */

#define TR31_KEY_DERIVATION_BASE_SIZE 8

typedef struct tagTR31_KEY_DERIVATION_BASE {
	uint8_t counter;
	uint8_t key_usage[2];
	uint8_t separator; /* must always be equal to TR31_SEPARATOR */
	uint8_t algorithm[2];
	uint8_t length[2];

} TR31_KEY_DERIVATION_BASE;

/** Populates the data in the key derivation base structure, conscious of byte order
 *  @param base the struct to populate
 *  @param counter the counter value
 *  @key_usage key usage (encryption or MAC)
 *  @algorithm algorithm (a flavor of TDES or AES)
 *  @length desired key length
 *  @result TR31_OK if ok, TR31_ERROR otherwise
 */
int tr31_prepare_key_derivation(TR31_KEY_DERIVATION_BASE *base, uint8_t counter,
		uint16_t key_usage, uint16_t algorithm);

/** Derives encryption/MAC keys using the variant method.
 *  @param kbpk 		Key Block Protection Key
 *  @param kbpk_size 	Length of the KBPK, can be either double or triple TDES.
 *  @param key_usage	Defines key usage, TR31_KEY_USAGE_ENC or TR31_KEY_USAGE_MAC
 *  @param output  		Output buffer, must be same length as the KBPK
 *  @result TR31_OK if OK, TR31_ERROR otherwise
 */
int tr31_derive_variant( uint8_t * kbpk, size_t kbpk_size, uint8_t key_usage, uint8_t * output );

/**
 * Derives keys in the binding mode, according to ANSI TR-31, by calculating
 * CMAC with the specified block cipher on an input vector as defined in TR31_KEY_DERIVATION_BASE.
 *
 * @param key_usage Derived key usage, TR31_KEY_USAGE_ENC or TR31_KEY_USAGE_MAC
 * @param derivation_algorithm Derivation algorithm, double or triple TDES, or an AES flavor
 * @param output Buffer for the derived key of sufficient length
 * @result returns TR31_OK on success or TR31_ERROR otherwise
 */
int tr31_derive_binding(uint16_t key_usage,
		uint16_t derivation_algorithm, uint8_t * kbpk, uint8_t* output);

/* some string arrays for human-readable display of parameters */
extern const char * tr31_algorithm_name[];
extern const char * tr31_usage[];

#endif /* SRC_TR31_H_ */
