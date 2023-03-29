package org.ilyadubinsky.cfpp.crypto;

import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

public class Constants {
	
	/* Key lengths and block sizes */
	public static final int AES_KEY_SIZE_1_B = 16; // 128 bit
	public static final int AES_KEY_SIZE_2_B = 24; // 192 bit
	public static final int AES_KEY_SIZE_3_B = 32; // 256 bit
	

	public static final int AES_BLOCK_SIZE_B = 16; // 128 bit
	
	public static final int DES_KEY_SIZE_1_B = DESKeySpec.DES_KEY_LEN; // Single DES - 8 bytes/64 bits
	public static final int DES_KEY_SIZE_2_B = DESKeySpec.DES_KEY_LEN *2; // Double DES - 16 bytes/128 bit
	public static final int DES_KEY_SIZE_3_B = DESedeKeySpec.DES_EDE_KEY_LEN; // Double DES - 24 bytes/192 bit
	
	public static final int DES_BLOCK_SIZE_B = 8;
	
	/* constants used to load Ciphers and Signatures */
	public static final String DSA_SHA256_ALGORITHM = "SHA256withDSA";
	public static final String TDES_ECB_NO_PADDING_ALGORITHM = "DESede/ECB/NoPadding";
	public static final String TDES_CBC_NO_PADDING_ALGORITHM = "DESede/CBC/NoPadding";
	public static final String DES_ECB_NO_PADDING_ALGORITHM = "DES/ECB/NoPadding";
	public static final String AES_ECB_NO_PADDING = "AES/ECB/NoPadding";
	public static final String AES_CBC_NO_PADDING = "AES/CBC/NoPadding";
	public static final String RSA_ECB_NO_PADDING = "RSA/ECB/NoPadding";
	public static final String RSA_ECB_OAEP = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	public static final String DIFFIE_HELLMAN = "DiffieHellman";

	public static final String HMAC_SHA256 = "HmacSHA256";
	public static final String HMAC_SHA1 = "HmacSHA1";
	public static final String SHA1 = "SHA-1";

	/* constants used to instantiate keys */
	public static final String DSA_KEY_ALGORITHM = "DSA";
	public static final String DES_KEY_ALGORITHM = "DES";
	public static final String TDES_KEY_ALGORITHM = "DESede";
	public static final String AES_KEY_ALGORITHM = "AES";
	public static final String RSA_KEY_ALGORITHM = "RSA";
	public static final String DIFFIE_HELLMAN_KEY_ALGORITHM = "DiffieHellman";
	
}
