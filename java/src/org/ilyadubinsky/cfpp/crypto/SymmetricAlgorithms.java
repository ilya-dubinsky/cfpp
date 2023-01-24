package org.ilyadubinsky.cfpp.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.ilyadubinsky.cfpp.utilis.TestIO;

public class SymmetricAlgorithms {

	/**
	 * @param plainInput Input vector, must be a single block
	 * @param key        Encryption key, must be a DES single key
	 * @return Encrypted value with a single DES
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptDESBlock(byte[] plainInput, byte[] key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (null == plainInput || null == key || plainInput.length != Constants.DES_BLOCK_SIZE_B
				|| key.length != Constants.DES_KEY_SIZE_1_B)
			return null;

		Cipher c = Cipher.getInstance(Constants.DES_ECB_NO_PADDING_ALGORITHM);

		SecretKeySpec encKey = new SecretKeySpec(key, Constants.DES_KEY_ALGORITHM);

		c.init(Cipher.ENCRYPT_MODE, encKey);

		return c.doFinal(plainInput);
	}

	/**
	 * @param cipherInput Encrypted input, a single block
	 * @param key         Decryption key, must be a single DES key
	 * @return Value, decrypted using single-DES
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptDESBlock(byte[] cipherInput, byte[] key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (null == cipherInput || null == key || cipherInput.length != Constants.DES_BLOCK_SIZE_B
				|| key.length != Constants.DES_KEY_SIZE_1_B || cipherInput.length != Constants.DES_BLOCK_SIZE_B)
			return null;

		Cipher c = Cipher.getInstance(Constants.DES_ECB_NO_PADDING_ALGORITHM);

		SecretKeySpec decKey = new SecretKeySpec(key, Constants.DES_KEY_ALGORITHM);

		c.init(Cipher.DECRYPT_MODE, decKey);

		return c.doFinal(cipherInput);
	}

	/**
	 * @param plainInput Input vector, must be a single block
	 * @param key        Encryption key, must be a DES single, double, or triple key
	 * @return Encrypted value with triple-DES, or null if the input is invalid
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptTDESBlock(byte[] plainInput, byte[] key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (null == plainInput || null == key || !SymmetricAlgorithms.isValidTDESKeyLength(key.length)
				|| plainInput.length != Constants.DES_BLOCK_SIZE_B)
			return null;

		byte[] tdesKey = getFullLengthTDESKey(key);

		System.out.println("Input: " + TestIO.printByteArray(plainInput));
		System.out.println("Full key: " + TestIO.printByteArray(tdesKey));

		Cipher c = Cipher.getInstance(Constants.TDES_ECB_NO_PADDING_ALGORITHM);

		SecretKeySpec encKey = new SecretKeySpec(tdesKey, Constants.TDES_KEY_ALGORITHM);

		c.init(Cipher.ENCRYPT_MODE, encKey);

		byte[] output = c.doFinal(plainInput);

		return output;
	}

	/**
	 * @param cipherInput Input vector, must be a single block
	 * @param key         Encryption key, must be a DES single, double, or triple
	 *                    key
	 * @return Encrypted value with triple-DES, or null if the input is invalid
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptTDESBlock(byte[] cipherInput, byte[] key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (null == cipherInput || null == key || !SymmetricAlgorithms.isValidTDESKeyLength(key.length)
				|| cipherInput.length != Constants.DES_BLOCK_SIZE_B)
			return null;

		byte[] tdesKey = getFullLengthTDESKey(key);

		System.out.println("Input: " + TestIO.printByteArray(cipherInput));
		System.out.println("Full key: " + TestIO.printByteArray(tdesKey));

		Cipher c = Cipher.getInstance(Constants.TDES_ECB_NO_PADDING_ALGORITHM);

		SecretKeySpec encKey = new SecretKeySpec(tdesKey, Constants.TDES_KEY_ALGORITHM);

		c.init(Cipher.ENCRYPT_MODE, encKey);

		byte[] output = c.doFinal(cipherInput);

		return output;
	}

	/**
	 * Returns the AES-encrypted single block
	 * @param plainInput input data, must be a single block
	 * @param key input key, must have a valid AES key length
	 * @return Encrypted value or null if input params are invalid
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptAESBlock(byte[] plainInput, byte[] key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (null == plainInput || null == key || !isValidAESKeyLength(key.length)
				|| plainInput.length != Constants.AES_BLOCK_SIZE_B)
			return null;

		Cipher c = Cipher.getInstance(Constants.AES_ECB_NO_PADDING);

		SecretKeySpec encKey = new SecretKeySpec(key, Constants.AES_KEY_ALGORITHM);

		c.init(Cipher.ENCRYPT_MODE, encKey);

		byte[] output = c.doFinal(plainInput);

		return output;
	}
	
	/**
	 * Returns the AES-decrypted single block
	 * @param cipherInput input data, must be a single block
	 * @param key input key, must have a valid AES key length
	 * @return Decrypted value or null if input params are invalid
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptAESBlock(byte[] cipherInput, byte[] key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (null == cipherInput || null == key || !isValidAESKeyLength(key.length)
				|| cipherInput.length != Constants.AES_BLOCK_SIZE_B)
			return null;

		Cipher c = Cipher.getInstance(Constants.AES_ECB_NO_PADDING);

		SecretKeySpec encKey = new SecretKeySpec(key, Constants.AES_KEY_ALGORITHM);

		c.init(Cipher.ENCRYPT_MODE, encKey);

		byte[] output = c.doFinal(cipherInput);

		return output;
	}

	/**
	 * Creates a triple-length TDES key from a single, double, or triple-length
	 * input.
	 * 
	 * @param key Input key, can be single, double, or triple-length.
	 * @return triple-length value, or null if the input is invalid
	 */
	public static byte[] getFullLengthTDESKey(byte[] key) {
		if (null == key || !SymmetricAlgorithms.isValidTDESKeyLength(key.length))
			return null;

		byte[] tdesKey = new byte[Constants.DES_KEY_SIZE_3_B];

		/* copy the first part of the key */
		System.arraycopy(key, 0, tdesKey, 0, Constants.DES_KEY_SIZE_1_B);

		for (int i = 0; i < 2; i++) {
			int sourcePos = 0;
			if (key.length == Constants.DES_KEY_SIZE_3_B)
				sourcePos = (i + 1) * Constants.DES_KEY_SIZE_1_B;
			else
				sourcePos = ((i + 1) % 2) * Constants.DES_KEY_SIZE_1_B;

			System.arraycopy(key, sourcePos, tdesKey, (i + 1) * Constants.DES_KEY_SIZE_1_B, Constants.DES_KEY_SIZE_1_B);
		}
		return tdesKey;
	}

	/**
	 * Returns true if the input value is a valid Triple DES key length in bytes
	 * 
	 * @param keyLength Input length in bytes
	 * @return true if valid, false otherwise
	 */
	public static boolean isValidTDESKeyLength(int keyLength) {
		return (keyLength == Constants.DES_KEY_SIZE_1_B || keyLength == Constants.DES_KEY_SIZE_2_B
				|| keyLength == Constants.DES_KEY_SIZE_3_B);
	}

	/**
	 * Returns true if the input value is a valid AES key length in bytes
	 * 
	 * @param keyLength Input length in bytes
	 * @return true if valid, false otherwise
	 */
	public static boolean isValidAESKeyLength(int keyLength) {
		return (keyLength == Constants.AES_KEY_SIZE_1_B || keyLength == Constants.AES_KEY_SIZE_2_B
				|| keyLength == Constants.AES_KEY_SIZE_3_B);
	}

}
