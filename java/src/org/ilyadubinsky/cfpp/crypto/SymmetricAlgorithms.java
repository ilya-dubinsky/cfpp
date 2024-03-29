package org.ilyadubinsky.cfpp.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.ilyadubinsky.cfpp.utils.IO;

import lombok.NonNull;
import lombok.extern.java.Log;

@Log
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
	public static byte[] encryptDESBlock(@NonNull byte[] plainInput, @NonNull byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {

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
	public static byte[] decryptDESBlock(@NonNull byte[] cipherInput, @NonNull byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {

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
	public static byte[] encryptTDESBlock(@NonNull byte[] plainInput, @NonNull byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {

		byte[] tdesKey = getFullLengthTDESKey(key);

		log.finest("TDES input: " + IO.printByteArray(plainInput));
		log.finest("Full key: " + IO.printByteArray(tdesKey));

		Cipher c = Cipher.getInstance(Constants.TDES_ECB_NO_PADDING_ALGORITHM);

		SecretKeySpec encKey = new SecretKeySpec(tdesKey, Constants.TDES_KEY_ALGORITHM);

		c.init(Cipher.ENCRYPT_MODE, encKey);

		byte[] output = c.doFinal(plainInput);

		return output;
	}

	/**
	 * @param paddedInput Input vector, must be padded to the size of the DES input block.
	 * @param key Key to use for encryption.
	 * @param iv Initialization vector, all zeroes will be used if not provided
	 * @return Encrypted value.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException 
	 */
	public static byte[] encryptTDESData(@NonNull byte[] paddedInput, @NonNull byte[] key, byte [] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		
		byte[] tdesKey = getFullLengthTDESKey(key);
		
		if ( null == iv)
			iv = new byte[Constants.DES_BLOCK_SIZE_B];

		log.finest("TDES input: " + IO.printByteArray(paddedInput));
		log.finest("Full key: " + IO.printByteArray(tdesKey));

		Cipher c = Cipher.getInstance(Constants.TDES_CBC_NO_PADDING_ALGORITHM);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);

		SecretKeySpec encKey = new SecretKeySpec(tdesKey, Constants.TDES_KEY_ALGORITHM);
	

		c.init(Cipher.ENCRYPT_MODE, encKey, ivSpec);

		byte[] output = c.doFinal(paddedInput);

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
	public static byte[] decryptTDESBlock(@NonNull byte[] cipherInput, @NonNull byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {

		byte[] tdesKey = getFullLengthTDESKey(key);

		log.finest("TDES Input: " + IO.printByteArray(cipherInput));
		log.finest("Full key: " + IO.printByteArray(tdesKey));

		Cipher c = Cipher.getInstance(Constants.TDES_ECB_NO_PADDING_ALGORITHM);

		SecretKeySpec encKey = new SecretKeySpec(tdesKey, Constants.TDES_KEY_ALGORITHM);

		c.init(Cipher.ENCRYPT_MODE, encKey);

		byte[] output = c.doFinal(cipherInput);

		return output;
	}

	/**
	 * Returns the AES-encrypted single block
	 * 
	 * @param plainInput input data, must be a single block
	 * @param key        input key, must have a valid AES key length
	 * @return Encrypted value or null if input params are invalid
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptAESBlock(@NonNull byte[] plainInput, @NonNull byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {

		Cipher c = Cipher.getInstance(Constants.AES_ECB_NO_PADDING);

		SecretKeySpec encKey = new SecretKeySpec(key, Constants.AES_KEY_ALGORITHM);

		c.init(Cipher.ENCRYPT_MODE, encKey);

		byte[] output = c.doFinal(plainInput);

		return output;
	}

	/**
	 * Returns the AES-decrypted single block
	 * 
	 * @param cipherInput input data, must be a single block
	 * @param key         input key, must have a valid AES key length
	 * @return Decrypted value or null if input params are invalid
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptAESBlock(@NonNull byte[] cipherInput, @NonNull byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {
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
	public static byte[] getFullLengthTDESKey(@NonNull byte[] key) {
		if (!SymmetricAlgorithms.isValidTDESKeyLength(key.length))
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
