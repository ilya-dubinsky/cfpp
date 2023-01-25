package org.ilyadubinsky.cfpp.crypto;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricAlgorithms {

	/**
	 * Encrypts the data with the RSA algorithm w/o padding
	 * 
	 * @param data data to encrypt
	 * @param n    modulus
	 * @param e    public exponent
	 * @return encrypted data
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptRSA(byte[] data, BigInteger n, BigInteger e)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		// TODO: input validation
		return doEncryptRSA(data, n, e, Constants.RSA_ECB_NO_PADDING);

	}

	/**
	 * Encrypts the data using RSA with OAEP padding. SHA-256 and MFG1 are used.
	 * 
	 * @param data data to encrypt
	 * @param n    modulus
	 * @param e    public exponent
	 * @return encrypted data
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptRSA_OAEP(byte[] data, BigInteger n, BigInteger e)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		// TODO: input validation
		return doEncryptRSA(data, n, e, Constants.RSA_ECB_OAEP);
	}

	/**
	 * Performs the actual RSA encryption with the specified algorithm flavor
	 * 
	 * @param data          Input data
	 * @param n             modulus
	 * @param e             public exponent
	 * @param algorithmName algorithm name
	 * @return encrypted data
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static byte[] doEncryptRSA(byte[] data, BigInteger n, BigInteger e, String algorithmName)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		/* wrap the key */
		RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);

		KeyFactory kf = KeyFactory.getInstance(Constants.RSA_KEY_ALGORITHM);
		PublicKey rsaPublicKey = kf.generatePublic(rsaPublicKeySpec);

		/* instantiate and initialize the cipher */
		Cipher c = Cipher.getInstance(algorithmName);
		c.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

		/* do the encryption */
		return c.doFinal(data);
	}

	/**
	 * Decrypts the data using plain RSA
	 * 
	 * @param data data to decrypt
	 * @param n    modulus
	 * @param d    private exponent
	 * @return Decrypted data
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptRSA(byte[] data, BigInteger n, BigInteger d)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// TODO: input validation

		return doDecryptRSA(data, n, d, Constants.RSA_ECB_NO_PADDING);
	}

	/**
	 * Decrypts the data using RSA with OAEP padding
	 * 
	 * @param data data to decrypt
	 * @param n    modulus
	 * @param d    private exponent
	 * @return Decrypted data
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptRSA_OAEP(byte[] data, BigInteger n, BigInteger d)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// TODO: input validation

		return doDecryptRSA(data, n, d, Constants.RSA_ECB_OAEP);
	}
	
	/**
	 * Performs RSA decryption using the specified algorithm flavor
	 * 
	 * @param data    data to decrypt
	 * @param n       modulus
	 * @param d       private exponent
	 * @param algname name of the algorithm
	 * @return decrypted data
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	protected static byte[] doDecryptRSA(byte[] data, BigInteger n, BigInteger d, String algname)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		/* wrap the key */
		RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(n, d);

		KeyFactory kf = KeyFactory.getInstance(Constants.RSA_KEY_ALGORITHM);
		PrivateKey rsaPrivateKey = kf.generatePrivate(rsaPrivateKeySpec);

		/* instantiate and initialized the cipher */
		Cipher c = Cipher.getInstance(algname);
		c.init(Cipher.DECRYPT_MODE, rsaPrivateKey);

		/* do the decryption */
		return c.doFinal(data);
	}
}
