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
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import lombok.NonNull;

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
	public static byte[] encryptRSA(@NonNull byte[] data, @NonNull BigInteger n, @NonNull BigInteger e)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
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
	public static byte[] encryptRSA_OAEP(@NonNull byte[] data, @NonNull BigInteger n, @NonNull BigInteger e)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
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
	public static byte[] decryptRSA(@NonNull byte[] data, BigInteger n, BigInteger d)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		/* work around an issue when the n is converted from a byte array without the leading zero */
		if (n.compareTo(BigInteger.ZERO) <0 ) {
			byte [] number = n.toByteArray();
			byte [] fixedInt = new byte[number.length+1];
			System.arraycopy(number, 0, fixedInt, 1, number.length);
			n = new BigInteger(fixedInt);
		}
		
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
	public static byte[] decryptRSA_OAEP(@NonNull byte[] data, @NonNull BigInteger n, @NonNull BigInteger d)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
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

	/**
	 * Generates a secret value using Diffie-Hellman algorithm.
	 * @param p P, a prime (domain parameter)
	 * @param g G, the generator (domain parameter)
	 * @param ourX - our private key, the exponent (a). 
	 * @param theirY - their public key, g^b, where b is their private exponent
	 * @return generated secret value
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 */
	public static byte[] generateDHKey(@NonNull BigInteger p, @NonNull BigInteger g, @NonNull BigInteger ourX, @NonNull BigInteger theirY)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalStateException {
		/* prepare the key specs */
		DHPrivateKeySpec ourKeySpec = new DHPrivateKeySpec(ourX, p, g);
		DHPublicKeySpec theirKeySpec = new DHPublicKeySpec(theirY, p, g);

		/* instantiate the keys */
		KeyFactory kf = KeyFactory.getInstance(Constants.DIFFIE_HELLMAN_KEY_ALGORITHM);
		PrivateKey ourKey = kf.generatePrivate(ourKeySpec);
		PublicKey theirKey = kf.generatePublic(theirKeySpec);
		
		/* Instantiate the key agreement implementation */
		KeyAgreement kag = KeyAgreement.getInstance(Constants.DIFFIE_HELLMAN);
		
		/* We init it with our (private) key */
		kag.init(ourKey);
		/* We do phase with their (public) key */
		kag.doPhase(theirKey, true);

		/* aaand we return the generated secret */
		return kag.generateSecret();
	}
}
