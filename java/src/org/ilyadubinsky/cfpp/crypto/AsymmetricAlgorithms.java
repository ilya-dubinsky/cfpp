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

	public static byte[] encryptRSA(byte[] data, BigInteger n, BigInteger e)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		// TODO: input validation
		
		/* wrap the key */
		RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);

		KeyFactory kf = KeyFactory.getInstance(Constants.RSA_ALGORITHM);
		PublicKey rsaPublicKey = kf.generatePublic(rsaPublicKeySpec);
		
		/* instantiate and initialize the cipher */
		Cipher c = Cipher.getInstance(Constants.RSA_ALGORITHM);
		c.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
		
		/* do the encryption */
		return c.doFinal(data);

	}

	public static byte[] decryptRSA(byte[] data, BigInteger n, BigInteger e, BigInteger d) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// TODO: input validation

		/* wrap the key */
		RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(n, d);
		
		KeyFactory kf = KeyFactory.getInstance(Constants.RSA_ALGORITHM);
		PrivateKey rsaPrivateKey = kf.generatePrivate(rsaPrivateKeySpec);
		
		/* instantiate and initialized the cipher */
		Cipher c = Cipher.getInstance(Constants.RSA_ALGORITHM);
		c.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
		
		/* do the decryption */
		return c.doFinal(data);
	}
}
