package org.ilyadubinsky.cfpp.crypto;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.ilyadubinsky.cfpp.utils.BitOps;
import org.ilyadubinsky.cfpp.utils.IO;

import lombok.extern.java.Log;

@Log
public class MessageAuthenticationAlgorithms {

	/**
	 * Computes the DSA signature of the input value
	 * 
	 * @param image the input value
	 * @param x     X parameter of the algorithm (the private key)
	 * @param p     P parameter of the algorithm (domain parameter, first prime)
	 * @param q     Q parameter of the algorithm (domain parameter, second prime)
	 * @param g     G parameter of the algorithm (domain parameter, generator)
	 * @return Signature, or null if inputs are invalid
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public static byte[] signDSA(byte[] image, BigInteger x, BigInteger p, BigInteger q, BigInteger g)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		if (null == image)
			return null;

		/*
		 * Create a private key spec from the domain parameters p,g,q, and the private
		 * key x
		 */
		DSAPrivateKeySpec dsaPrivKeySpec = new DSAPrivateKeySpec(x, p, q, g);

		/* "Generate" the key - this will only copy the values above */
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.DSA_KEY_ALGORITHM);
		PrivateKey privKey = keyFactory.generatePrivate(dsaPrivKeySpec);

		/*
		 * instantiate the algorithm. NOTE: SHA1 will only work with small numbers, so
		 * we'll use SHA256 here
		 */
		Signature s = Signature.getInstance(Constants.DSA_SHA256_ALGORITHM);

		/*
		 * this is a very, very DANGEROUS workaround for the k collision issue that's
		 * not handled in the Java JDK
		 */
		if (p.bitLength() < 500) {/* However, you shouldn't be using keys this small anyway */
			log.severe("**** DANGER **** DSA signature is calculated with a very short key and without randomization");
			s.initSign(privKey, new Utils.DisableRandom());
		} else {
			s.initSign(privKey);
		}

		/* sign the image */
		s.update(image);

		byte[] output = s.sign();

		return output;
	}

	/**
	 * Validates the DSA signature of the input value
	 * 
	 * @param image     the input value
	 * @param signature the signature to validate
	 * @param y         Y parameter of the algorithm (the public key)
	 * @param p         P parameter of the algorithm (domain parameter, first prime)
	 * @param q         Q parameter of the algorithm (domain parameter, second
	 *                  prime)
	 * @param g         G parameter of the algorithm (domain parameter, generator)
	 * @return true if valid, false otherwise
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 */
	public static boolean verifyDSA(byte[] image, byte[] signature, BigInteger y, BigInteger p, BigInteger q,
			BigInteger g)
			throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {

		if (null == image || null == signature)
			return false;

		/*
		 * Create a public key spec from the domain parameters p,g,q, and the public key
		 * y
		 */
		DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(y, p, q, g);

		/* "Generate" the key - this will only copy the values above */
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.DSA_KEY_ALGORITHM);
		PublicKey pubKey = keyFactory.generatePublic(dsaPubKeySpec);

		/*
		 * instantiate the algorithm. NOTE: SHA1 will only work with small numbers, so
		 * we'll use SHA256 here
		 */
		Signature s = Signature.getInstance(Constants.DSA_SHA256_ALGORITHM);

		s.initVerify(pubKey);

		s.update(image);

		return s.verify(signature);

	}

	/**
	 * Computes the HMAC value
	 * 
	 * @param image The image to sign
	 * @param key   The secret key
	 * @return Byte value of the HMAC, or null if the inputs are wrong
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] computeHMAC(byte[] image, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		if (null == image || null == key)
			return null;

		/* wrap the key */
		SecretKeySpec hmacKeySpec = new SecretKeySpec(key, Constants.HMAC_SHA1);

		/* instantiate the algorithm */
		Mac mac = Mac.getInstance(Constants.HMAC_SHA1);

		mac.init(hmacKeySpec);

		mac.update(image);

		return mac.doFinal();
	}

	public static int[] AES_F_2_8_POLY = { 0x87 };

	public static byte[] computeAESCMAC(byte[] image, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		if (null == image || null == key || !SymmetricAlgorithms.isValidAESKeyLength(key.length))
			return null;

		/* first, we derive the keys, k1 and k2 */
		byte[] zeroBlock = new byte[Constants.AES_BLOCK_SIZE_B];

		byte[] k0 = SymmetricAlgorithms.encryptAESBlock(zeroBlock, key);

		/* k1 is k0 times x modulo the generating polynomial of GF(2^8), 0x1B */
		byte[] irredPoly = BitOps.toByteArray(AES_F_2_8_POLY);
		
		log.finest("K0 (L): " + IO.printByteArray(k0));

		byte[] k1 = BitOps.mulByX(k0, irredPoly);
		/* k2 is k1 times x modulo the generating polynomial of GF(2^8), 0x1B */
		byte[] k2 = BitOps.mulByX(k1, irredPoly);

		/* start padding the data */
		/* calculate the target length */
		int targetLen = (image.length - (image.length % Constants.AES_BLOCK_SIZE_B))
				+ (Integer.signum(image.length % Constants.AES_BLOCK_SIZE_B) * Constants.AES_BLOCK_SIZE_B);
		
		/* handle empty input block */
		if (targetLen == 0) targetLen = Constants.AES_BLOCK_SIZE_B;

		byte[] encryptionInput = new byte[targetLen];

		System.arraycopy(image, 0, encryptionInput, 0, image.length);
		
		/* k will be used to encrypt the value, default is k1 */
		byte[] k = k1;
		
		if (image.length != targetLen) {
			/* pad the value and use k2 for encryption */
			encryptionInput[image.length] = (byte) 0x80;
			k = k2;
		}
		log.finest("K1    : " + IO.printByteArray(k1));
		log.finest("K2    : " + IO.printByteArray(k2));

		/* no need to pad, using k1 to xor the last chunk */
		byte[] xoredChunk = BitOps.xorArray(
				Arrays.copyOfRange(encryptionInput, targetLen - Constants.AES_BLOCK_SIZE_B , targetLen ), k);


		System.arraycopy(xoredChunk, 0,
				encryptionInput, targetLen - Constants.AES_BLOCK_SIZE_B , Constants.AES_BLOCK_SIZE_B);

		log.finest("inBlock: " + IO.printByteArray(encryptionInput));
		
		Cipher c = Cipher.getInstance(Constants.AES_CBC_NO_PADDING);

		SecretKeySpec encKey = new SecretKeySpec(key, Constants.AES_KEY_ALGORITHM);
		IvParameterSpec ivParams = new IvParameterSpec(zeroBlock);
		
		c.init(Cipher.ENCRYPT_MODE, encKey, ivParams);

		byte[] fullCiphertext = c.doFinal(encryptionInput);
		
		log.finest("Tag: " + IO.printByteArray(fullCiphertext));

		return Arrays.copyOfRange(fullCiphertext, fullCiphertext.length-Constants.AES_BLOCK_SIZE_B, fullCiphertext.length);
	}
}
