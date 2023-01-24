package org.ilyadubinsky.cfpp.crypto;

import java.math.BigInteger;
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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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

		/* Create a private key spec from the domain parameters p,g,q, and the private key x */
		DSAPrivateKeySpec dsaPrivKeySpec = new DSAPrivateKeySpec(x, p, q, g);

		/* "Generate" the key - this will only copy the values above */
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.DSA_KEY_ALGORITHM);
		PrivateKey privKey = keyFactory.generatePrivate(dsaPrivKeySpec);
		
		/* instantiate the algorithm. NOTE: SHA1 will only work with small numbers, so we'll use SHA256 here */
		Signature s = Signature.getInstance(Constants.DSA_SHA256_ALGORITHM);
		
		/* this is a very, very DANGEROUS workaround for the k collision issue that's not handled in the Java JDK */
		if (p.bitLength()<500) {/* However, you shouldn't be using keys this small anyway */
			log.severe("**** DANGER **** DSA signature is calculated with a very short key and without randomization");
			s.initSign(privKey, new Utils.DisableRandom());
		}
		else {
			s.initSign(privKey);
		}
		
		/* sign the image */
		s.update(image);

		byte[] output = s.sign();

		return output;
	}

	/**
	 * Validates the DSA signature of the input value
	 * @param image the input value
	 * @param signature the signature to validate
	 * @param y Y parameter of the algorithm (the public key)
	 * @param p P parameter of the algorithm (domain parameter, first prime)
	 * @param q Q parameter of the algorithm (domain parameter, second prime)
	 * @param g G parameter of the algorithm (domain parameter, generator)
	 * @return true if valid, false otherwise
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 */
	public static boolean verifyDSA(byte[] image, byte[] signature, BigInteger y, BigInteger p, BigInteger q, BigInteger g)
			throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {

		if (null == image || null == signature)
			return false;

		/* Create a public key spec from the domain parameters p,g,q, and the public key y */
		DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(y, p, q, g);
		
		/* "Generate" the key - this will only copy the values above */
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.DSA_KEY_ALGORITHM);
		PublicKey pubKey = keyFactory.generatePublic(dsaPubKeySpec);

		/* instantiate the algorithm. NOTE: SHA1 will only work with small numbers, so we'll use SHA256 here */
		Signature s = Signature.getInstance(Constants.DSA_SHA256_ALGORITHM);
		
		s.initVerify(pubKey);
		
		s.update(image);
		
		return s.verify(signature);
		
	}
	
	/**
	 * Computes the HMAC value 
	 * @param image The image to sign
	 * @param key The secret key 
	 * @return Byte value of the HMAC, or null if the inputs are wrong
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] computeHMAC( byte [] image, byte[] key ) throws NoSuchAlgorithmException, InvalidKeyException {
		if (null == image || null == key )
			return null;
		
		/* wrap the key */
		SecretKeySpec hmacKeySpec = new SecretKeySpec(key, Constants.HMAC_SHA1);

		/* instantiate the algorithm */
		Mac mac = Mac.getInstance(Constants.HMAC_SHA1);
		
		mac.init(hmacKeySpec);
		
		mac.update(image);
		
		return mac.doFinal();
	}
}
