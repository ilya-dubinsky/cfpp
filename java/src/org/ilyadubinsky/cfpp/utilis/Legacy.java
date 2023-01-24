package org.ilyadubinsky.cfpp.utilis;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import lombok.extern.java.Log;

@Log

public class Legacy {

	/**
	 * Computes the CVV value
	 * 
	 * @param unpackedPAN   PAN as an unpacked array (byte per digit)
	 * @param expiry        Expiry date as a 4-byte unpacked array
	 * @param serviceCode   Service code as a 3-byte unpacked array
	 * @param cvkA          CVK A DES key, as an 8-byte byte array
	 * @param cvkB          CVK A DES key, as an 8-byte byte array
	 * @param desiredLength Desired number of digits
	 * @return byte array of desired length, unpacked, consisting of CVV digits
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] computeCVV(byte[] unpackedPAN, byte[] expiry, byte[] serviceCode, byte[] cvkA, byte[] cvkB,
			int desiredLength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		/* validate inputs */
		if (unpackedPAN == null || expiry == null || serviceCode == null || cvkA == null || cvkB == null
				|| unpackedPAN.length == 0 || expiry.length == 0 || serviceCode.length == 0 || cvkA.length == 0
				|| cvkB.length == 0 || desiredLength == 0)
			return null;

		byte[] block1 = BitOps.packBCD(unpackedPAN, 8, true);
		byte[] block1Output = new byte[8];

		log.log(Level.FINE, "Input block 1: " + TestIO.printByteArray(block1));

		byte[] block2Input = new byte[7];
		System.arraycopy(expiry, 0, block2Input, 0, 4);
		System.arraycopy(serviceCode, 0, block2Input, 4, 3);
		byte[] block2 = BitOps.packBCD(block2Input, 8, false);

		Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
		SecretKeySpec keyCVKA = new SecretKeySpec(cvkA, "DES");

		byte[] cvkFull = new byte[24];
		System.arraycopy(cvkA, 0, cvkFull, 0, 8);
		System.arraycopy(cvkB, 0, cvkFull, 8, 8);
		System.arraycopy(cvkA, 0, cvkFull, 16, 8);

		SecretKeySpec keyCVKB = new SecretKeySpec(cvkFull, "DESede");

		c.init(Cipher.ENCRYPT_MODE, keyCVKA);
		c.doFinal(block1, 0, 8, block1Output);

		log.log(Level.FINE, "Output step 1: " + TestIO.printByteArray(block1Output));

		log.log(Level.FINE, "Input block 2: " + TestIO.printByteArray(block2));

		/* xor */
		block2 = BitOps.xorArray(block2, block1Output);
		log.log(Level.FINE, "After XOR: " + TestIO.printByteArray(block2));
		/* encrypt block 2 in EDE mode */
		c = Cipher.getInstance("DESede/ECB/NoPadding");

		byte[] block2Output = new byte[8];
		c.init(Cipher.ENCRYPT_MODE, keyCVKB);
		c.doFinal(block2, 0, 8, block2Output);
		log.log(Level.FINE, "After 2nd encryption: " + TestIO.printByteArray(block2Output));

		return BitOps.decimalizeVector(block2Output, desiredLength);
	}

	/**
	 * Computes the PVV
	 * 
	 * @param pan the PAN, unpacked BCD. The last digit is assumed to be the check digit
	 * @param unpackedPAN the PAN, unpacked BCD. The last digit is assumed to be the check digit.
	 * @param unpackedPIN unpacked BCD of the PIN, min 4 digits, only they are going to be used
	 * @param pvki single digit PVKI
	 * @param pvkA PVK A key
	 * @param pvkB PVK B key
	 * @param desiredLength Desired length of the output
	 * @return unpacked BCD value of the PVV
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] computePVV(byte[] unpackedPAN, byte[] unpackedPIN, byte pvki, byte[] pvkA, byte[] pvkB,
			int desiredLength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		if (unpackedPAN == null || unpackedPIN == null || pvkA == null || pvkB == null || unpackedPAN.length == 0
				|| unpackedPIN.length == 0 || pvkA.length == 0 || pvkB.length == 0)
			return null;
		byte[] unpackedInput = new byte[16];

		System.arraycopy(unpackedPAN, unpackedPAN.length - 12, unpackedInput, 0, 11);
		unpackedInput[11] = pvki;

		System.arraycopy(unpackedPIN, 0, unpackedInput, 12, 4);
		byte[] packedInput = BitOps.packBCD(unpackedInput, 8, false);

		log.log(Level.FINE, "Packed input for PVV: " + TestIO.printByteArray(packedInput));

		byte[] pvk = new byte[24];
		System.arraycopy(pvkA, 0, pvk, 0, 8);
		System.arraycopy(pvkB, 0, pvk, 8, 8);
		System.arraycopy(pvkA, 0, pvk, 16, 8);

		Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
		SecretKeySpec pvkKey = new SecretKeySpec(pvk, "DESede");

		c.init(Cipher.ENCRYPT_MODE, pvkKey);
		byte[] encOutput = new byte[8];
		c.doFinal(packedInput, 0, 8, encOutput);

		log.log(Level.FINE, "PVV after encryption: " + TestIO.printByteArray(encOutput));

		return BitOps.decimalizeVector(encOutput, desiredLength);

	}
}
