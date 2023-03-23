package org.ilyadubinsky.cfpp.emv;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.ilyadubinsky.cfpp.crypto.Constants;
import org.ilyadubinsky.cfpp.crypto.MessageAuthenticationAlgorithms;
import org.ilyadubinsky.cfpp.crypto.SymmetricAlgorithms;
import org.ilyadubinsky.cfpp.utils.BitOps;
import org.ilyadubinsky.cfpp.utils.IO;

import lombok.extern.java.Log;

@Log
public class ApplicationCryptogram {

	public static final int EMV_OPTION_A_MAX_PAN_LEN = 16;

	public static byte[] deriveICCMasterKey(byte[] unpackedPAN, byte[] csn, String keyAlgorithm, byte[] issuerMasterKey)
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		if (Constants.AES_KEY_ALGORITHM != keyAlgorithm && Constants.DES_KEY_ALGORITHM != keyAlgorithm)
			throw new NoSuchAlgorithmException("Unknown algorithm: " + keyAlgorithm);

		if (null == unpackedPAN)
			throw new IllegalArgumentException("PAN cannot be null");

		if (null == csn || csn.length != 2)
			throw new IllegalArgumentException("Invalid csn: " + IO.printByteArray(csn));

		byte[] unpackedSeedString = new byte[unpackedPAN.length + 2];
		System.arraycopy(unpackedPAN, 0, unpackedSeedString, 0, unpackedPAN.length);
		System.arraycopy(csn, 0, unpackedSeedString, unpackedPAN.length, 2);

		byte[] inputVector, packedSeed;

		log.finest("PAN string: " + IO.printByteArray(unpackedSeedString));

		if (Constants.AES_KEY_ALGORITHM == keyAlgorithm) {
			/*
			 * Option C: AES The PAN is concatenated with the CSN, then left-padded with
			 * zeroes to the length of 16 bytes or 32 digits.
			 */
			inputVector = BitOps.packBCD(unpackedSeedString, Constants.AES_BLOCK_SIZE_B, true);
			/* encipher, always return 256 bits */
			byte [] firstHalf = SymmetricAlgorithms.encryptAESBlock(inputVector, issuerMasterKey);
			byte [] secondHalf = SymmetricAlgorithms.encryptAESBlock(BitOps.xorArray(inputVector, (byte) 0xFF), issuerMasterKey);
			
			return BitOps.concatenate(firstHalf, secondHalf);	

		} else {
			packedSeed = BitOps.packBCD(unpackedSeedString, (unpackedSeedString.length >> 1) + (unpackedSeedString.length % 2), true);
			log.finest("Packed seed: " + IO.printByteArray(packedSeed));
			/* copy the packed seed rightmost digits to the input vector */
			
			/* if the PAN length is <= 16, Option A */
			if (unpackedPAN.length <= 16) {
				/* Option A */
				log.finest("Option A");

				inputVector = new byte[Constants.DES_BLOCK_SIZE_B];
				
				System.arraycopy(
						packedSeed, 
						Integer.max(0, packedSeed.length - Constants.DES_BLOCK_SIZE_B), 
						inputVector,
						Integer.max(0, Constants.DES_BLOCK_SIZE_B - packedSeed.length),
						Integer.min(Constants.DES_BLOCK_SIZE_B, packedSeed.length));				
			} else {
				/* Option B */
				log.finest("Option B");
				
				log.finest("Hash input " + IO.printByteArray(packedSeed));
				byte [] hashedSeed = MessageAuthenticationAlgorithms.computeSHA1(packedSeed);
				log.finest("Hash result " + IO.printByteArray(hashedSeed));
				inputVector = BitOps.packBCD(BitOps.decimalizeVector(hashedSeed, Constants.DES_BLOCK_SIZE_B*2), Constants.DES_BLOCK_SIZE_B, false);
			}
			log.finest("Input vector: " + IO.printByteArray(inputVector));
			
			/* encrypt */
			byte [] firstHalf = SymmetricAlgorithms.encryptTDESBlock(inputVector, issuerMasterKey);

			/* invert the input vector */
			byte [] secondHalf = SymmetricAlgorithms.encryptTDESBlock(BitOps.xorArray(inputVector, (byte) 0xFF), issuerMasterKey);
			
			/* concatenate */			
			return BitOps.fixParity(BitOps.concatenate(firstHalf, secondHalf), false);
		}

	}
}
