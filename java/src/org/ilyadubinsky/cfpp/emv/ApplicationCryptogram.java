package org.ilyadubinsky.cfpp.emv;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.ilyadubinsky.cfpp.crypto.Constants;
import org.ilyadubinsky.cfpp.crypto.MessageAuthenticationAlgorithms;
import org.ilyadubinsky.cfpp.crypto.SymmetricAlgorithms;
import org.ilyadubinsky.cfpp.utils.BitOps;
import org.ilyadubinsky.cfpp.utils.IO;

import lombok.NonNull;
import lombok.extern.java.Log;

/**
 * The class encapsulates methods to produce various application cryptograms.
 * Since producing a cryptogram requires computing an ICC master key and an ICC
 * session key, methods to do so are also provided here.
 * 
 * @author idubinsky
 */
@Log
public class ApplicationCryptogram {

	public static final int EMV_OPTION_A_MAX_PAN_LEN = 16;

	/**
	 * The method derives the ICC master key. For AES keys, it always generates a
	 * 256-bit key. If a shorter key is required, the return value should be
	 * truncated accordingly.
	 * 
	 * @param unpackedPAN     The PAN of the card, unpacked (i.e. byte per digit).
	 * @param unpackedCSN     The card sequence number (CSN), unpacked.
	 * @param keyAlgorithm    The key algorithm. Values other than "DES" and "AES"
	 *                        will cause an exception.
	 * @param issuerMasterKey The issuer master key. Must be valid for the algorithm
	 *                        in use.
	 * @return The derived ICC master key. For AES, 256 bits are returned always.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] deriveICCMasterKey(@NonNull byte[] unpackedPAN, byte[] unpackedCSN, String keyAlgorithm,
			byte[] issuerMasterKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {

		if (Constants.AES_KEY_ALGORITHM != keyAlgorithm && Constants.DES_KEY_ALGORITHM != keyAlgorithm)
			throw new NoSuchAlgorithmException("Unknown algorithm: " + keyAlgorithm);

		if (null == unpackedCSN || unpackedCSN.length != 2)
			throw new IllegalArgumentException("Invalid csn: " + IO.printByteArray(unpackedCSN));

		byte[] unpackedSeedString = new byte[unpackedPAN.length + 2];
		System.arraycopy(unpackedPAN, 0, unpackedSeedString, 0, unpackedPAN.length);
		System.arraycopy(unpackedCSN, 0, unpackedSeedString, unpackedPAN.length, 2);

		byte[] inputVector, packedSeed;

		log.finest("PAN string: " + IO.printByteArray(unpackedSeedString));

		if (Constants.AES_KEY_ALGORITHM == keyAlgorithm) {
			/*
			 * Option C: AES The PAN is concatenated with the CSN, then left-padded with
			 * zeroes to the length of 16 bytes or 32 digits.
			 */
			inputVector = BitOps.packBCD(unpackedSeedString, Constants.AES_BLOCK_SIZE_B, true);
			/* encipher, always return 256 bits */
			byte[] firstHalf = SymmetricAlgorithms.encryptAESBlock(inputVector, issuerMasterKey);
			byte[] secondHalf = SymmetricAlgorithms.encryptAESBlock(BitOps.xorArray(inputVector, (byte) 0xFF),
					issuerMasterKey);

			return BitOps.concatenate(firstHalf, secondHalf);

		} else {
			packedSeed = BitOps.packBCD(unpackedSeedString,
					(unpackedSeedString.length >> 1) + (unpackedSeedString.length % 2), true);
			log.finest("Packed seed: " + IO.printByteArray(packedSeed));
			/* copy the packed seed rightmost digits to the input vector */

			/* if the PAN length is <= 16, Option A */
			if (unpackedPAN.length <= 16) {
				/* Option A */
				log.finest("Option A");

				inputVector = new byte[Constants.DES_BLOCK_SIZE_B];

				System.arraycopy(packedSeed, Integer.max(0, packedSeed.length - Constants.DES_BLOCK_SIZE_B),
						inputVector, Integer.max(0, Constants.DES_BLOCK_SIZE_B - packedSeed.length),
						Integer.min(Constants.DES_BLOCK_SIZE_B, packedSeed.length));
			} else {
				/* Option B */
				log.finest("Option B");

				log.finest("Hash input " + IO.printByteArray(packedSeed));
				byte[] hashedSeed = MessageAuthenticationAlgorithms.computeSHA1(packedSeed);
				log.finest("Hash result " + IO.printByteArray(hashedSeed));
				inputVector = BitOps.packBCD(BitOps.decimalizeVector(hashedSeed, Constants.DES_BLOCK_SIZE_B * 2),
						Constants.DES_BLOCK_SIZE_B, false);
			}
			log.finest("Input vector: " + IO.printByteArray(inputVector));

			/* encrypt */
			byte[] firstHalf = SymmetricAlgorithms.encryptTDESBlock(inputVector, issuerMasterKey);

			/* invert the input vector */
			byte[] secondHalf = SymmetricAlgorithms.encryptTDESBlock(BitOps.xorArray(inputVector, (byte) 0xFF),
					issuerMasterKey);

			/* concatenate */
			return BitOps.fixParity(BitOps.concatenate(firstHalf, secondHalf), false);
		}
	}

	/**
	 * Derives the ICC session key, based on the ICC master key and the transaction
	 * counter.
	 * 
	 * @param iccMasterKey The ICC master key
	 * @param atc          The ATC, two bytes, unpacked
	 * @param keyAlgorithm The key algorithm. Values other than "DES" and "AES" will
	 *                     trigger an exception
	 * @param outputLength The desired output length.
	 * @return The derived key of the desired output length.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] deriveICCSessionKey(@NonNull byte[] iccMasterKey, @NonNull byte[] atc, String keyAlgorithm,
			int outputLength) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {

		if (Constants.AES_KEY_ALGORITHM != keyAlgorithm && Constants.DES_KEY_ALGORITHM != keyAlgorithm)
			throw new NoSuchAlgorithmException("Unknown algorithm: " + keyAlgorithm);

		if ((Constants.AES_KEY_ALGORITHM == keyAlgorithm && !SymmetricAlgorithms.isValidAESKeyLength(outputLength))
				|| (Constants.DES_KEY_ALGORITHM == keyAlgorithm && !(Constants.DES_KEY_SIZE_2_B == outputLength)))
			throw new IllegalArgumentException(
					String.format("%d is not a valid key length for %s", outputLength, keyAlgorithm));

		int iterations = 2;
		byte[] magicNumber = { (byte) 0xF0, (byte) 0x0F };

		if (Constants.AES_KEY_SIZE_1_B == outputLength && Constants.AES_KEY_ALGORITHM == keyAlgorithm) {
			magicNumber[0] = 0;
			iterations = 1;
		}
		byte[] output = new byte[outputLength];
		int blockSize = (Constants.AES_KEY_ALGORITHM == keyAlgorithm) ? Constants.AES_BLOCK_SIZE_B
				: Constants.DES_BLOCK_SIZE_B;

		byte[] inputData = new byte[blockSize];

		System.arraycopy(atc, 0, inputData, 0, 2);

		for (int i = 0; i < iterations; i++) {
			inputData[2] = magicNumber[i];
			log.finest("Diversification value: " + IO.printByteArray(inputData));

			byte[] keyPart = Constants.AES_KEY_ALGORITHM == keyAlgorithm
					? SymmetricAlgorithms.encryptAESBlock(inputData, iccMasterKey)
					: SymmetricAlgorithms.encryptTDESBlock(inputData, iccMasterKey);
			log.finest("Key part: " + IO.printByteArray(keyPart));

			System.arraycopy(keyPart, 0, output, i * blockSize, blockSize);
		}

		
		if (Constants.DES_KEY_ALGORITHM == keyAlgorithm)
			output = BitOps.fixParity(output, false);
		
		log.finest("ICC session key: " + IO.printByteArray(output));

		return output;
	}

	/**
	 * Generates the ARQC based on the given session key.
	 * @param data Data to use for ARQC generation.
	 * @param iccSessionKey Session key, derived according to the EMV spec.
	 * @param keyAlgorithm Algorithm to use, can be either "AES" or "DES".
	 * @return ARQC value (CMAC in case of AES, or last block of a CBC chain in case of TDES).
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] generateARQC(@NonNull byte[] data, @NonNull byte[] iccSessionKey, @NonNull String keyAlgorithm)
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {

		
		/* padding is part of AES CMAC computation */
		if (Constants.AES_KEY_ALGORITHM == keyAlgorithm)
			return MessageAuthenticationAlgorithms.computeAESCMAC(data, iccSessionKey);
		
		if (Constants.DES_KEY_ALGORITHM != keyAlgorithm)
			throw new NoSuchAlgorithmException("Unknown algorithm: " + keyAlgorithm);

		/* calculate the data input size */
		int paddedDataSize = data.length + 1;
		/* decide how much extra padding is required */
		if ((paddedDataSize % Constants.DES_BLOCK_SIZE_B) != 0)
			paddedDataSize += (Constants.DES_BLOCK_SIZE_B - (paddedDataSize % Constants.DES_BLOCK_SIZE_B));

		byte[] inputVector = new byte[paddedDataSize];
		System.arraycopy(data, 0, inputVector, 0, data.length);
		inputVector[data.length] = (byte) 0x80;

		log.finest("ARQC input: " + IO.printByteArray(inputVector));
		
		byte [] fullCiphertext = SymmetricAlgorithms.encryptTDESData(inputVector, iccSessionKey, null);

		return Arrays.copyOfRange(fullCiphertext, fullCiphertext.length-Constants.DES_BLOCK_SIZE_B, fullCiphertext.length);
	}

}
