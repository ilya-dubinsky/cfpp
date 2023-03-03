package org.ilyadubinsky.cfpp.payments;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.ilyadubinsky.cfpp.crypto.Constants;
import org.ilyadubinsky.cfpp.crypto.MessageAuthenticationAlgorithms;
import org.ilyadubinsky.cfpp.utils.BitOps;
import org.ilyadubinsky.cfpp.utils.IO;

import lombok.NonNull;
import lombok.extern.java.Log;

@Log
public class TR31 {

	public enum TR31Algorithm {

		TDES_2(0x0000, Constants.DES_KEY_SIZE_2_B * 8, "TDES Double-length"),
		TDES_3(0x0001, Constants.DES_KEY_SIZE_3_B * 8, "TDES Triple-length"),
		AES_128(0x0002, Constants.AES_KEY_SIZE_1_B * 8, "AES 128 bit"),
		AES_192(0x0003, Constants.AES_KEY_SIZE_2_B * 8, "AES 192 bit"),
		AES_256(0x0004, Constants.AES_KEY_SIZE_3_B * 8, "AES 256 bit");

		TR31Algorithm(int value, int keyLenBits, String name) {
			this.value = value;
			this.keyLenBits = keyLenBits;
			this.keyLen = keyLenBits >> 3;
			this.name = name;
		}

		public final String name; /* readable algorithm name */
		public final int value; /* TR31 value representing the algorithm */
		public final int keyLenBits; /* key length of the algorithm in bits */
		public final int keyLen; /* syntatic sugar - key length in bytes */
	}

	public enum TR31Usage {

		ENC(0x0000, (byte) 'E', "Encryption"), MAC(0x0001, (byte) 'M', "MAC");

		public final int value; /* TR31 value representing the usage */
		final byte variantMask; /* Mask to apply when deriving using XOR */
		public final String name; /* readable name */

		TR31Usage(int value, byte variantMask, String name) {
			this.value = value;
			this.variantMask = variantMask;
			this.name = name;
		}
	}

	public static final int TR31_DERIVATION_BASE_LENGTH = 8;

	private static final byte TR31_SEPARATOR = 0;

	/**
	 * Populates the data for the key derivation
	 * 
	 * @param counter   Counter of the key to derive
	 * @param usage     Desired usage of the key
	 * @param algorithm Key algorithm
	 * @return Data vector used for key derivation
	 */
	public static byte[] prepareDerivationBase(int counter, TR31Usage usage, TR31Algorithm algorithm) {
		byte[] result = new byte[TR31_DERIVATION_BASE_LENGTH];

		ByteBuffer bbResult = ByteBuffer.wrap(result);
		/* write the counter */
		bbResult.put((byte) (0xFF & counter));
		/* write the usage */
		bbResult.putShort((short) usage.value);
		/* write the separator */
		bbResult.put(TR31_SEPARATOR);

		/* write the algorithm */
		bbResult.putShort((short) algorithm.value);
		/* write the key length */
		bbResult.putShort((short) algorithm.keyLenBits);
		
		log.fine("Derivation base: " + IO.printByteArray(result));

		return result;
	}

	public static byte[] deriveVariantKey(@NonNull byte[] fromKey, TR31Usage usage) {
		return BitOps.xorArray(fromKey, usage.variantMask);
	}

	public static byte[] deriveBindingAESKey(byte[] fromKey, TR31Usage usage, TR31Algorithm targetAlgorithm)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		byte[] result = new byte[targetAlgorithm.keyLen];

		int desiredLength = targetAlgorithm.keyLen;
		int bytesGenerated = 0;
		/*
		 * we only support AES, so there are at most 2 iterations, for 128 bit and for
		 * everything else
		 */
		int counter = 1;

		while (bytesGenerated < desiredLength) {
			/* prepare the input vector */
			byte[] keygenInput = prepareDerivationBase(counter, usage, targetAlgorithm);
			/* perform AES CMAC on the input vector */
			byte[] keyPart = MessageAuthenticationAlgorithms.computeAESCMAC(keygenInput, fromKey);
			/* copy the result */
			int toCopy = Integer.min(desiredLength - bytesGenerated, keyPart.length);
			System.arraycopy(keyPart, 0, result, bytesGenerated, toCopy);
			bytesGenerated += toCopy;
			counter ++;
		}

		return result;
	}
}
