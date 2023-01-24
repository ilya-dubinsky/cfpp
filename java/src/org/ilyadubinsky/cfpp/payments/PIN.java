package org.ilyadubinsky.cfpp.payments;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.ilyadubinsky.cfpp.crypto.Constants;
import org.ilyadubinsky.cfpp.crypto.SymmetricAlgorithms;
import org.ilyadubinsky.cfpp.utils.BitOps;
import org.ilyadubinsky.cfpp.utils.IO;

import lombok.extern.java.Log;

@Log

public class PIN {

	public static final int PIN_BLOCK_SIZE_0123_N = 16; // Formats 0 to 3, size in nibbles
	public static final int PIN_BLOCK_SIZE_0123_B = PIN_BLOCK_SIZE_0123_N/2; // Formats 0 to 3, size in bytes

	public static final int PIN_BLOCK_SIZE_4_N = 32; // Format 4, length of a single block in nibbles
	public static final int PIN_BLOCK_SIZE_4_B = PIN_BLOCK_SIZE_4_N / 2; // Format 4 size in bytes

	public static final int PIN_MAX_LENGTH = 12;
	public static final int PAN_MIN_LENGTH = 12;

	public static boolean validAESKeyLength(int length) {
		return (length == (128 >> 3) || length == (192 >> 3) || length == (256 >> 3));
	}

	/**
	 * Prepares a pin block of the given format. The PIN block is written return in
	 * a packed form as a byte array.
	 *
	 * In case of PIN block format 4, two concatenated blocks are returned (they
	 * will have to be CBC encrypted)
	 *
	 * @param format   PIN block format, 0 to 4
	 * @param pin      PIN value, unpacked BCD
	 * @param pan      PAN value, unpacked BCD (can be null depending on the format)
	 * @param uniqueID unique ID value, unpacked BCD (can be null depending on the
	 *                 format)
	 * @return returns the PIN block
	 */
	public static byte[] makePINBlock(int format, byte[] pin, byte[] pan, byte[] uniqueID) {
		if (format < 0 || format > 4 || null == pin || pin.length == 0 || pin.length > PIN_MAX_LENGTH)
			return null;

		if (format != 1 && format != 2 && (null == pan || pan.length == 0 || pan.length <= PAN_MIN_LENGTH))
			return null;

		byte[] unpackedBuffer = new byte[format != 4 ? PIN_BLOCK_SIZE_0123_N : PIN_BLOCK_SIZE_4_N * 2];

		int p = 0;

		/* copy the format and the PIN */
		unpackedBuffer[0] = (byte) (format & 0xF);
		p++;

		System.arraycopy(pin, 0, unpackedBuffer, p, pin.length);

		p += pin.length;

		/*
		 * pad depends on the PIN block format. The logic is: if the format is 0 or 2,
		 * pad with 0xF if the format is 1, and a unique ID is provided, pad with it if
		 * the format is 3, or the format is 1 and there's no unique ID, use random
		 * padding if the format is 4, pad with 0xA the first 8 bytes, then pad with
		 * random bytes
		 */
		switch (format) {

		case 0:
		case 2:
			log.fine(" Block 1: " + IO.printByteArray(BitOps.packBCD(unpackedBuffer, PIN_BLOCK_SIZE_0123_B, false)));
			BitOps.padArray(unpackedBuffer, p, PIN_BLOCK_SIZE_0123_N - p, (byte) 0x0F);
			break;

		case 1:
			if (uniqueID != null) {
				/* pad with unique ID as far as it goes */
				int padLen = PIN_BLOCK_SIZE_0123_N - p > uniqueID.length ? uniqueID.length : PIN_BLOCK_SIZE_0123_N - p;
				System.arraycopy(uniqueID, 0, unpackedBuffer, p, padLen);
				p += padLen;
				log.fine(" Block 1: " + IO.printByteArray(BitOps.packBCD(unpackedBuffer, PIN_BLOCK_SIZE_0123_B, false)));
				if (p == PIN_BLOCK_SIZE_0123_N)
					break;
			}
		case 3:
			/* whatever is left must be padded with a random sequence of bytes */
			byte[] seq = BitOps.randomByteSequence(PIN_BLOCK_SIZE_0123_N - p);
			System.arraycopy(seq, 0, unpackedBuffer, p, PIN_BLOCK_SIZE_0123_N - p);
			break;

		case 4:
			/* pad to length of 16 nibbles with 0xA, then random-pad the rest */
			BitOps.padArray(unpackedBuffer, p, PIN_BLOCK_SIZE_0123_N - p, (byte) 0xA);
			System.arraycopy(BitOps.randomByteSequence(PIN_BLOCK_SIZE_0123_N), 0, unpackedBuffer, PIN_BLOCK_SIZE_0123_N,
					PIN_BLOCK_SIZE_0123_N);
			/* make the second block */
			System.arraycopy(makeFormat4Block2(pan), 0, unpackedBuffer, PIN_BLOCK_SIZE_0123_N * 2,
					PIN_BLOCK_SIZE_0123_N * 2);
			break;
		}

		/* if the format is 0 or 3, the buffer should be XOR-ed with the second block */
		if (format == 0 || format == 3) {
			/* prepare the second block */
			byte[] block2 = new byte[PIN_BLOCK_SIZE_0123_N];
			int panDigitsToCopy = pan.length > 12 ? 12 : pan.length - 1;
			System.arraycopy(pan, pan.length - 1 - panDigitsToCopy, block2, 16 - panDigitsToCopy, panDigitsToCopy);

			log.fine(" Block 2: " + IO.printByteArray(BitOps.packBCD(block2, 8, false)));
			/* XOR the PIN block */
			unpackedBuffer = BitOps.xorArray(unpackedBuffer, block2);

		}
		return BitOps.packBCD(unpackedBuffer, unpackedBuffer.length >> 1, false);
	}

	/**
	 * Utility method to create PIN block format 4 second block
	 * @param pan PAN number, unpacked
	 * @return The unpacked block
	 */
	protected static byte[] makeFormat4Block2(byte[] pan) {

		byte[] block2 = new byte[PIN_BLOCK_SIZE_0123_N * 2];

		int p = 0;
		block2[p++] = (byte) (pan.length - 12);

		System.arraycopy(pan, 0, block2, p, pan.length);

		return block2;
	}

	/**
	 * Encrypts a format 4 block formerly prepared by makePINBlock
	 *
	 * @param key          AES encryption key
	 * @param rawPINBlock4 raw Format 4 PIN block, as returned by makePINBlock
	 * @return encrypted PIN block
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ShortBufferException
	 */
	public static byte[] encryptPINBlock4(byte[] key, byte[] rawPINBlock4)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		if (null == key || !validAESKeyLength(key.length) || null == rawPINBlock4
				|| rawPINBlock4.length != PIN_BLOCK_SIZE_4_N)
			return null;

		Cipher c = Cipher.getInstance(Constants.AES_CBC_NO_PADDING);

		SecretKeySpec encKey = new SecretKeySpec(key, Constants.AES_KEY_ALGORITHM);

		IvParameterSpec iv = new IvParameterSpec(new byte[Constants.AES_BLOCK_SIZE_B]);

		c.init(Cipher.ENCRYPT_MODE, encKey, iv);

		/* last block of the encryption output is omitted */

		byte[] retval = new byte[PIN_BLOCK_SIZE_4_B];

		System.arraycopy(c.doFinal(rawPINBlock4), 0, retval, 0, PIN_BLOCK_SIZE_4_B);

		return retval;
	}

	/**
	 * @param key AES decryption key
	 * @param epb Encrypted PIN block
	 * @param pan PAN value
	 * @return Full decrypted PIN block as a packed array
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptPINBlock4(byte[] key, byte[] epb, byte[] pan)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		if (null == key || !validAESKeyLength(key.length) || null == epb || null == pan
				|| epb.length != PIN_BLOCK_SIZE_4_B)
			return null;

		byte[] unpackedBuffer = new byte[PIN_BLOCK_SIZE_4_N * 2];
		/*
		 * to decrypt PIN format 4 PIN block, we take the ciphertext, append the block 2
		 * to it, then use CBC to decipher
		 */
		System.arraycopy(BitOps.unpackBCD(epb), 0, unpackedBuffer, 0, PIN_BLOCK_SIZE_4_N);
		System.arraycopy(makeFormat4Block2(pan), 0, unpackedBuffer, PIN_BLOCK_SIZE_4_N, PIN_BLOCK_SIZE_4_N);
		byte[] packedBuffer = BitOps.packBCD(unpackedBuffer, PIN_BLOCK_SIZE_4_N, false);

		log.fine("Method input: " + IO.printByteArray(epb));
		log.fine("Cipher input: " + IO.printByteArray(packedBuffer));

		/* CBC deciphering */
		Cipher c = Cipher.getInstance(Constants.AES_CBC_NO_PADDING);
		SecretKeySpec encKey = new SecretKeySpec(key, Constants.AES_KEY_ALGORITHM);

		IvParameterSpec iv = new IvParameterSpec(new byte[Constants.AES_BLOCK_SIZE_B]);

		c.init(Cipher.DECRYPT_MODE, encKey, iv);

		return c.doFinal(packedBuffer);
	}

	public static byte[] encryptKeyVariant(  byte[] key, byte [] kek, byte [] variant) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		if ( null == key || null == kek || null == variant) return null;
		
		/* validate key length */
		if (!SymmetricAlgorithms.isValidTDESKeyLength(key.length) || kek.length != Constants.DES_KEY_SIZE_2_B)
			return null;
		
		/*
		 * the length of the variant must be as big as the multiplicity of the key, i.e.
		 * 1 for single, 2 for double and 3 for triple-length keys
		 */
		if (variant.length <= key.length/Constants.DES_KEY_SIZE_1_B) return null;
		
		log.fine("KEK prior to variants: " + IO.printByteArray(kek));
		
		byte[] buffer = new byte[key.length];
		
		for (int i = 0; i< key.length/Constants.DES_KEY_SIZE_1_B; i++) {
			/* XOR variant byte with the first byte of KEK's second half */
			kek [ Constants.DES_KEY_SIZE_1_B] ^= variant[i];
			
			/* extract the chunk */
			byte[] chunk = new byte[Constants.DES_KEY_SIZE_1_B];
			System.arraycopy(key, i*Constants.DES_KEY_SIZE_1_B, chunk, 0, Constants.DES_KEY_SIZE_1_B);
			
			/* encrypt the key chunk with the variant KEK */
			byte[] encryptedChunk = SymmetricAlgorithms.encryptTDESBlock(chunk, kek);
			System.arraycopy(encryptedChunk, 0, buffer, i*Constants.DES_KEY_SIZE_1_B, Constants.DES_KEY_SIZE_1_B);
			
			/* XOR variant byte with the first byte of KEK's second half again to undo the first XOR */
			kek [ Constants.DES_KEY_SIZE_1_B ] ^= variant[i];
		}

		return buffer;
	}

}
