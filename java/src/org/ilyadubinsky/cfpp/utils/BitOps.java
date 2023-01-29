package org.ilyadubinsky.cfpp.utils;

import java.util.Arrays;
import java.util.Random;

public class BitOps {

	private static Random random = new Random(System.currentTimeMillis());

	/**
	 * Calculate bit cardinality of the value
	 * 
	 * @param v input value
	 * @result number of set bits
	 */
	public static int bitCardinality(long v) {
		int c; // c accumulates the total bits set in v
		for (c = 0; v != 0; c++) {
			v &= v - 1; // clear the least significant bit set
		}
		return c;
	}

	/**
	 * Computes the trailing zero bits
	 * 
	 * @param v input long value
	 * @return number of trailing zero bits
	 */
	public static int countTrailingZeroBits(long v) {
		v &= -v;
		int c = 64; /* Long has a 64-bit size */
		System.out.println(String.format("\t\t%04x", v));

		if (v != 0)
			c--;

		if ((v & 0x00000000FFFFFFFFL) != 0)
			c -= 32;
		if ((v & 0x0000FFFF0000FFFFL) != 0)
			c -= 16;
		if ((v & 0x00FF00FF00FF00FFL) != 0)
			c -= 8;
		if ((v & 0x0F0F0F0F0F0F0F0FL) != 0)
			c -= 4;
		if ((v & 0x3333333333333333L) != 0)
			c -= 2;
		if ((v & 0x5555555555555555L) != 0)
			c -= 1;

		return c;
	}

	/**
	 * Calculate even parity bit of the input long value
	 * 
	 * @param v - value for which to compute parity
	 * @return 1 if the number of set bits in v is odd
	 */
	public static int evenParity(long v) {
		int p = 0;
		v ^= v >> 32; /* Shorten the value of v to a 32-bit word while preserving parity */
		v ^= v >> 16; /* Shorten the value of v to a 16-bit word while preserving parity */
		v ^= v >> 8; /* Shorten the value of v to a 8-bit word while preserving parity */
		v ^= v >> 4; /* Shorten the value of v to a 4-bit word while preserving parity */
		v &= 0xF; /* cut off the upper nibble as it is no longer needed */
		p = (0x6996 >> v) & 1; /* use the magic number 0x6996 as the lookup table with 16 entries */
		return p;
	}

	/**
	 * Computes the binary logarithm - the most significant bit of the input long
	 * value
	 * 
	 * @param v input value
	 * @return binary logarithm (leftmost bit).
	 */
	public static int log2(long v) {
		long b[] = { 0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000, 0xFFFFFFFF00000000L };
		int S[] = { 1, 2, 4, 8, 16, 32 };
		int i;

		int r = 0; // result of log2(v) will go here
		for (i = 5; i >= 0; i--) {
			if ((v & b[i]) != 0) {
				v >>= S[i];
				r |= S[i];
			}
		}
		return r;
	}

	/**
	 * Packs two digits into a single byte
	 * 
	 * @param digit1 First digit to pack
	 * @param digit2 Second digit to pack
	 * @return Byte value with packed digits
	 */
	public static byte packDigits(byte digit1, byte digit2) {
		return (byte) (0xFF & (((0xF & digit1) << 4) | (0xF & digit2)));
	}

	/**
	 * Packs digits into bytes with zero padding, left or right
	 * 
	 * @param digits        input array of individual digits
	 * @param desiredLength desired output length in bytes
	 * @param padLeft       true if the padding should be from the left
	 * @return output array
	 */
	public static byte[] packBCD(byte[] digits, int desiredLength, boolean padLeft) {
		if (digits == null || digits.length == 0)
			return null;

		int paddingLength = desiredLength * 2 - digits.length;
		if (paddingLength < 0)
			paddingLength = 0;

		int inputPtr = 0, outputPtr = 0;

		byte[] output = new byte[desiredLength]; // will allocate and initialize with zeroes

		if (padLeft) {
			// skip bytes from the left
			outputPtr += (paddingLength >> 1);
			if (paddingLength % 2 == 1) {
				output[outputPtr++] = packDigits((byte) 0, digits[inputPtr++]);
			}
		}
		/* once left padding is done, all is left is to copy the remaining digits */
		while (outputPtr < desiredLength && inputPtr < digits.length) {
			byte digit1 = digits[inputPtr++];
			byte digit2 = 0;

			if (inputPtr < digits.length) /* this will always be true if the total number of digits is even */
				digit2 = digits[inputPtr++];

			output[outputPtr++] = packDigits(digit1, digit2);
		}

		return output;
	}

	public static byte[] unpackBCD(byte[] packed) {
		if (packed == null || packed.length == 0)
			return null;

		byte[] result = new byte[packed.length * 2];

		for (int i = 0; i < packed.length; i++) {
			result[2 * i] = (byte) (0xF & (packed[i] >> 4));
			result[2 * i + 1] = (byte) (0xF & (packed[i]));
		}

		return result;
	}

	/**
	 * Apply single-byte mask to the array
	 * @param data input value
	 * @param mask mask to apply
	 * @return
	 */
	public static byte[] xorArray(byte[] data, byte mask) {
		byte [] maskArray = new byte[1];
		maskArray[0] = mask;
		
		return xorArray(data, maskArray);
	}
	
	/**
	 * XOR two arrays and return the result. If the mask is shorter than the array,
	 * it will be applied cyclically
	 * 
	 * @param data input value
	 * @param mask mask to apply
	 * @return data XORed with the mask
	 */
	public static byte[] xorArray(byte[] data, byte[] mask) {
		if (data == null || mask == null || data.length == 0 || mask.length == 0)
			return null;
		int maskPtr = 0;
		byte[] result = new byte[data.length];
		for (int resPtr = 0; resPtr < result.length; resPtr++) {
			result[resPtr] = (byte) ((data[resPtr] ^ mask[maskPtr++]) & 0xFF);
			if (maskPtr == mask.length)
				maskPtr = 0;
		}
		return result;
	}

	/**
	 * Shifts a byte array left by a number of bits
	 * 
	 * @param data input array of bytes
	 * @param by   number of bits by which to shift
	 * @return copy of data, shifted left
	 */
	public static byte[] leftShiftArray(byte[] data, int by) {
		if (null == data || by < 0)
			return null;

		byte[] result = new byte[data.length];

		if (0 == by)
			return Arrays.copyOf(data, data.length);

		/* start by shifting the whole bytes, then apply ourselves for the remainder */

		int byBytes = by / 8;

		if (byBytes >= data.length)
			return result;

		if (byBytes > 0) /* there is a whole number of bytes to shift by */
		{
			/* start from by and copy the array into the result */
			System.arraycopy(data, byBytes, result, 0, data.length - byBytes);

			return leftShiftArray(result, by % 8);
		} else { /* shift by bits */
			/* compute the msb mask that will be used to extract carry */
			byte msbMask = (byte) (0xFF & ~(((1 << (8 - by)) - 1)));
			byte carry = 0;
			/*
			 * scan the array from the end to the beginning, shifting left and applying
			 * carry
			 */
			for (int i = data.length - 1; i >= 0; i--) {

				byte newCarry = (byte) ((0xFF & (data[i] & msbMask)) >> (8 - by));

				result[i] = (byte) (data[i] << by | carry);

				carry = newCarry;
			}
		}

		return result;
	}

	/**
	 * Fixes parity bits of the byte array.
	 * 
	 * @param input input array
	 * @param isOdd false if the desired parity is odd, true otherwise
	 * @return byte array with the lowest bit adjusted for parity
	 */
	public static byte[] fixParity(byte[] input, boolean isOdd) {
		if (input == null || input.length == 0)
			return null;

		byte[] result = new byte[input.length];
		for (int i = 0; i < input.length; i++) {
			if ((evenParity(input[i]) == 0) ^ isOdd)
				result[i] = 1;
			result[i] ^= input[i];
		}

		return result;
	}

	/**
	 * Decimalize the input vector. Note: the input value is a packed BCD (nibble
	 * per digit), the output value is unpacked BCD (byte per digit)
	 * 
	 * @param packedInput   input vector
	 * @param desiredLength desired output length
	 * @return unpacked decimalized value
	 */
	public static byte[] decimalizeVector(byte[] packedInput, int desiredLength) {
		if (null == packedInput || 0 == packedInput.length)
			return null;

		if (desiredLength > packedInput.length * 2)
			desiredLength = packedInput.length * 2;

		byte[] result = new byte[desiredLength];
		int resultPtr = 0;
		byte[] unpackedInput = unpackBCD(packedInput);
		int adjustment = 0;
		int inputPtr = 0;
		while (resultPtr < desiredLength && adjustment < 20) {
			if (unpackedInput[inputPtr] >= adjustment && unpackedInput[inputPtr] < adjustment + 10) {
				result[resultPtr++] = (byte) (unpackedInput[inputPtr] - adjustment);
			}
			inputPtr++;

			if (inputPtr == unpackedInput.length) {
				inputPtr = 0;
				adjustment += 10;
			}
		}

		return result;
	}

	/**
	 * Calculates the Luhn check digit of an unpacked BCD array
	 * 
	 * @param unpackedValues array of single digits
	 * @return Luhn's check value
	 */
	public static int luhnCheckDigit(byte[] unpackedValues) {
		if (null == unpackedValues || 0 == unpackedValues.length)
			return 0;

		byte result = 0;

		for (int i = 0; i < unpackedValues.length; i++) {
			int temp = unpackedValues[unpackedValues.length - 1 - i];

			if (i % 2 == 0) {
				temp *= 2;
				if (temp > 10)
					temp = (temp / 10) + (temp % 10);
			}

			result += temp;
		}

		if (result == 0)
			return 0;
		return 10 - (result % 10);
	}

	/**
	 * Converts an Object array to a byte array
	 * 
	 * @param array input array
	 * @return byte array
	 */
	public static byte[] toByteArray(Object[] array) {
		/* input sanity */
		if (array == null)
			return null;
		if (array.length == 0)
			return null;
		/* check the types */
		byte[] result = new byte[array.length];
		for (int i = 0; i < array.length; i++)
			result[i] = (byte) (0xFF & Byte.valueOf(String.valueOf(array[i])).byteValue());

		return result;
	}

	/**
	 * Converts a long array to a byte array
	 * 
	 * @param array input array
	 * @return byte array
	 */
	public static byte[] toByteArray(long[] array) {
		/* input sanity */
		if (array == null)
			return null;
		if (array.length == 0)
			return null;
		/* check the types */
		byte[] result = new byte[array.length];
		for (int i = 0; i < array.length; i++)
			result[i] = (byte) (0xFF & array[i]);

		return result;
	}

	/**
	 * Converts input array to a byte array
	 * 
	 * @param array input array
	 * @return byte array
	 */
	public static byte[] toByteArray(int[] array) {
		/* input sanity */
		if (array == null)
			return null;
		if (array.length == 0)
			return null;
		/* check the types */
		byte[] result = new byte[array.length];
		for (int i = 0; i < array.length; i++)
			result[i] = (byte) (0xFF & array[i]);

		return result;
	}

	/**
	 * Generates a random sequence of bytes of a given size
	 * 
	 * @param size Number of bytes to generate
	 * @return Desired random sequence
	 */
	public static byte[] randomByteSequence(int size) {
		if (size <= 0)
			return null;
		byte[] result = new byte[size];

		for (int i = 0; i < result.length; i++)
			result[i] = (byte) (0xF & random.nextInt());

		return result;
	}

	/**
	 * Pads array from a certain index with a given value till desired length
	 * 
	 * @param array The array to pad
	 * @param from  starting index
	 * @param size  total length to pad
	 * @param value value to use for padding
	 */
	public static void padArray(byte[] array, int from, int size, byte value) {
		if (array == null)
			return;
		if (from + size > array.length)
			return;
		for (int i = from; i < from + size; i++)
			array[i] = value;
	}
	
	/**
	 * Performs multiplication by x in GF(2^n)
	 * @param input Byte array which is considered the coefficients of the polynomial
	 * @param factor The irreducible polynomial
	 * @return Multiplication result as a new array
	 */
	public static byte[] mulByX(byte[] input, byte[] factor) {
		
		int msb = log2( (0xFF & input[0]));
		if (msb != 7)
			/* if the most significant bit of the input is 0, multiplication by x is shifting left */
			return leftShiftArray(input, 1);
		
		/* if the most significant bit is 1, we need to subtract the factor polynomial */
		byte[] result = leftShiftArray (input, 1);
		for (int i=0; i< Integer.min(result.length, factor.length); i++) {
			result[result.length-1-i] ^= factor[factor.length-1-i];
		}
		return result;
	}
}
