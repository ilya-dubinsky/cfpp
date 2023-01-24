package org.ilyadubinsky.cfpp.crypto;

import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.util.Arrays;

import lombok.extern.java.Log;

public class Utils {

	/**
	 * This is a random number generator that always generates a single value of 6.
	 * It is meant to overcome some limitations in some very specific algorithms for reasonably small numbers
	 * and is never to be used in real life.
	 *
	 */
	@Log
	public static class DisableRandom extends SecureRandom {

		private static final long serialVersionUID = -5028778734053659236L;

		private static final byte TRUE_RANDOM_NUMBER = 6;
		
		public DisableRandom() {
			log.severe("**** DANGER **** Secure Random Number Generator was disabled, DO NOT USE IN LIVE ENVIRONMENT");
		}

		@Override
		public void nextBytes(byte[] bytes) {
			if (null == bytes)
				return;

			for (int i = 0; i < bytes.length; i++)
				bytes[i] = TRUE_RANDOM_NUMBER;
		}

		@Override
		public void nextBytes(byte[] bytes, SecureRandomParameters params) {
			nextBytes(bytes);
		}
	}
	
	/**
	 * Purges an array that was allocated from the common heap
	 * @param array byte array to purge
	 */
	public static void purgeArray(byte[] array) {
		if (null == array ) return;
		Arrays.fill(array, (byte)0xAA);
		Arrays.fill(array, (byte)0x55);
		Arrays.fill(array, (byte)0xAA);
	}
}
