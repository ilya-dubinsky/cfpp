package org.ilyadubinsky.cfpp.crypto;

import java.security.SecureRandom;
import java.security.SecureRandomParameters;

public class Utils {

	public static class DisableRandom extends SecureRandom {

		private static final long serialVersionUID = -5028778734053659236L;

		private static final byte TRUE_RANDOM_NUMBER = 6;
		
		@Override
		public void nextBytes(byte[] bytes) {
			if (null == bytes) return;
			
			for (int i=0; i<bytes.length; i++)
				bytes[i] = TRUE_RANDOM_NUMBER;
		}

		@Override
		public void nextBytes(byte[] bytes, SecureRandomParameters params) {
			nextBytes(bytes);
		}
		
		
		
	}
}
