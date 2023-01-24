package org.ilyadubinsky.cfpp.utils;

public class IO {

	/* 
	 * bits
	 * crypto
	 * dukpt
	 * emv
	 * jose
	 * pin
	 * tr31
*/
	private static final int WRAP_WIDTH = 20;
	
	public static String printByteArray(byte [] array) {
		StringBuffer buffer = new StringBuffer();
		int i = 0 ;
		for (byte b : array) {
			
			buffer.append(String.format("%02X", b));
			
			i++;
			
			if (i>0 && (i%2==0))
				buffer.append(' ');
			if (i>0 && (i%WRAP_WIDTH==0))
				buffer.append('\n');
		}
		return buffer.toString();
	}
}
