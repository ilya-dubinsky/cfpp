package org.ilyadubinsky.cfpp.utils;

public class IO {

	/* 
	 * dukpt
	 * emv
*/
	private static final int WRAP_WIDTH = 20;
	
	public static final String SEPARATOR = "============================================================";
	
	/**
	 * Prints the byte array, wrapping at WRAP_WIDTH
	 * @param array array to print
	 * @return String containing the value of the output
	 */
	public static String printByteArray(byte [] array) {
		return printByteArray(array, "", true);
	}
	
	/**
	 * Prints the byte array with the given prefix on each line, wrapping at WRAP_WIDTH
	 * @param array array to print
	 * @param prefix prefix to prepend to each line
	 * @param groupBytes if true, each 2 bytes will be separated by a space
	 * @return String containing the value of the output
	 */
	public static String printByteArray(byte[] array, String prefix, boolean groupBytes) {
		StringBuffer buffer = new StringBuffer();
		
		if (null == array)
			return "";
		
		int i = 0 ;
		for (byte b : array) {
			if (i%WRAP_WIDTH==0) /* we had just wrapped a line*/
				buffer.append(prefix);

			buffer.append(String.format("%02X", b));
			
			i++;
			
			if (i>0 && (i%2==0) && groupBytes)
				buffer.append(' ');
			
			if (i>0 && (i%WRAP_WIDTH==0))
				buffer.append('\n');
		}
		
		if (groupBytes) 
			buffer.append(String.format(" len: %d", array.length));
		
		return buffer.toString();
	}
}
