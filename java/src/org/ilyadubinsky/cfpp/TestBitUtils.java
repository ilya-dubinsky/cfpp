package org.ilyadubinsky.cfpp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.LogManager;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.ilyadubinsky.cfpp.utilis.BitOps;
import org.ilyadubinsky.cfpp.utilis.Legacy;
import org.ilyadubinsky.cfpp.utilis.TestIO;

public class TestBitUtils {
	public static void main(String[] args)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException, SecurityException, FileNotFoundException, IOException {

		LogManager manager = LogManager.getLogManager();
		manager.readConfiguration(new FileInputStream("logging.properties"));

		System.out.println(
				String.format("Value %04X, trailing zero bits %d", 0x2C0L, BitOps.countTrailingZeroBits(0x2C0L)));
		System.out.println(String.format("Value %04X, log2 %d", 0x2L, BitOps.log2(0x2L)));

		byte[] digits = { 4, 3, 2, 1, 5, 6, 7 };
		byte[] parity = { 0xE, 0xF };
		byte[] dec = { (byte) 0xB2, (byte) 0xB3, (byte) 0xC5 };
		byte[] luhn = { 3, 1, 7, 2, 1, 8, 1, 4 };

		System.out.println("Packed value: " + TestIO.printByteArray(BitOps.packBCD(digits, 2, false)));
		System.out.println("Bit cardinality: " + BitOps.bitCardinality(0xFEFEFEFEL));

		System.out.println("Fix parity:" + TestIO.printByteArray(BitOps.fixParity(parity, true)));

		System.out.println("Decimalize:" + TestIO.printByteArray(BitOps.decimalizeVector(dec, 2)));

		System.out.println("Luhn: " + BitOps.luhnCheckDigit(luhn));

		byte[] testPan = { 0x4, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5 };
		byte[] testExpiry = { 0x8, 0x7, 0x0, 0x1 };
		byte[] testServiceCode = { 0x1, 0x0, 0x1 };

		byte[] testCVKA = { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
		byte[] testCVKB = { (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98, 0x76, 0x54, 0x32, 0x10 };

		byte[] pvvTestPan = { 4, 4, 4, 4, 3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1 };
		byte[] pvvTestPin = { 1, 2, 3, 4 };
		byte pvvTestPvk = 1;
		byte[] pvvPVKA = { 0x23, 0x32, 0x20, (byte) 0xCC, (byte) 0xDD, (byte) 0xCC, 0x32, 0x23 };
		byte[] pvvPVKB = { 0x15, (byte) 0xC4, 0x4C, 0x2A, 0x51, (byte) 0xA2, (byte) 0xDF, (byte) 0xFD };

		System.out.println("CVV: " + TestIO
				.printByteArray(Legacy.computeCVV(testPan, testExpiry, testServiceCode, testCVKA, testCVKB, 3)));

		System.out.println("PVV: "
				+ TestIO.printByteArray(Legacy.computePVV(pvvTestPan, pvvTestPin, pvvTestPvk, pvvPVKA, pvvPVKB, 4)));
	}
}
