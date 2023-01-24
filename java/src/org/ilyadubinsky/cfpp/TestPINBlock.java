package org.ilyadubinsky.cfpp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.LogManager;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.ilyadubinsky.cfpp.utilis.PIN;
import org.ilyadubinsky.cfpp.utilis.TestIO;

public class TestPINBlock {

	public static void main(String[] args) throws SecurityException, FileNotFoundException, IOException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
		LogManager manager = LogManager.getLogManager();
		manager.readConfiguration(new FileInputStream("logging.properties"));

		byte[] pin = { 1, 2, 3, 4 };
		byte[] pan = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5 };
		byte[] uniqueId = { 7, 7, 3, 2 };
		byte[] aesKey = { 0x45, 0x12, 0x34, 0x5A, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xFB, 0x1B,
				(byte) 0x8F, 0x4D, (byte) 0xB0, 0x6C, (byte) 0xC4, (byte) 0xF5, 0x40, 0x12, 0x34, 0x56, 0x78,
				(byte) 0x90, 0x12, 0x34, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		
		byte[] tdesKey = { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 
				(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
		byte[] kek = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
		byte[] variant = { (byte) 0xA6, (byte) 0xED, (byte) 0xB2};

		byte[] pinBlock0 = PIN.makePINBlock(0, pin, pan, null);
		System.out.println("Format 0 packed value: " + TestIO.printByteArray(pinBlock0));

		byte[] pinBlock1 = PIN.makePINBlock(1, pin, pan, uniqueId);
		System.out.println("Format 1 packed value: " + TestIO.printByteArray(pinBlock1));

		byte[] pinBlock2 = PIN.makePINBlock(2, pin, pan, uniqueId);
		System.out.println("Format 2 packed value: " + TestIO.printByteArray(pinBlock2));

		byte[] pinBlock3 = PIN.makePINBlock(3, pin, pan, uniqueId);
		System.out.println("Format 3 packed value: " + TestIO.printByteArray(pinBlock3));

		byte[] pinBlock4 = PIN.makePINBlock(4, pin, pan, uniqueId);
		System.out.println("Format 4 packed value: " + TestIO.printByteArray(pinBlock4));

		byte[] epb4 = PIN.encryptPINBlock4(aesKey, pinBlock4);
		System.out.println("Format 4 encrypted value: " + TestIO.printByteArray(epb4));
		
		byte[] epb4_back = PIN.decryptPINBlock4(aesKey, epb4, pan);
		System.out.println("Format 4 decrypted value: " + TestIO.printByteArray(epb4_back));
		
		byte[] epbVariant = PIN.encryptKeyVariant(tdesKey, kek, variant);
		System.out.println("Vairant-encrypted key: " + TestIO.printByteArray(epbVariant));

	}

}
