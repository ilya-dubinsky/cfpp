package org.ilyadubinsky.cfpp;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

import org.ilyadubinsky.cfpp.crypto.MessageAuthenticationAlgorithms;
import org.ilyadubinsky.cfpp.utilis.TestIO;

public class TestDSA {

	public static void main(String[] args) throws Exception {
		

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		KeyPair pair = kpg.generateKeyPair();

		DSAPrivateKey dsaPrivKey = (DSAPrivateKey) pair.getPrivate();
		DSAPublicKey dsaPubKey = (DSAPublicKey) pair.getPublic();
		DSAParams dparams = dsaPrivKey.getParams();
		
		
//		BigInteger x = dsaPrivKey.getX();
//		BigInteger p = dparams.getP();
//		BigInteger q = dparams.getQ();
//		BigInteger g = dparams.getG();
//		BigInteger y = dsaPubKey.getY();
//		
		BigInteger p = BigInteger.valueOf(43); // a prime
		BigInteger q = BigInteger.valueOf(7);  // a prime such that p-1 is a multiple of q
		BigInteger g = BigInteger.valueOf(41); // 3^((43-1)/7) mod 43
		BigInteger x = BigInteger.valueOf(4);  // randomly chosen from 1.. to q-1
		BigInteger y = BigInteger.valueOf(16); // g^x mod p		
		
//		BigInteger p = BigInteger.valueOf(2339); // a prime
//		BigInteger q = BigInteger.valueOf(167);  // a prime such that p-1 is a multiple of q
//		BigInteger g = BigInteger.valueOf(11); // 2^((43-1)/7) mod 43
//		BigInteger x = BigInteger.valueOf(4);  // randomly chosen from 1.. to q-1
//		BigInteger y = BigInteger.valueOf(477); // g^x mod p
		
		System.out.println("DSA keys: \n\t\tX: " + x.toString() + "\n\t\tP: " + p.toString() + "\n\t\tQ: "
				+ q.toString() + "\n\t\tG: " + g.toString());
		
		byte[] image = { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF };
		
		byte[] dsaSignature = MessageAuthenticationAlgorithms.signDSA(image, x, p, q, g);
		
		System.out.println("Signature: " + TestIO.printByteArray(dsaSignature));

		System.out.println("DSA keys: \n\t\tY: " + y.toString() + "\n\t\tP: " + p.toString() + "\n\t\tQ: "
				+ q.toString() + "\n\t\tG: " + g.toString());
		
		System.out.println("Validation: " + MessageAuthenticationAlgorithms.verifyDSA(image, dsaSignature, y, p, q, g));

	}

}
