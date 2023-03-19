package org.ilyadubinsky.cfpp.emv;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

interface EMVKeyPair extends RSAPublicKey, RSAPrivateKey {

	public int getModulusLength();
	public int getPublicExponentLength();
	
	byte[] getModulusData();
	void setModulus(byte[] data);
	void setPublicExponent(int publicExponent);
	void setPrivateExponent(byte [] data);
}
