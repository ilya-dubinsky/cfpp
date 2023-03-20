package org.ilyadubinsky.cfpp.emv;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * The interface encapsulates a key pair for use with the EMV standard.
 * Since it is important to know the exact byte length of each key component, and since the implementation has to be
 * interoperable, the platform {@link RSAPublicKey RSAPublicKey} and {@link RSAPrivateKey RSAPrivateKey} interfaces are
 * extended further.
 * 
 * The standard Java serialization mechanism is not used to improve clarity of the code.
 * @author idubinsky
 */
public interface EMVKeyPair extends RSAPublicKey, RSAPrivateKey {

	
	/**
	 * Returns the length of the modulus in bytes.
	 * @return length of the modulus in bytes
	 */
	public int getModulusLength();
	
	/**
	 * Returns the length of the public exponent in bytes. Can be either 1 or 3 in EMV applications
	 * @return length of the public exponent in bytes.
	 */
	public int getPublicExponentLength();
	
	/**
	 * Returns the modulus as an array of bytes.
	 * @return modulus as a byte array.
	 */
	public byte[] getModulusData();

	/**
	 * Sets the value of the modulus.
	 * @param data modulus, in bytes
	 */
	void setModulus(byte[] data);
	
	/**
	 * Sets the value of the public exponent.
	 * @param publicExponent Valid EMV public exponent (3 or 65537, the fourth Fermat prime). Values are not validated.
	 */
	void setPublicExponent(int publicExponent);
	
	/**
	 * Sets the value of the private exponent
	 * @param data private exponent, bytes
	 */
	void setPrivateExponent(byte [] data);
}
