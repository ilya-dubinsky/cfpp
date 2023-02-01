package org.ilyadubinsky.cfpp.jose;

import java.math.BigInteger;

public class JWK extends BaseJOSEObject {

	private static final String JWK_KEY_TYPE 	= "kty";
	
	private static final String JWK_KEY_ID 		= "kid";
	private static final String JWK_USE 		= "use";
	private static final String JWK_RSA_N 		= "n";
	private static final String JWK_RSA_E 		= "e";
	
	private static final String JWK_CURVE 		= "crv";
	private static final String JWK_X			= "x";	
	private static final String JWK_Y			= "y";
	
	/**
	 * Returns key type (kty)
	 * @return
	 */
	public String getKeyType() {
		return String.valueOf(contents.get(JWK_KEY_TYPE));
	}
	
	/**
	 * Sets key type (kty)
	 * @param keyType
	 */
	public void setKeyType(String keyType) {
		contents.put(JWK_KEY_TYPE, keyType);
	}
	
	/**
	 * Sets RSA values, if not null
	 * @param e the public exponent
	 * @param n the modulus
	 * @param kid key ID
	 */
	public void setRSAValues(BigInteger e, BigInteger n, String kid) {
		if (null != e)
			contents.put(JWK_RSA_E, encode(e));
		
		if (null != n)
			contents.put(JWK_RSA_N, encode(n));
		
		if (null != kid)
			contents.put(JWK_KEY_ID, kid);
	}
	
	/**
	 * Sets the key use parameter (use)
	 * @param use
	 */
	public void setUse(String use) {
		if ( null != use )
			contents.put(JWK_USE, use);
	}
	
	/**
	 * Sets elliptic curve values
	 * @param curve curve ID
	 * @param x X coordinate 
	 * @param y Y coordinate
	 * @param kid key ID
	 */
	public void setECValues(String curve, BigInteger x, BigInteger y, String kid) {
		if ( null != curve )
			contents.put(JWK_CURVE, curve);
		
		if ( null != kid )
			contents.put(JWK_KEY_ID, kid);
		
		if (null != x)
			contents.put(JWK_X, encode(x));
		
		if (null != y)
			contents.put(JWK_Y, encode(y));
	}

}
