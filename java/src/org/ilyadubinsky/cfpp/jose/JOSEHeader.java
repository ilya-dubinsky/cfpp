package org.ilyadubinsky.cfpp.jose;

public class JOSEHeader extends BaseJOSEObject {

	
	private static final String JOSE_ALGORITHM 	= "alg";
	private static final String JOSE_ENCRYPTION 	= "enc";
	private static final String JOSE_JWK 			= "jwk";
	private static final String JOSE_KID			= "kid";
	
	/**
	 * Identifies the cryptographic algorithm used to encrypt or determine the value of the CEK.  
	 * @param algorithm
	 */
	public void setAlgorithm (String algorithm) {
		contents.put(JOSE_ALGORITHM, algorithm);
	}
	
	/**
	 * identifies the content encryption algorithm used to perform authenticated
	 * encryption on the plaintext to produce the ciphertext and the Authentication
	 * Tag.
	 * 
	 * @param algorithm
	 */
	public void setEncryptionAlgorithm (String algorithm) {
		contents.put(JOSE_ENCRYPTION, algorithm);
	}
	
	/**
	 * The key is the public key to which the JWE was encrypted; this can be used to
	 * determine the private key needed to decrypt the JWE
	 * 
	 * @param jwk
	 */
	public void setJWK(JWK jwk) {
		contents.put(JOSE_JWK, jwk);
	}
	
	/**
	 * references the public key to which the JWE was encrypted; this can be used to
	 * determine the private key needed to decrypt the JWE.
	 * 
	 * @param kid
	 */
	public void setKeyId(String kid) {
		contents.put(JOSE_KID, kid);
	}
}
