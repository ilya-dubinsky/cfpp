package org.ilyadubinsky.cfpp.jose;

import java.nio.charset.StandardCharsets;

import lombok.Setter;

public class JWE extends BaseJOSEObject {
	
	@Setter
	private transient JOSEHeader protectedHeader;
	
	private final String JWE_PROTECTED_HEADER 	= "protected";
	private final String JWE_ENCRYPTED_KEY		= "encrypted_key"; 
	private final String JWE_IV					= "iv";
	private final String JWE_CIPHERTEXT			= "ciphertext";
	private final String JWE_TAG				= "tag";
	private final String JWE_AAD				= "aad";
	
	public JWE() {
		protectedHeader = new JOSEHeader();
	}
	
	public String toCompactString() {
		
		/* BASE64URL(UTF8(JWE Protected Header)) || '.' || BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE Initialization
   Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' || BASE64URL(JWE Authentication Tag)*/
		return String.format( "%s.%s.%s.%s.%s",
			encode(protectedHeader.toJSON()),
			contents.get(JWE_ENCRYPTED_KEY),
			contents.get(JWE_IV),
			contents.get(JWE_CIPHERTEXT),
			contents.get(JWE_TAG)
				);
		
	}
	
	public void setEncryptedKey(byte[] key) {
		contents.put(JWE_ENCRYPTED_KEY, encode(key));
	}
	
	public void setIV(byte[] iv) {
		contents.put(JWE_IV, encode(iv));
	}

	public void setCipherText(byte[] cipherText) {
		contents.put(JWE_CIPHERTEXT, encode(cipherText));
	}
	
	public void setTag(byte[] tag) {
		contents.put(JWE_TAG, encode(tag));
	}

	protected byte[] getAad() {
		/* AAD is ASCII(BASE64URL(UTF8(JWE Protected Header))) */
		return encode(protectedHeader.toJSON()).getBytes(StandardCharsets.US_ASCII);
	}
	

	@Override
	protected void prepareSerialize() {
		String encodedProtectedHeader = encode( protectedHeader.toJSON() );
				
		contents.put(JWE_PROTECTED_HEADER, encodedProtectedHeader );
		contents.put(JWE_AAD, encode(getAad()));
		
		super.prepareSerialize();
	}
}
