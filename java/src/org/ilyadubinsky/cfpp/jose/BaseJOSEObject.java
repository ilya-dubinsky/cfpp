package org.ilyadubinsky.cfpp.jose;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;

public abstract class BaseJOSEObject {
	
	protected Map<String, Object> contents;
	
	protected transient Encoder encoder; /* marked Transient so that serialization skips it */
	
	protected BaseJOSEObject() {
		contents = new HashMap<String, Object>();
		encoder =  Base64.getUrlEncoder().withoutPadding();
	}
	
	Map<String, Object> getContents() {
		return contents;
	}
	
	protected void prepareSerialize() {
		
	}
	
	public String toJSON() {
		Gson gson = new Gson();
		prepareSerialize();
		
		return (gson.toJson(contents));
	}
	
	protected String encode(BigInteger value) {
		return encode (value.toByteArray());
	}
	
	protected String encode(byte[] value) {
		return new String(encoder.encode(value), StandardCharsets.US_ASCII);
	}
}
