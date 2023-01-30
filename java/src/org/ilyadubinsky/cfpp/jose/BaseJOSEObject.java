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
	
	protected Encoder encoder;
	
	protected BaseJOSEObject() {
		contents = new HashMap<String, Object>();
		encoder =  Base64.getUrlEncoder().withoutPadding();
	}
	
	public String toJSON() {
		Gson gson = new Gson();
		
		return (gson.toJson(contents));
	}
	
	protected String encode(BigInteger value) {
		return encode (value.toByteArray());
	}
	
	protected String encode(byte[] value) {
		return new String(encoder.encode(value), StandardCharsets.US_ASCII);
	}
}
