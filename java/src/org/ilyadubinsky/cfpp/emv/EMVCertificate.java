package org.ilyadubinsky.cfpp.emv;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

public class EMVCertificate {
	
	

	protected static final int HASH_VALUE_LENGTH = 20;

	protected static final byte START_SENTINEL = 0x6A;
	protected static final byte END_SENTINEL = (byte) 0xBC;
	protected static final byte SHA1_HASH_ALGORITHM = 0x01;
	protected static final byte RSA_PK_ALGORITHM = 0x01;

	protected static final Map<Byte, String> HASH_ALGORITHMS = new ConcurrentHashMap<Byte, String>();
	protected static final Map<Byte, String> PK_ALGORITHMS = new ConcurrentHashMap<Byte, String>();

	static {
		HASH_ALGORITHMS.put((byte) SHA1_HASH_ALGORITHM, "SHA-1");

		PK_ALGORITHMS.put((byte) RSA_PK_ALGORITHM, "RSA");
	}

	@Getter
	@Setter(AccessLevel.PACKAGE)
	protected EMVCertificate parentCertificate;

	@Getter
	@Setter(AccessLevel.PACKAGE)
	protected byte[] modulus;
	
	@Getter
	@Setter(AccessLevel.PACKAGE)
	protected int publicExponent;

}
