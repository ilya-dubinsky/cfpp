package org.ilyadubinsky.cfpp.emv;

import org.ilyadubinsky.cfpp.utils.IO;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;

@Log
public class CertificateAuthorityKey extends EMVCertificate {
	
	@Getter @Setter
	private String authorityName;

	@Getter @Setter
	private byte index;

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		
		buffer.append(IO.SEPARATOR).append('\n');
		buffer.append("Certificate Authority Key\n");
		buffer.append(IO.SEPARATOR).append('\n');
		buffer.append("Authority name: ").append(getAuthorityName()).append('\n');
		buffer.append("PKI: ").append(String.format("%02x", getIndex())).append('\n');
		buffer.append("Exponent: ").append(String.format("%02x", publicExponent)).append('\n');
		buffer.append("Modulus: \n").append(IO.printByteArray(getModulus(), "         ", true)).append('\n');
		buffer.append(IO.SEPARATOR).append('\n');
		
		return buffer.toString();
	}
	
	
	/**
	 * Retrieves the CA key by its index. Raises an exception if the CA key wasn't found
	 * @param keyIndex one-byte key index to lookup the key by.
	 * @return CA key
	 * @throws IllegalArgumentException
	 */
	public static CertificateAuthorityKey getCAKey( byte keyIndex ) throws IllegalArgumentException {
		CertificateAuthorityKey caKey = CertificateAuthorityKeyTable.getCAKeyTable().getCA(keyIndex);
		if (caKey == null) {
			log.warning(String.format("CA PK not found by index %02X", keyIndex));
			throw new IllegalArgumentException("CA PK index not found");
		}

		return caKey;
	}
}
