package org.ilyadubinsky.cfpp.emv;

import org.ilyadubinsky.cfpp.utils.IO;

import lombok.Getter;
import lombok.Setter;

public class CertificateAuthorityKey {
	
	@Getter @Setter
	private String authorityName;

	@Getter @Setter
	private byte index;

	@Getter @Setter
	private byte[] modulus;
	
	@Getter @Setter
	private int publicExponent;

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		
		buffer.append("Authority name: ").append(getAuthorityName()).append('\n');
		buffer.append("PKI: ").append(String.format("%02x", getIndex())).append('\n');
		buffer.append("Exponent: ").append(String.format("%02x", publicExponent)).append('\n');
		buffer.append("Modulus: \n").append(IO.printByteArray(getModulus(), "         ", true));
		
		return buffer.toString();
	}
		
}
