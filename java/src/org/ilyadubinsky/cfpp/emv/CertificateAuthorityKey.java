package org.ilyadubinsky.cfpp.emv;

import java.math.BigInteger;

import org.ilyadubinsky.cfpp.utils.IO;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;

@Log
public class CertificateAuthorityKey implements EMVKeyPair {
	
	private static final long serialVersionUID = 1309477290609938231L;

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

	@Getter @Setter
	private String authorityName;

	@Getter @Setter
	private byte index;
	
	protected BigInteger modulus = null;

	protected byte[] modulusData;

	protected BigInteger privateExponent = null;

	@Setter(AccessLevel.PACKAGE)
	protected byte[] privateExponentData;

	protected int publicExponent;
	
	
	@Override
	public String getAlgorithm() {
		return "RSA";
	}


	@Override
	public byte[] getEncoded() {
		return null;
	}


	@Override
	public String getFormat() {
		return null;
	}


	@Override
	public BigInteger getModulus() {
		if (modulus == null)
			modulus = new BigInteger(modulusData);
		return modulus;
	}


	@Override
	public BigInteger getPrivateExponent() {
		if (privateExponent == null)
			privateExponent = new BigInteger(privateExponentData);
		return privateExponent;
	}


	@Override
	public BigInteger getPublicExponent() {
		return BigInteger.valueOf(publicExponent);
	}


	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		
		buffer.append(IO.SEPARATOR).append('\n');
		buffer.append("Certificate Authority Key\n");
		buffer.append(IO.SEPARATOR).append('\n');
		buffer.append("Authority name: ").append(getAuthorityName()).append('\n');
		buffer.append("PKI: ").append(String.format("%02x", getIndex())).append('\n');
		buffer.append("Exponent: ").append(String.format("%02x", publicExponent)).append('\n');
		buffer.append("Modulus: \n").append(IO.printByteArray(this.modulusData, "         ", true)).append('\n');
		buffer.append(IO.SEPARATOR).append('\n');
		
		return buffer.toString();
	}


	@Override
	public int getModulusLength() {
		return modulusData.length;
	}


	@Override
	public int getPublicExponentLength() {
		/* we're abusing the fact that there only are 2 exponents in the standard */
		return publicExponent == 3 ? 1 : 3;
	}


	@Override
	public void setModulus(byte[] data) {
		this.modulusData = data;
	}


	@Override
	public void setPublicExponent(int publicExponent) {
		this.publicExponent = publicExponent;
	}


	@Override
	public void setPrivateExponent(byte[] data) {
		this.privateExponentData = data;
	}


	@Override
	public byte[] getModulusData() {
		return modulusData;
	}

}
