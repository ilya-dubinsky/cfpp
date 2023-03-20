package org.ilyadubinsky.cfpp.emv;

import java.math.BigInteger;

import org.ilyadubinsky.cfpp.utils.IO;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;

/**
 * Encapsulates the certificate authority key pair.
 * 
 * @author idubinsky
 */
@Log
public class CertificateAuthorityKey implements EMVKeyPair {

	private static final long serialVersionUID = 1309477290609938231L;

	/**
	 * Retrieves the CA key by its index. Raises an exception if the CA key wasn't
	 * found
	 * 
	 * @param keyIndex one-byte key index to lookup the key by.
	 * @return CA key
	 * @throws IllegalArgumentException
	 */
	public static CertificateAuthorityKey getCAKey(byte keyIndex) throws IllegalArgumentException {
		CertificateAuthorityKey caKey = CertificateAuthorityKeyTable.getCAKeyTable().getCA(keyIndex);
		if (caKey == null) {
			log.warning(String.format("CA PK not found by index %02X", keyIndex));
			throw new IllegalArgumentException("CA PK index not found");
		}

		return caKey;
	}

	/**
	 * Holds the certification authority name - this is for readability only.
	 * Typically, this would be a card scheme.
	 */
	@Getter
	@Setter
	private String authorityName;

	@Getter
	@Setter
	private byte index;

	/**
	 * Contains modulus data and its BigInteger representation. The latter will be
	 * initialized lazily.
	 */
	protected transient BigInteger modulus = null;
	@Setter(AccessLevel.PACKAGE)
	protected byte[] modulusData;

	/**
	 * Contains private exponent data and its BigInteger representation. The latter
	 * will be initialized lazily.
	 */
	protected transient BigInteger privateExponent = null;
	@Setter(AccessLevel.PACKAGE)
	protected byte[] privateExponentData;

	/**
	 * Contains the public exponent. The exponent in EMV applications can be only 3
	 * or F4, hence, int is more than enough.
	 */
	protected int publicExponent;

	/** {@inheritDoc} */
	@Override
	public String getAlgorithm() {
		return "RSA";
	}

	/** {@inheritDoc} */
	@Override
	public byte[] getEncoded() {
		return null;
	}

	/** {@inheritDoc} */
	@Override
	public String getFormat() {
		return null;
	}

	/**
	 * Returns the modulus as a BigInteger. The modulus is lazily initialized from
	 * the previously provided byte array.
	 */
	@Override
	public BigInteger getModulus() {
		if (modulus == null)
			modulus = new BigInteger(modulusData);
		return modulus;
	}

	/** {@inheritDoc} */
	@Override
	public byte[] getModulusData() {
		return modulusData;
	}

	/**
	 * Returns the length of the modulus in bytes.
	 */
	@Override
	public int getModulusLength() {
		if (null == modulusData)
			return 0;
		return modulusData.length;
	}

	/**
	 * Returns the private exponent as a BigInteger. The private exponent is lazily
	 * initialized from the previously provided byte array.
	 */

	@Override
	public BigInteger getPrivateExponent() {
		if (privateExponent == null)
			privateExponent = new BigInteger(privateExponentData);
		return privateExponent;
	}

	/** Returns the public exponent as a BigInteger */
	@Override
	public BigInteger getPublicExponent() {
		return BigInteger.valueOf(publicExponent);
	}

	/**
	 * Returns the length of the public exponent in bytes.
	 */
	@Override
	public int getPublicExponentLength() {
		/* we're relying on the fact that there only are 2 exponents in the standard */
		return publicExponent == 3 ? 1 : 3;
	}

	/** {@inheritDoc} */
	@Override
	public void setModulus(byte[] data) {
		this.modulusData = data;
	}

	/** {@inheritDoc} */
	@Override
	public void setPrivateExponent(byte[] data) {
		this.privateExponentData = data;
	}

	/** {@inheritDoc} */
	@Override
	public void setPublicExponent(int publicExponent) {
		this.publicExponent = publicExponent;
	}

	/** {@inheritDoc} */
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

}
