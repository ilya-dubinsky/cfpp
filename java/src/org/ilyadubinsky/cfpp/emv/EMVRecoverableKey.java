package org.ilyadubinsky.cfpp.emv;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.ilyadubinsky.cfpp.utils.IO;

import lombok.Getter;

/**
 * This subclass of {@link EMVRecoverable} is the common abstract superclass of
 * two keys, issuer and ICC. It therefore also implements the {@link EMVKeyPair}
 * interface.
 * 
 * @author idubinsky
 *
 */
public abstract class EMVRecoverableKey extends EMVRecoverable implements EMVKeyPair {

	private static final long serialVersionUID = 4299124539796050126L;

	protected final static int CERTIFICATE_SERIAL_NO_LENGTH = 3;

	/**
	 * Contains the serial number of the certificate.
	 */
	@Getter
	protected byte[] certificateSerial = new byte[CERTIFICATE_SERIAL_NO_LENGTH];

	/**
	 * Contains the ID of the entity that has issued the certificate. It is the
	 * issuer BIN in case of the issuer key, or the application PAN in case of the
	 * ICC key.
	 */
	@Getter
	protected byte[] issuingEntityId;

	/**
	 * Contains the modulus of the recovered key. See
	 * {@link CertificateAuthorityKey#modulus} and
	 * {@Link CertificateAuthorityKey#modulusData}.
	 */
	protected BigInteger modulus;
	protected byte[] modulusData;

	/**
	 * Contains the algorithm of the public key. Can be anything as long as it is
	 * RSA.
	 */
	@Getter
	protected byte pkAlgorithm;
	/**
	 * Contains the private exponent. See
	 * {@link CertificateAuthorityKey#privateExponent} and
	 * {@link CertificateAuthorityKey#privateExponentData}.
	 * 
	 */
	protected BigInteger privateExponent;
	protected byte[] privateExponentData;

	/**
	 * Contains the publc exponent. See
	 * {@link CertificateAuthorityKey#publicExponent}.
	 * 
	 */
	protected int publicExponent;

	/**
	 * Contains the length of the public exponent, as recovered from the
	 * certificate.
	 */
	protected byte publicExponentLength;

	/**
	 * Contains the length of the public key, as recovered from the certificate.
	 */
	@Getter
	protected int publicKeyLength;

	/**
	 * Contains the month until which the key is valid, as recovered from the
	 * certificate.
	 */
	@Getter
	protected byte validUntilMonth;

	/**
	 * Contains the year until which the key is valid, as recovered from the
	 * certificate.
	 */
	@Getter
	protected byte validUntilYear;

	/**
	 * See {@link EMVRecoverable#doReadCertificate(ByteBuffer)}. Parses the
	 * certificate, starting after the certificate type and until the end of the
	 * modulus.
	 */
	@Override
	protected void doReadCertificate(ByteBuffer buffer) {
		/* get the issuer ID */
		this.readEntityIdentifier(buffer);
		/* get the month and year */
		this.readExpiryDate(buffer);
		/* read the serial number */
		this.readCertificateSerial(buffer);
		/* read the hash algorithm */
		this.readHashAlgorithm(buffer);
		/* read the issuer PK algorithm */
		this.readPkAlgorithm(buffer);
		/* read the issuer key length */
		this.readPkLength(buffer);
		/* read the issuer exponent length */
		this.readPublicExponentLength(buffer);
		/* read the issuer key part */
		this.readModulus(buffer);
	}

	/**
	 * @return Returns the length of the entity identifier. The ID differs between
	 *         issuer and ICC keys - see {@link EMVRecoverableKey#issuingEntityId}.
	 */
	protected abstract int getEntityIdentiferLength();

	/**
	 * @return Returns the entity name, either issuer or ICC. This is done for the
	 *         toString() readability only.
	 */
	protected abstract String getEntityName();

	/**
	 * Returns the size of the extra data. In this case, it is the length of the
	 * public exponent, which is read from the certificate.
	 */
	@Override
	protected int getExtraDataSize() {
		return this.getPublicExponentLength();
	}

	/**
	 * Reads the serial number of the certificate from the buffer.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readCertificateSerial(ByteBuffer fromBuffer) {
		fromBuffer.get(certificateSerial);
	}

	/**
	 * Reads the identifier of the issuer or the PAN, depending on the key.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readEntityIdentifier(ByteBuffer fromBuffer) {
		issuingEntityId = new byte[getEntityIdentiferLength()];
		fromBuffer.get(issuingEntityId);
	}

	/**
	 * Reads the expiry date of the certificate.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readExpiryDate(ByteBuffer fromBuffer) {
		validUntilMonth = fromBuffer.get();
		validUntilYear = fromBuffer.get();
	}

	/**
	 * Reads the key modulus, skipping the overhead.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readModulus(ByteBuffer fromBuffer) {
		this.modulusData = new byte[this.getPublicKeyLength()];
		fromBuffer.get(modulusData);
		/* need to analyze how much is left and handle padding accordingly */
		int toSkip = fromBuffer.remaining() - HASH_VALUE_LENGTH - 1;
		for (int i = 0; i < toSkip; i++)
			fromBuffer.get();
	}

	/**
	 * Reads and validates the algorithm value.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readPkAlgorithm(ByteBuffer fromBuffer) {
		pkAlgorithm = fromBuffer.get();

		if (!PK_ALGORITHMS.containsKey(pkAlgorithm))
			throw new UnsupportedOperationException("Unsupported issuer PK algorithm value");
	}

	/**
	 * Reads the length of the public key.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readPkLength(ByteBuffer fromBuffer) {
		publicKeyLength = 0xFF & ((int) fromBuffer.get());
	}

	/**
	 * Reads the exponent length.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readPublicExponentLength(ByteBuffer fromBuffer) {
		publicExponentLength = fromBuffer.get();
	}

	/**
	 * Writes the extra data for the purpose of hash signature validation. In this
	 * case, this is the public exponent of the key.
	 */
	@Override
	protected void writeExtraData(ByteBuffer extraDataBuffer) {
		if (getExtraDataSize() == 1) {
			extraDataBuffer.put((byte) (0xFF & this.publicExponent));
		} else {
			// TODO: test this
			extraDataBuffer.put((byte) (0xFF & (this.publicExponent >> 16)));
			extraDataBuffer.put((byte) (0xFF & (this.publicExponent >> 8)));
			extraDataBuffer.put((byte) (0xFF & this.publicExponent));
		}
	}

	@Override
	/** {@inheritDoc} */
	public String getAlgorithm() {
		return null;
	}

	@Override
	/** {@inheritDoc} */
	public byte[] getEncoded() {
		return null;
	}

	@Override
	/** {@inheritDoc} */
	public String getFormat() {
		return null;
	}

	@Override
	/** {@inheritDoc} */
	public BigInteger getModulus() {
		if (this.modulus == null)
			this.modulus = new BigInteger(this.modulusData);
		return this.modulus;
	}

	@Override
	/** {@inheritDoc} */
	public byte[] getModulusData() {
		return this.modulusData;
	}

	@Override
	/** {@inheritDoc} */
	public int getModulusLength() {
		return this.modulusData.length;
	}

	@Override
	/** {@inheritDoc} */
	public BigInteger getPrivateExponent() {

		if (privateExponent == null)
			privateExponent = new BigInteger(privateExponentData);
		return privateExponent;
	}

	@Override
	/** {@inheritDoc} */
	public BigInteger getPublicExponent() {
		return BigInteger.valueOf(publicExponent);
	}

	@Override
	/** {@inheritDoc} */
	public int getPublicExponentLength() {
		return this.publicExponentLength;
	}

	/**
	 * @return Entity ID without the trailing padding of 0xFF.
	 */
	public byte[] getTrimmedEntityId() {
		int padCount = 0;

		for (byte b : issuingEntityId)
			if (b == (byte) (0xFF))
				padCount++;

		byte[] result = new byte[getEntityIdentiferLength() - padCount];
		System.arraycopy(issuingEntityId, 0, result, 0, getEntityIdentiferLength() - padCount);

		return result;
	}

	@Override
	/** {@inheritDoc} */
	public void setModulus(byte[] data) {
		this.modulusData = data;
		this.modulus = null;
	}

	@Override
	/** {@inheritDoc} */
	public void setPrivateExponent(byte[] data) {
		this.privateExponentData = data;
		this.privateExponent = null;
	}

	@Override
	/** {@inheritDoc} */
	public void setPublicExponent(int publicExponent) {
		this.publicExponent = publicExponent;
	}

	@Override
	/** {@inheritDoc} */
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getParentKey().toString());

		builder.append(IO.SEPARATOR).append('\n').append(getEntityName()).append(" key\n").append(IO.SEPARATOR)
				.append('\n');

		if (this.getParentKey() instanceof CertificateAuthorityKey) {
			CertificateAuthorityKey caKey = (CertificateAuthorityKey) this.getParentKey();
			builder.append("\tCA PK ID               : ").append(String.format("%02X", caKey.getIndex())).append('\n');
		}

		builder.append("\tSentinel               : ").append(String.format("%02X", this.getStartSentinel()))
				.append('\n');
		builder.append("\tCertificate format     : ").append(String.format("%02X", this.getCertificateFormat()))
				.append('\n');
		builder.append("\t").append(getEntityName()).append(" identifier      : ")
				.append(IO.printByteArray(this.getTrimmedEntityId(), "", false)).append('\n');
		builder.append("\tExpiry date            : ")
				.append(String.format("%02X/%02X", this.getValidUntilMonth(), this.getValidUntilYear())).append('\n');
		builder.append("\tCertificate number     : ").append(IO.printByteArray(this.getCertificateSerial(), "", false))
				.append('\n');
		builder.append("\tHash algorithm         : ").append(
				String.format("%02X (%s)", this.getHashAlgorithm(), HASH_ALGORITHMS.get(this.getHashAlgorithm())))
				.append('\n');
		builder.append("\tPK algorithm           : ")
				.append(String.format("%02X (%s)", this.getPkAlgorithm(), PK_ALGORITHMS.get(this.getPkAlgorithm())))
				.append('\n');
		builder.append("\t").append(getEntityName()).append(" PK length       : ")
				.append(String.format("%d", ((int) publicKeyLength) & 0xFF)).append('\n');
		builder.append("\t").append(getEntityName()).append(" exponent length : ")
				.append(String.format("%d", ((int) this.getPublicExponentLength()) & 0xFF)).append('\n');
		builder.append("\t").append(getEntityName()).append(" exponent        : ")
				.append(String.format("%04X", this.getPublicExponent())).append('\n');
		builder.append("\t").append(getEntityName()).append(" modulus:\n")
				.append(IO.printByteArray(getModulusData(), "\t\t", true)).append('\n');
		builder.append("\tHash signature:\n").append(IO.printByteArray(getHashSignature(), "\t\t", false));
		builder.append("\tSentinel               : ").append(String.format("%02X", this.getEndSentinel())).append('\n');

		builder.append(IO.SEPARATOR).append('\n');
		return builder.toString();
	}

	@Override
	protected void writeHeader(ByteBuffer b) {
		/* write the entity identifier */
		writeEntityIdentifier(b);
		/* write the expiry date */
		writeExpiryDate(b);
		/* write the serial number */
		writeCertificateSerial(b);
		/* write the hash algorithm identifier */
		writeHashAlgorithm(b);
		/* write the public key algorithm */
		writePkAlgorithm(b);
		/* write the PK length */
		writePkLength(b);
		/* write the exponent length */
		writePublicExponentLength(b);
	}

	private void writePublicExponentLength(ByteBuffer b) {
		b.put(publicExponentLength);
	}

	private void writePkLength(ByteBuffer b) {
		b.put((byte) getPublicKeyLength());
	}

	private void writePkAlgorithm(ByteBuffer b) {
		b.put(RSA_PK_ALGORITHM);
	}

	private void writeCertificateSerial(ByteBuffer b) {
		b.put(getCertificateSerial());
	}

	private void writeExpiryDate(ByteBuffer b) {
		b.put(getValidUntilMonth());
		b.put(getValidUntilYear());
	}

	private void writeEntityIdentifier(ByteBuffer b) {
		b.put(getIssuingEntityId());
	}
	
	@Override
	protected void writePayload(ByteBuffer b) {
		b.put(this.getModulusData());
	}

}
