package org.ilyadubinsky.cfpp.emv;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.ilyadubinsky.cfpp.utils.IO;

import lombok.Getter;

public abstract class EMVRecoverableKey extends EMVRecoverable implements EMVKeyPair {

	private static final long serialVersionUID = 4299124539796050126L;
	
	protected final static int ISSUER_IDENTIFIER_LENGTH = 4;
	protected final static int CERTIFICATE_SERIAL_NO_LENGTH = 3;

	@Getter
	protected byte validUntilMonth;
	@Getter
	protected byte validUntilYear;
	@Getter
	protected byte[] certificateSerial = new byte[CERTIFICATE_SERIAL_NO_LENGTH];
	@Getter
	protected byte pkAlgorithm;
	@Getter
	protected int payloadLength;
	
	protected byte publicExponentLength;
	protected int publicExponent;
	
	protected byte [] privateExponentData;
	protected BigInteger privateExponent;
	
	protected byte [] modulusData;
	protected BigInteger modulus;
	

	@Getter 
	protected byte[] issuingEntityId;

	protected void readExpiryDate(ByteBuffer fromBuffer) {
		validUntilMonth = fromBuffer.get();
		validUntilYear = fromBuffer.get();
	}


	protected void readCertificateSerial(ByteBuffer fromBuffer) {
		fromBuffer.get(certificateSerial);
	}
	
	protected void readPkAlgorithm(ByteBuffer fromBuffer) {
		pkAlgorithm = fromBuffer.get();

		if (!PK_ALGORITHMS.containsKey(pkAlgorithm))
			throw new UnsupportedOperationException("Unsupported issuer PK algorithm value");
	}

	protected abstract int getEntityIdentiferLength ();
	
	protected abstract String getEntityName();
	
	protected void readEntityIdentifier(ByteBuffer fromBuffer) {
		issuingEntityId = new byte[getEntityIdentiferLength()];
		fromBuffer.get(issuingEntityId);
	}

	protected void readPkLength(ByteBuffer fromBuffer) {
		payloadLength = 0xFF & ((int) fromBuffer.get());
	}

	protected void readPublicExponentLength(ByteBuffer fromBuffer) {
		publicExponentLength = fromBuffer.get();
	}

	protected void readModulus(ByteBuffer fromBuffer) {
		this.modulusData = new byte[this.getPayloadLength()];
		fromBuffer.get(modulusData);
		/* need to analyze how much is left and handle padding accordingly */
		int toSkip = fromBuffer.remaining() - HASH_VALUE_LENGTH - 1;
		for (int i =0; i<toSkip; i++) fromBuffer.get();		
	}

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
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getParentKey().toString());
	
		builder.append(IO.SEPARATOR).append('\n').append(getEntityName()).append(" key\n").append(IO.SEPARATOR).append('\n');
	
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
				.append(String.format("%d", ((int) payloadLength) & 0xFF)).append('\n');
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
	protected void doReadData(ByteBuffer buffer) {
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

	@Override
	protected int getExtraDataSize() {
		return this.getPublicExponentLength();
	}

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
	public BigInteger getPublicExponent() {
		return BigInteger.valueOf(publicExponent);
	}

	@Override
	public BigInteger getPrivateExponent() {
		
		if (privateExponent == null)
			privateExponent = new BigInteger(privateExponentData);
		return privateExponent;
	}

	@Override
	public String getAlgorithm() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public BigInteger getModulus() {
		if (this.modulus == null)
			this.modulus = new BigInteger(this.modulusData);
		return this.modulus;
	}

	@Override
	public int getModulusLength() {
		return this.modulusData.length;
	}

	@Override
	public int getPublicExponentLength() {
		return this.publicExponentLength;
	}

	@Override
	public byte[] getModulusData() {
		return this.modulusData;
	}

	@Override
	public void setModulus(byte[] data) {
		this.modulusData = data;
		this.modulus = null;
	}

	@Override
	public void setPublicExponent(int publicExponent) {
		this.publicExponent = publicExponent;
	}

	@Override
	public void setPrivateExponent(byte[] data) {
		this.privateExponentData = data;
		this.privateExponent = null;
	}
	
	

}
