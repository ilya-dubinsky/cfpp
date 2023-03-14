package org.ilyadubinsky.cfpp.emv;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.ilyadubinsky.cfpp.crypto.AsymmetricAlgorithms;
import org.ilyadubinsky.cfpp.crypto.MessageAuthenticationAlgorithms;
import org.ilyadubinsky.cfpp.utils.IO;

import lombok.Getter;
import lombok.extern.java.Log;

@Log
public abstract class EMVRecoverableCertificate extends EMVCertificate {

	protected static EMVRecoverableCertificate doRecoverKey(EMVRecoverableCertificate result, EMVCertificate parentKey, byte[] certificate, int exponent, byte[] remainder)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {
		
				result.setParentCertificate(parentKey);
			
				byte[] decipheredKey = AsymmetricAlgorithms.decryptRSA(certificate, new BigInteger(result.getParentCertificate().getModulus()),
						BigInteger.valueOf(result.getParentCertificate().getPublicExponent()));
			
				byte[] fullKey = new byte[decipheredKey.length + ((remainder != null) ? remainder.length : 0)];
				
				log.finest("Certificate   : \n" + IO.printByteArray(certificate, "\t", true));
				log.finest("Deciphered key: \n" + IO.printByteArray(decipheredKey, "\t", true));
			
				/*
				 * the order is: deciphered certificate without the hash and the sentinel, remainder, hash,
				 * sentinel
				 */
				ByteBuffer writeBuffer = ByteBuffer.wrap(fullKey);
			
				/* deciphered certificate */
				writeBuffer.put(Arrays.copyOfRange(decipheredKey, 0, decipheredKey.length - HASH_VALUE_LENGTH - 1));
			
				/* remainder */
				if (remainder != null)
					writeBuffer.put(remainder);
			
				/* the hash value and the sentinel */
				writeBuffer.put(
						Arrays.copyOfRange(decipheredKey, decipheredKey.length - HASH_VALUE_LENGTH - 1, decipheredKey.length));
			
				result.setPublicExponent(exponent);
			
				result.readData(fullKey);
			
				return result;
			}

	protected final static int ISSUER_IDENTIFIER_LENGTH = 4;
	protected final static int CERTIFICATE_SERIAL_NO_LENGTH = 3;

	@Getter
	private byte startSentinel;
	@Getter
	protected byte validUntilMonth;
	@Getter
	protected byte validUntilYear;
	@Getter
	protected byte[] certificateSerial = new byte[CERTIFICATE_SERIAL_NO_LENGTH];
	@Getter
	protected byte hashAlgorithm;
	@Getter
	protected byte pkAlgorithm;
	@Getter
	protected int pkLength;
	@Getter
	protected byte publicExponentLength;
	@Getter
	private byte[] hashSignature;
	@Getter
	private byte endSentinel;
	@Getter
	protected byte certificateFormat;
	
	@Getter 
	protected byte[] issuingEntityId;

	/**
	 * Reads the start sentinel from the buffer
	 * 
	 * @param fromBuffer
	 */
	protected void readStartSentinel(ByteBuffer fromBuffer) {
		startSentinel = fromBuffer.get();
	
		if (START_SENTINEL != startSentinel)
			throw new IllegalArgumentException("Issuer key start sentinel value is incorrect - wrong CA PKI?");
	}

	protected void readHashSignature(ByteBuffer fromBuffer) {
		this.hashSignature = new byte[HASH_VALUE_LENGTH];
	
		fromBuffer.get(hashSignature);
	}

	protected void readEndSentinel(ByteBuffer fromBuffer) {
		this.endSentinel = fromBuffer.get();
	
		if (END_SENTINEL != endSentinel)
			throw new IllegalArgumentException("Issuer key end sentinel value is incorrect ");
	}
	
	protected abstract void validateCertificateFormat();
	
	protected void readCertificateFormat(ByteBuffer fromBuffer) {
		certificateFormat = fromBuffer.get();
	
		validateCertificateFormat();
	}

	protected void readExpiryDate(ByteBuffer fromBuffer) {
		validUntilMonth = fromBuffer.get();
		validUntilYear = fromBuffer.get();
	}

	protected void readHashAlgorithm(ByteBuffer fromBuffer) {
		hashAlgorithm = fromBuffer.get();
	
		if (!HASH_ALGORITHMS.containsKey(hashAlgorithm))
			throw new UnsupportedOperationException(String.format("Unsupported hash algorithm value: %2X", hashAlgorithm));
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
	
	protected abstract int getOverheadSize();

	protected void readEntityIdentifier(ByteBuffer fromBuffer) {
		issuingEntityId = new byte[getEntityIdentiferLength()];
		fromBuffer.get(issuingEntityId);
	}

	protected void readPkLength(ByteBuffer fromBuffer) {
		pkLength = 0xFF & ((int) fromBuffer.get());
	}

	protected void readPublicExponentLength(ByteBuffer fromBuffer) {
		publicExponentLength = fromBuffer.get();
	}

	protected void readModulus(ByteBuffer fromBuffer) {
		this.modulus = new byte[this.getPkLength()];
		fromBuffer.get(modulus);
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

	/**
	 * Reads key data from the provided byte array, performing validation according to the spec
	 * @param fullKey input byte array
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalArgumentException
	 * @throws SignatureException
	 */
	protected void readData(byte[] fullKey)
			throws NoSuchAlgorithmException, IllegalArgumentException, SignatureException {
				ByteBuffer buffer = ByteBuffer.wrap(fullKey);
			
				this.readStartSentinel(buffer);
				this.readCertificateFormat(buffer);
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
				/* read the hash value */
				this.readHashSignature(buffer);
				/* read the end sentinel */
				this.readEndSentinel(buffer);
			
				/* determine if padding is required */
				int paddingLength = this.getParentCertificate().getModulus().length 
						- this.getOverheadSize() - this.getPkLength();
				if (paddingLength < 0)
					paddingLength = 0;

				/* validate the hash value */
				int hashInputLength = 1 /* certificate format */ 
						+ getEntityIdentiferLength() 
						+ 2 /* expiry date */
						+ CERTIFICATE_SERIAL_NO_LENGTH 
						+ 1 /* hash algorithm */
						+ 1 /* PK algorithm */
						+ 1 /* PK length field */
						+ 1 /* exponent length field */
						+ this.getPkLength() 
						+ paddingLength -1 /* compensating for the sentinel */
						+ this.getPublicExponentLength();
								
				byte[] hashInput = new byte[hashInputLength];
				
//				log.finest("fullKey: \n" + IO.printByteArray(fullKey));
				
//				log.finest("full key len: " + fullKey.length + " hashInput len: " + hashInputLength);
			
				System.arraycopy(fullKey, 1, hashInput, 0, hashInputLength - this.getPublicExponentLength());
			
				/* write the exponent */
				ByteBuffer exponentBuffer = ByteBuffer.wrap(hashInput, hashInput.length - this.getPublicExponentLength(),
						this.getPublicExponentLength());
			
				if (this.getPublicExponentLength() == 1) {
					exponentBuffer.put((byte) (0xFF & this.getPublicExponent()));
				} else {
					// TODO: test this
					exponentBuffer.put((byte) (0xFF & (this.getPublicExponent() >> 16)));
					exponentBuffer.put((byte) (0xFF & (this.getPublicExponent() >> 8)));
					exponentBuffer.put((byte) (0xFF & this.getPublicExponent()));
				}
			
//				log.finest("Hash input: \n" + IO.printByteArray(hashInput));
				byte[] hashOutput = MessageAuthenticationAlgorithms.computeSHA1(hashInput);
//				log.finest("Hash Output: \n" + IO.printByteArray(hashOutput));
			
				/* compare the computed hash with the provided one */
				if (!Arrays.equals(hashOutput, this.getHashSignature())) {
					log.warning("The provided signature " + IO.printByteArray(this.getHashSignature())
							+ " doesn't match the computed signature " + IO.printByteArray(hashOutput));
					throw new SignatureException("The provided SHA-1 signature doesn't match the recovered one");
				}
			
			}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getParentCertificate().toString());
	
		builder.append(IO.SEPARATOR).append('\n').append(getEntityName()).append(" key\n").append(IO.SEPARATOR).append('\n');
	
		if (this.getParentCertificate() instanceof CertificateAuthorityKey) {
			CertificateAuthorityKey caKey = (CertificateAuthorityKey) this.getParentCertificate();
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
				.append(String.format("%d", ((int) pkLength) & 0xFF)).append('\n');
		builder.append("\t").append(getEntityName()).append(" exponent length : ")
				.append(String.format("%d", ((int) this.getPublicExponentLength()) & 0xFF)).append('\n');
		builder.append("\t").append(getEntityName()).append(" exponent        : ")
				.append(String.format("%04X", this.getPublicExponent())).append('\n');
		builder.append("\t").append(getEntityName()).append(" modulus:\n")
				.append(IO.printByteArray(getModulus(), "\t\t", true)).append('\n');
		builder.append("\tHash signature:\n").append(IO.printByteArray(getHashSignature(), "\t\t", false));
		builder.append("\tSentinel               : ").append(String.format("%02X", this.getEndSentinel())).append('\n');
	
		builder.append(IO.SEPARATOR).append('\n');
		return builder.toString();
	};
}
