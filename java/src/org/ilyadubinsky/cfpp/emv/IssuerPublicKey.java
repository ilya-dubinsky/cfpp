package org.ilyadubinsky.cfpp.emv;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.ilyadubinsky.cfpp.crypto.AsymmetricAlgorithms;
import org.ilyadubinsky.cfpp.crypto.MessageAuthenticationAlgorithms;
import org.ilyadubinsky.cfpp.utils.IO;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.java.Log;

@Log
public class IssuerPublicKey {

	@Getter
	@Setter(AccessLevel.PRIVATE)
	@NonNull
	private CertificateAuthorityKey caKey;

	@Getter
	private byte startSentinel;
	@Getter
	private byte certificateFormat;
	@Getter
	private byte[] issuerIdentifier = new byte[ISSUER_IDENTIFIER_LENGTH];
	@Getter
	private byte validUntilMonth;
	@Getter
	private byte validUntilYear;
	@Getter
	private byte[] certificateSerial = new byte[CERTIFICATE_SERIAL_NO_LENGTH];
	@Getter
	private byte hashAlgorithm;
	@Getter
	private byte issuerPkAlgorithm;
	@Getter
	private int issuerPkLength;
	@Getter
	private byte issuerExponentLength;

	@Getter
	@Setter
	private int issuerExponent;

	@Getter
	private byte[] issuerPublicKey;

	@Getter
	private byte[] hashSignature;

	@Getter
	private byte endSentinel;

	private final static int ISSUER_IDENTIFIER_LENGTH = 4;
	private final static int CERTIFICATE_SERIAL_NO_LENGTH = 3;

	private final static int HASH_VALUE_LENGTH = 20;

	private final static byte ISSUER_START_SENTINEL = 0x6A;
	private final static byte ISSUER_CERTIFICATE_FORMAT = 0x02;
	private static final byte ISSUER_END_SENTINEL = (byte) 0xBC;

	private final static byte ISSUER_SHA1_HASH_ALGORITHM = 0x01;
	private static final byte ISSUER_RSA_PK_ALGORITHM = 0x01;

	private static final Map<Byte, String> HASH_ALGORITHMS = new ConcurrentHashMap<Byte, String>();
	private static final Map<Byte, String> PK_ALGORITHMS = new ConcurrentHashMap<Byte, String>();

	static {
		HASH_ALGORITHMS.put((byte) ISSUER_SHA1_HASH_ALGORITHM, "SHA-1");

		PK_ALGORITHMS.put((byte) ISSUER_RSA_PK_ALGORITHM, "RSA");
	}

	/**
	 * Reads the start sentinel from the buffer
	 * 
	 * @param fromBuffer
	 */
	private void readStartSentinel(ByteBuffer fromBuffer) {
		startSentinel = fromBuffer.get();

		if (ISSUER_START_SENTINEL != startSentinel)
			throw new IllegalArgumentException("Issuer key start sentinel value is incorrect - wrong CA PKI?");
	}

	private void readCertificateFormat(ByteBuffer fromBuffer) {
		certificateFormat = fromBuffer.get();

		if (ISSUER_CERTIFICATE_FORMAT != certificateFormat)
			throw new UnsupportedOperationException("Unsupported certificate format");
	}

	private void readIssuerIdentifier(ByteBuffer fromBuffer) {
		fromBuffer.get(issuerIdentifier);
	}

	private void readExpiryDate(ByteBuffer fromBuffer) {
		validUntilMonth = fromBuffer.get();
		validUntilYear = fromBuffer.get();
	}

	private void readCertificateSerial(ByteBuffer fromBuffer) {
		fromBuffer.get(certificateSerial);
	}

	private void readHashAlgorithm(ByteBuffer fromBuffer) {
		hashAlgorithm = fromBuffer.get();

		if (!HASH_ALGORITHMS.containsKey(hashAlgorithm))
			throw new UnsupportedOperationException("Unsupported hash algorithm value");
	}

	private void readIssuerPkAlgorithm(ByteBuffer fromBuffer) {
		issuerPkAlgorithm = fromBuffer.get();

		if (!PK_ALGORITHMS.containsKey(issuerPkAlgorithm))
			throw new UnsupportedOperationException("Unsupported issuer PK algorithm value");
	}

	private void readIssuerPkLength(ByteBuffer fromBuffer) {
		issuerPkLength = 0xFF & ((int) fromBuffer.get());
	}

	private void readIssuerExponentLength(ByteBuffer fromBuffer) {
		issuerExponentLength = fromBuffer.get();
	}

	private void readIssuerKey(ByteBuffer fromBuffer) {

		this.issuerPublicKey = new byte[this.getIssuerPkLength()];
		fromBuffer.get(issuerPublicKey);
	}

	private void readHashSignature(ByteBuffer fromBuffer) {
		this.hashSignature = new byte[HASH_VALUE_LENGTH];

		fromBuffer.get(hashSignature);
	}

	private void readEndSentinel(ByteBuffer fromBuffer) {
		this.endSentinel = fromBuffer.get();

		if (ISSUER_END_SENTINEL != endSentinel)
			throw new IllegalArgumentException("Issuer key end sentinel value is incorrect ");
	}

	public byte[] getTrimmedIssuerIdentifier() {
		int padCount = 0;

		for (byte b : issuerIdentifier)
			if (b == (byte) (0xFF))
				padCount++;

		byte[] result = new byte[ISSUER_IDENTIFIER_LENGTH - padCount];
		System.arraycopy(issuerIdentifier, 0, result, 0, ISSUER_IDENTIFIER_LENGTH - padCount);

		return result;
	}

	public static IssuerPublicKey recoverKey(byte caPublicKeyIndex, @NonNull byte[] certificate, byte[] remainder,
			int exponent)
			throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		/* instantiate a new object */

		IssuerPublicKey result = new IssuerPublicKey();

		/* locate and set the CA */
		CertificateAuthorityKey caKey = CertificateAuthorityKeyTable.getCAKeyTable().getCA(caPublicKeyIndex);
		if (caKey == null) {
			log.warning(String.format("CA PK not found by index %02X", caPublicKeyIndex));
			throw new IllegalArgumentException("CA PK index not found");
		}
		result.setCaKey(caKey);

		byte[] decipheredKey = AsymmetricAlgorithms.decryptRSA(certificate, new BigInteger(caKey.getModulus()),
				BigInteger.valueOf(caKey.getPublicExponent()));

		byte[] fullKey = new byte[decipheredKey.length + ((remainder != null) ? remainder.length : 0)];

		/*
		 * the order is: deciphered certificate without the hash and the sentinel, hash,
		 * sentinel
		 */
		ByteBuffer writeBuffer = ByteBuffer.wrap(fullKey);

		writeBuffer.put(Arrays.copyOfRange(decipheredKey, 0, decipheredKey.length - HASH_VALUE_LENGTH - 1));

		if (remainder != null)
			writeBuffer.put(remainder);

		/* now the hash value and the sentinel */
		writeBuffer.put(
				Arrays.copyOfRange(decipheredKey, decipheredKey.length - HASH_VALUE_LENGTH - 1, decipheredKey.length));

		ByteBuffer buffer = ByteBuffer.wrap(fullKey);

		result.readStartSentinel(buffer);
		result.readCertificateFormat(buffer);
		/* get the issuer ID */
		result.readIssuerIdentifier(buffer);
		/* get the month and year */
		result.readExpiryDate(buffer);
		/* read the serial number */
		result.readCertificateSerial(buffer);
		/* read the hash algorithm */
		result.readHashAlgorithm(buffer);
		/* read the issuer PK algorithm */
		result.readIssuerPkAlgorithm(buffer);
		/* read the issuer key length */
		result.readIssuerPkLength(buffer);
		/* read the issuer exponent length */
		result.readIssuerExponentLength(buffer);
		/* read the issuer key part */
		result.readIssuerKey(buffer);
		/* read the hash value */
		result.readHashSignature(buffer);
		/* read the end sentinel */
		result.readEndSentinel(buffer);

		result.setIssuerExponent(exponent);

		/* validate the hash value */
		int hashInputLength = 1 /* certificate format */ + ISSUER_IDENTIFIER_LENGTH + 2 + /* expiry date */
				CERTIFICATE_SERIAL_NO_LENGTH + 1 + /* hash algorithm */
				1 + /* PK algorithm */
				1 + /* PK length */
				1 + /* exponent length */
				result.getIssuerPkLength() + result.getIssuerExponentLength();

		byte[] hashInput = new byte[hashInputLength];

		System.arraycopy(fullKey, 1, hashInput, 0,
				result.getIssuerPkLength() + 7 + ISSUER_IDENTIFIER_LENGTH + CERTIFICATE_SERIAL_NO_LENGTH);

		/* write the exponent */
		ByteBuffer exponentBuffer = ByteBuffer.wrap( hashInput, hashInput.length - result.getIssuerExponentLength(), result.getIssuerExponentLength() );

		if (result.getIssuerExponentLength() == 1) {
			exponentBuffer.put( (byte) (0xFF & exponent) );
		}
		else {
			//TODO: test this
			exponentBuffer.put( (byte) (0xFF & (exponent >> 16) ));
			exponentBuffer.put( (byte) (0xFF & (exponent >> 8) ));
			exponentBuffer.put( (byte) (0xFF & exponent ));
		}

		log.finest("Hash input: " + IO.printByteArray(hashInput));
		byte[] hashOutput = MessageAuthenticationAlgorithms.computeSHA1(hashInput);
		log.finest("Hash Output: " + IO.printByteArray(hashOutput));

		/* compare the computed hash with the provided one */
		if (!Arrays.equals(hashOutput, result.getHashSignature()))
		{
			log.warning("The provided signature " + IO.printByteArray(result.getHashSignature() ) + " doesn't match the computed signature " + IO.printByteArray(hashOutput) );
			throw new SignatureException("The provided SHA-1 signature doesn't match the recovered one");
		}
		return result;

	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();

		builder.append(IO.SEPARATOR).append('\n').append("Issuer key\n").append(IO.SEPARATOR).append('\n');
		builder.append("\tCA PK ID               : ").append(String.format("%02X", this.caKey.getIndex())).append('\n');
		builder.append("\tSentinel               : ").append(String.format("%02X", this.getStartSentinel()))
				.append('\n');
		builder.append("\tCertificate format     : ").append(String.format("%02X", this.getCertificateFormat()))
				.append('\n');
		builder.append("\tIssuer identifier      : ")
				.append(IO.printByteArray(this.getTrimmedIssuerIdentifier(), "", false)).append('\n');
		builder.append("\tExpiry date            : ")
				.append(String.format("%02X/%02X", this.getValidUntilMonth(), this.getValidUntilYear())).append('\n');
		builder.append("\tCertificate number     : ").append(IO.printByteArray(this.getCertificateSerial(), "", false))
				.append('\n');
		builder.append("\tHash algorithm         : ").append(
				String.format("%02X (%s)", this.getHashAlgorithm(), HASH_ALGORITHMS.get(this.getHashAlgorithm())))
				.append('\n');
		builder.append("\tPK algorithm           : ").append(
				String.format("%02X (%s)", this.getIssuerPkAlgorithm(), PK_ALGORITHMS.get(this.getIssuerPkAlgorithm())))
				.append('\n');
		builder.append("\tIssuer PK length       : ").append(String.format("%d", ((int) issuerPkLength) & 0xFF))
				.append('\n');
		builder.append("\tIssuer exponent length : ")
				.append(String.format("%d", ((int) this.getIssuerExponentLength()) & 0xFF)).append('\n');
		builder.append("\tIssuer exponent        : ").append(String.format("%04X", this.getIssuerExponent()))
				.append('\n');
		builder.append("\tIssuer key:\n").append(IO.printByteArray(getIssuerPublicKey(), "\t\t", true)).append('\n');
		builder.append("\tHash signature         : ").append(IO.printByteArray(getHashSignature(), "", false));
		builder.append("\tSentinel               : ").append(String.format("%02X", this.getEndSentinel())).append('\n');

		builder.append(IO.SEPARATOR).append('\n');
		return builder.toString();
	}
}
