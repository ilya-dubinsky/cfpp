package org.ilyadubinsky.cfpp.emv;

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
import lombok.Setter;
import lombok.extern.java.Log;

/**
 * The class encapsulates all possible values that can be recovered during an
 * EMV interaction between the terminal and the card. There are two types of
 * certificates: those encapsulating keys (issuer and ICC public keys) and those
 * encapsulating other values, specifically, SDA and DDA.
 * 
 * The type hierarchy is as follows:
 * 
 * <pre>
	EMVRecoverable
	  |
	  +---EMVRecoverableKey
	  |     |
	  |     +---EMVSDACertificate
	  |     |
	  |     +---EMVDDACertificate
	  |
	  +---IssuerPublicKey
	  |
	  +---ICCPublicKey
 * </pre>
 * 
 * All certificates have common properties which are reflected in this class.
 * Specifically, all certificates are recovered as a result of public-key
 * decryption of the certificate value. All certificates contain same "sentinel"
 * values at the beginning and at the end of the decrypted certificate. All
 * certificates also carry an indication of the hash algorithm (which can be any
 * algorithm as long as it is SHA-1) and all certificates have the hash value
 * embedded at the end, immediately before the end sentinel.
 * 
 * The structure is reflected below.
 * 
 * <pre>
 * 
		      Cert           Hash
		      type           algo
		      code           code
		+----+----+---------+----+-------------+----+
		|    |    |         |    |             |    |
		| 6A | XX |  . . .  | 01 |    . . .    | BC |
		|    |    |         |    |             |    |
		+----+----+---------+----+-------------+----+
		Start       Other             Data      End
		senti-      header                      senti-
		nel         values                      nel
 * </pre>
 * 
 * @author idubinsky
 *
 */

@Log
public abstract class EMVRecoverable {

	protected static final byte END_SENTINEL = (byte) 0xBC;
	protected static final Map<Byte, String> HASH_ALGORITHMS = new ConcurrentHashMap<Byte, String>();

	protected static final int HASH_VALUE_LENGTH = 20;

	/* these static tables are used for readability only */
	protected static final Map<Byte, String> PK_ALGORITHMS = new ConcurrentHashMap<Byte, String>();
	protected static final byte RSA_PK_ALGORITHM = 0x01;

	protected static final byte SHA1_HASH_ALGORITHM = 0x01;
	protected static final byte START_SENTINEL = 0x6A;
	
	protected static final byte PADDING_VALUE = (byte) 0xBB;

	static {
		HASH_ALGORITHMS.put((byte) SHA1_HASH_ALGORITHM, "SHA-1");

		PK_ALGORITHMS.put((byte) RSA_PK_ALGORITHM, "RSA");
	}

	/**
	 * Decrypts the certificate, prepares the full data vector and invokes the
	 * {@link #readCertificate(byte[])} method to parse the data.
	 * 
	 * 
	 * When the data that needs to be encrypted by the private key is longer than
	 * its modulus, the EMV standard prescribes use of remainders. I.e., the portion
	 * of the (usually) key that didn't fit into the payload vector is provided
	 * separately and in the clear.
	 * 
	 * 
	 * To facilitate parsing, after the decryption, the remainder is placed inside
	 * the decrypted contents immediately before the hash signature.
	 * 
	 * <pre>
	+----+---------------------------------+--------------+----+    +------------------------+
	|    |                                 |              |    |    |                        |
	| 6A |           Contents              |     Hash     | BC |    |       Remainder        |
	|    |                                 |              |    |    |                        |
	+----+---------------------------------+--------------+----+    +------------------------+
	
	
	+----+----------------------------------+------------------------+--------------+----+
	|    |                                  |                        |              |    |
	| 6A |           Contents               |       Remainder        |     Hash     | BC |
	|    |                                  |                        |              |    |
	+----+----------------------------------+------------------------+--------------+----+
	 * </pre>
	 * 
	 * @param result      The EMVRecoverable object that will parse the data and
	 *                    will be returned by the method.
	 * @param parentKey   The parent key that will be used to decipher the
	 *                    certificate.
	 * @param certificate The certificate value to be deciphered and parsed.
	 * @param remainder   The remainder, if applicable.
	 * @param extraData   The extra data. The extra data is used to calculate the
	 *                    hash value. It is appended instead of the hash value and
	 *                    the trailing sentinel. The outcome, without the leading
	 *                    sentinel, is then fed to the hash function to calculate
	 *                    the independent signature.
	 * @return The object, with fields populated from the certificate and the
	 *         remainder.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws SignatureException
	 */
	protected static EMVRecoverable doRecoverData(EMVRecoverable result, EMVKeyPair parentKey, byte[] certificate,
			byte[] remainder, byte[] extraData)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {

		result.setParentKey(parentKey);
		result.setCertificate(certificate);
		result.setRemainder(remainder);

		byte[] decipheredData = AsymmetricAlgorithms.decryptRSA(certificate, result.getParentKey().getModulus(),
				result.getParentKey().getPublicExponent());

		byte[] fullKey = new byte[decipheredData.length + ((remainder != null) ? remainder.length : 0)];

		log.finest("Certificate   : \n" + IO.printByteArray(certificate, "\t", true));
		log.finest("Deciphered value: \n" + IO.printByteArray(decipheredData, "\t", true));

		/*
		 * the order is: deciphered certificate without the hash and the sentinel,
		 * remainder, hash, sentinel
		 */
		ByteBuffer writeBuffer = ByteBuffer.wrap(fullKey);

		/* deciphered certificate */
		writeBuffer.put(Arrays.copyOfRange(decipheredData, 0, decipheredData.length - HASH_VALUE_LENGTH - 1));

		/* remainder */
		if (remainder != null)
			writeBuffer.put(remainder);

		/* the hash value and the sentinel */
		writeBuffer.put(Arrays.copyOfRange(decipheredData, decipheredData.length - HASH_VALUE_LENGTH - 1,
				decipheredData.length));

		result.readCertificate(fullKey);

		return result;
	}

	/**
	 * Stores the certificate format, as read from the data.
	 */
	@Getter
	protected byte certificateFormat;
	/** Stores the end sentinel of the certificate. */
	@Getter
	protected byte endSentinel;

	/**
	 * Stores the hash algorithm, as read from the data.
	 */
	@Getter
	protected byte hashAlgorithm;

	/**
	 * Stores the hash signature, as read from the data.
	 */
	@Getter
	protected byte[] hashSignature;

	@Getter
	@Setter(AccessLevel.PACKAGE)
	protected EMVKeyPair parentKey;

	/**
	 * Stores the start sentinel of the certificate.
	 */
	@Getter
	protected byte startSentinel;
	
	
	/**
	 *  Stores the remainder of the certificate contents, if applicable.
	 */
	@Getter 
	@Setter(AccessLevel.PACKAGE)
	protected byte[] remainder;

	/**
	 * Stores the enciphered certificate.
	 */
	@Getter 
	@Setter(AccessLevel.PACKAGE)
	protected byte[] certificate;

	/**
	 * Reads the contents of the certificate from the buffer. The "contents" are
	 * recombined as described in {@link #readCertificate(byte[]). The start and end
	 * sentinels and the certificate format are read by the {@link EMVRecoverable}
	 * class, while the rest of the data must be read by the deriving class.
	 * 
	 * @param fromBuffer Byte buffer to read the data from.
	 */
	protected abstract void doReadCertificate(ByteBuffer fromBuffer);

	/**
	 * @return Returns the size of the extra data that will be used to calculate the
	 *         hash signature. Depending on type of the recovered object, this would
	 *         be either the public exponent, or some terminal/card specific data to
	 *         be signed. 
	 */
	protected abstract int getExtraDataSize();

	/**
	 * @return Returns the size of the "overhead", i.e. anything other than the
	 *         payload in the certificate. This would include, at least, the
	 *         sentinels, the hash signature, the certificate format and any other
	 *         fields. Padding is not considered overhead.
	 */
	protected abstract int getOverheadSize();

	/**
	 * Reads key data from the provided byte array, performing validation according
	 * to the specification. The data has, at this point, the following layout:
	 * 
	 * 
	 * <pre>
	+----+----------------------------------+------------------------+--------------+----+
	|    |                                  |                        |              |    |
	| 6A |           Contents               |       Remainder        |     Hash     | BC |
	|    |                                  |                        |              |    |
	+----+----------------------------------+------------------------+--------------+----+
	 * </pre>
	 * 
	 * After the data has been parsed, the hash signature has to be calculated
	 * independently, to be compared with the one recovered from the certificate.
	 * This is done by appending extra data to the payload and computing the hash.
	 * The hash input would look like follows:
	 * 
	 * <pre>
	     +----------------------------------+------------------------+------------+
	     |                                  |                        |            |
	     |           Contents               |       Remainder        | Extra data |
	     |                                  |                        |            |
	     +----------------------------------+------------------------+------------+
	 * </pre>
	 * 
	 * @param fullKey input byte array
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalArgumentException
	 * @throws SignatureException
	 */
	protected void readCertificate(byte[] fullKey)
			throws NoSuchAlgorithmException, IllegalArgumentException, SignatureException {
		ByteBuffer buffer = ByteBuffer.wrap(fullKey);

		this.readStartSentinel(buffer);

		this.readCertificateFormat(buffer);

		/* invoke the child class implementation for parsing of the rest of the data */
		doReadCertificate(buffer);

		/* read the hash value */
		this.readHashSignature(buffer);
		/* read the end sentinel */
		this.readEndSentinel(buffer);

		/* validate the hash value */
		byte[] hashOutput = computeHashSignature();
		
		/* compare the computed hash with the provided one */
		if (!Arrays.equals(hashOutput, this.getHashSignature())) {
			log.warning("The provided signature " + IO.printByteArray(this.getHashSignature())
					+ " doesn't match the computed signature " + IO.printByteArray(hashOutput));
			throw new SignatureException("The provided SHA-1 signature doesn't match the recovered one");
		}
	}
	
	protected byte[] computeHashSignature() throws NoSuchAlgorithmException, IllegalArgumentException {
		int hashInputSize = this.getParentKey().getModulusLength() 
								- 2 /* sentinels */ + getExtraDataSize() 
								- HASH_VALUE_LENGTH;
		
		byte[] hashInput = new byte[hashInputSize];
		Arrays.fill(hashInput, PADDING_VALUE);
		
		ByteBuffer hashBuffer = ByteBuffer.wrap(hashInput);
		
		hashBuffer.put(getCertificateFormat());
		/* write the header except the sentinel */
		writeHeader(hashBuffer);
		/* write the payload */
		writePayload(hashBuffer);
		/* the extra data */
		ByteBuffer extraDataBuffer = ByteBuffer.wrap(hashInput, hashInputSize - getExtraDataSize(), getExtraDataSize());
		writeExtraData(extraDataBuffer);
		
		log.finest("Hash input: \n" + IO.printByteArray(hashInput));
		byte[] hashOutput = MessageAuthenticationAlgorithms.computeSHA1(hashInput);
		log.finest("Hash Output: \n" + IO.printByteArray(hashOutput));

		return hashOutput;
		
	}
	
	protected abstract void writeHeader(ByteBuffer b);

	protected abstract void writePayload(ByteBuffer b);
	
	
	/**
	 * Reads the start sentinel from the buffer, validating its value.
	 * 
	 * @param fromBuffer
	 */
	protected void readStartSentinel(ByteBuffer fromBuffer) {
		startSentinel = fromBuffer.get();
		
		if (START_SENTINEL != startSentinel)
			throw new IllegalArgumentException("Key start sentinel value is incorrect - wrong CA PKI or public key?");
	}
	
	/**
	 * The method reads the certificate format, then invokes
	 * {@link #validateCertificateFormat()} to validate its value. It is invoked by
	 * this class during the parsing of the certificate.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readCertificateFormat(ByteBuffer fromBuffer) {
		certificateFormat = fromBuffer.get();

		validateCertificateFormat();
	}

	/**
	 * The method reads the hash algorithm indicator from the buffer and validates
	 * its value. It is not invoked by this class; the derived classes each invoke
	 * it to parse the hash algorithm value, since its exact position differs.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readHashAlgorithm(ByteBuffer fromBuffer) {
		hashAlgorithm = fromBuffer.get();

		if (!HASH_ALGORITHMS.containsKey(hashAlgorithm))
			throw new UnsupportedOperationException(
					String.format("Unsupported hash algorithm value: %2X", hashAlgorithm));
	}

	/**
	 * The method reads the hash signature. It is invoked by this class.
	 * @param fromBuffer
	 */
	protected void readHashSignature(ByteBuffer fromBuffer) {
		this.hashSignature = new byte[HASH_VALUE_LENGTH];

		fromBuffer.get(hashSignature);
	}

	/**
	 * The method reads the end sentinel and validates its value. It is invoked by
	 * this class during the parsing of the certificate.
	 * 
	 * @param fromBuffer Buffer from which to read the value.
	 */
	protected void readEndSentinel(ByteBuffer fromBuffer) {
		this.endSentinel = fromBuffer.get();
		
		if (END_SENTINEL != endSentinel)
			throw new IllegalArgumentException("Key end sentinel value is incorrect ");
	}
	
	/**
	 * This is the utility method to skip padding. It is used by some of the subclasses.
	 * @param fromBuffer Buffer in which the padding is.
	 */
	protected void skipPadding(ByteBuffer fromBuffer) {
		int payloadSize = this.getParentKey().getModulusLength() - this.getOverheadSize();

		for (int i = 0; i < payloadSize; i++)
			fromBuffer.get();
	}

	/**
	 * The method validates the certificate format, throwing an exception if its
	 * value doesn't match the expected one. It is implemented by subclasses of this
	 * class.
	 */
	protected abstract void validateCertificateFormat();

	/**
	 * The method writes the extra data to the given buffer. Depending on the
	 * implementation, this can be either the public exponent (taking either 1 or 3
	 * bytes), or a DOL.
	 * 
	 * @param buffer Buffer to which the extra data is written.
	 */
	protected abstract void writeExtraData(ByteBuffer buffer);

	protected void writeHashAlgorithm(ByteBuffer b) {
		b.put(SHA1_HASH_ALGORITHM);
	}

}
