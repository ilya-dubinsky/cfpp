package org.ilyadubinsky.cfpp.emv;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.ilyadubinsky.cfpp.utils.IO;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

/**
 * Validates the SDA value, recovers the issuer authentication value, and
 * confirms the hash signature. See {@link EMVRecoverable}.
 * 
 * @author idubinsky
 *
 */
public class EMVSDACertificate extends EMVRecoverable {

	private static final int ISSUER_AUTH_CODE_LENGTH = 2;

	private final static byte SDA_CERTIFICATE_FORMAT = 0x03;

	/**
	 * Recover the SDA data and validate the hash signature. See
	 * {@link EMVRecoverable#doRecoverData(EMVRecoverable, EMVKeyPair, byte[], byte[], byte[])}.
	 * 
	 * @param issuerPublicKey Issuer public key used for the certificate.
	 * @param certificate     Certificate to decipher.
	 * @param extraData       Extra data for static authentication.
	 * @return Instantiated object that encapsulates the issuer auth data and is
	 *         validated.
	 * 
	 * @throws IllegalArgumentException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws SignatureException
	 */
	public static EMVSDACertificate recoverKey(IssuerPublicKey issuerPublicKey, @NonNull byte[] certificate,
			byte[] extraData)
			throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		/* instantiate a new object */

		EMVSDACertificate result = new EMVSDACertificate();

		result.setExtraData(extraData);

		return (EMVSDACertificate) doRecoverData(result, issuerPublicKey, certificate, null, extraData);
	}

	/**
	 * Extra authentication data for the SDA, as provided separately from the certificate.
	 */
	@Getter
	@Setter(AccessLevel.PACKAGE)
	private byte[] extraData;

	/** 
	 * Issuer authentication code, as retrieved from the certificate.
	 */
	@Getter
	@Setter(AccessLevel.PACKAGE)
	private byte[] issuerAuthCode;

	@Override
	/**  {@inheritDoc} */
	protected void doReadCertificate(ByteBuffer fromBuffer) {
		/* read the hash algorithm */
		readHashAlgorithm(fromBuffer);

		/* read issuer auth code */
		readIssuerAuthCode(fromBuffer);

		/* skip the rest of the padding */
		skipPadding(fromBuffer);
	}

	@Override
	/** {@inheritDoc } */
	protected int getExtraDataSize() {
		if (null == extraData)
			return 0;
		return extraData.length;
	}

	@Override
	/** {@inheritDoc } */
	protected int getOverheadSize() {
		return HASH_VALUE_LENGTH + 2 /* sentinels */ + 4 /* certificate, hash algorithm and 2 bytes of issuer code */;
	}

	protected void readIssuerAuthCode(ByteBuffer fromBuffer) {
		this.issuerAuthCode = new byte[ISSUER_AUTH_CODE_LENGTH];
		fromBuffer.get(issuerAuthCode);
	}

	@Override
	/** Validates the certificate format value as recovered from the certificate. */
	protected void validateCertificateFormat() {
		if (SDA_CERTIFICATE_FORMAT != certificateFormat)
			throw new UnsupportedOperationException(
					String.format("Unsupported certificate format: %2X", certificateFormat));
	}

	@Override
	/** {@inheritDoc } */
	protected void writeExtraData(ByteBuffer extraDataBuffer) {
		extraDataBuffer.put(this.extraData);
	}

	@Override
	/** {@inheritDoc } */
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getParentKey().toString());

		builder.append(IO.SEPARATOR).append('\n').append("SDA").append(IO.SEPARATOR).append('\n');

		builder.append("\tSentinel               : ").append(String.format("%02X", this.getStartSentinel()))
				.append('\n');
		builder.append("\tCertificate format     : ").append(String.format("%02X", this.getCertificateFormat()))
				.append('\n');
		builder.append("\tHash algorithm         : ").append(
				String.format("%02X (%s)", this.getHashAlgorithm(), HASH_ALGORITHMS.get(this.getHashAlgorithm())))
				.append('\n');
		builder.append("\tIssuer auth code       : ").append(IO.printByteArray(issuerAuthCode)).append('\n');
		builder.append("\tHash signature:\n").append(IO.printByteArray(getHashSignature(), "\t\t", false));
		builder.append("\tSentinel               : ").append(String.format("%02X", this.getEndSentinel())).append('\n');

		builder.append(IO.SEPARATOR).append('\n');
		return builder.toString();
	}

}
