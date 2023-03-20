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
 * 
 * Validates the DDA value, recovers the ICC dynamic data, and confirms the hash
 * signature. See {@link EMVRecoverable}.
 * 
 * @author idubinsky
 *
 */
public class EMVDDACertificate extends EMVRecoverable {

	private final static byte DDA_CERTIFICATE_FORMAT = 0x05;

	/**
	 * 
	 * Recover the ICC dynamic data and validate the hash signature. See
	 * {@link EMVRecoverable#doRecoverData(EMVRecoverable, EMVKeyPair, byte[], byte[], byte[])}.
	 * 
	 * @param iccPublicKey ICC public key.
	 * @param certificate  Certificate from which to recover the key.
	 * @param ddol         Data object list for signature validation.
	 * @return Instantiated object that encapsulates the ICC dynamic data and is
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
	public static EMVDDACertificate recoverKey(ICCPublicKey iccPublicKey, @NonNull byte[] certificate, byte[] ddol)
			throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		/* instantiate a new object */

		EMVDDACertificate result = new EMVDDACertificate();

		result.setDdol(ddol);

		return (EMVDDACertificate) doRecoverData(result, iccPublicKey, certificate, null, ddol);
	}

	/** Extra data as specified by the DDOL. Used for hash validation. */
	@Getter
	@Setter(AccessLevel.PACKAGE)
	private byte[] ddol;

	/**
	 * ICC dynamic data as recovered from the certificate.
	 */
	@Getter
	@Setter(AccessLevel.PACKAGE)
	private byte[] iccDynamicData;

	/**
	 * ICC dynamic data length as recovered from the certificate.
	 */
	@Getter
	@Setter(AccessLevel.PACKAGE)
	private byte iccDynamicDataLength;

	@Override
	/** {@inheritDoc } */
	protected void doReadCertificate(ByteBuffer fromBuffer) {
		readHashAlgorithm(fromBuffer);

		readICCDynamicDataLength(fromBuffer);
		readICCDynamicData(fromBuffer);

		skipPadding(fromBuffer);
	}

	@Override
	/** {@inheritDoc } */
	protected int getExtraDataSize() {
		if (null == ddol)
			return 0;
		return ddol.length;
	}

	@Override
	/** {@inheritDoc } */
	protected int getOverheadSize() {
		return HASH_VALUE_LENGTH + 2 /* sentinels */ + 2 /* certificate format and hash algorihtm */
				+ 1 /* L_DD */ + getIccDynamicDataLength();
	}

	/**
	 * Reads the ICC dynamic data.
	 * 
	 * @param fromBuffer Buffer from which to read the data.
	 */
	protected void readICCDynamicData(ByteBuffer fromBuffer) {
		this.iccDynamicData = new byte[this.iccDynamicDataLength];
		fromBuffer.get(this.iccDynamicData);
	}

	/**
	 * Reads the ICC dynamic data length.
	 * 
	 * @param fromBuffer Buffer from which to read the data.
	 */
	protected void readICCDynamicDataLength(ByteBuffer fromBuffer) {
		this.iccDynamicDataLength = fromBuffer.get();
	}

	@Override
	/** Validates the certificate format value as recovered from the certificate. */
	protected void validateCertificateFormat() {
		if (DDA_CERTIFICATE_FORMAT != certificateFormat)
			throw new UnsupportedOperationException(
					String.format("Unsupported certificate format: %2X", certificateFormat));
	}

	@Override
	/** {@inheritDoc } */
	protected void writeExtraData(ByteBuffer buffer) {
		buffer.put(ddol);
	}

	@Override
	/** {@inheritDoc } */
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getParentKey().toString());

		builder.append(IO.SEPARATOR).append('\n').append("DDA").append(IO.SEPARATOR).append('\n');

		builder.append("\tSentinel               : ").append(String.format("%02X", this.getStartSentinel()))
				.append('\n');
		builder.append("\tCertificate format     : ").append(String.format("%02X", this.getCertificateFormat()))
				.append('\n');
		builder.append("\tHash algorithm         : ").append(
				String.format("%02X (%s)", this.getHashAlgorithm(), HASH_ALGORITHMS.get(this.getHashAlgorithm())))
				.append('\n');
		builder.append("\tICC dynamic data length: ").append(String.format("%2d", this.getIccDynamicDataLength()))
				.append('\n');
		builder.append("\tICC dynamic data       : ").append(IO.printByteArray(iccDynamicData)).append('\n');
		builder.append("\tHash signature:\n").append(IO.printByteArray(getHashSignature(), "\t\t", false));
		builder.append("\tSentinel               : ").append(String.format("%02X", this.getEndSentinel())).append('\n');

		builder.append(IO.SEPARATOR).append('\n');
		return builder.toString();
	}
}
