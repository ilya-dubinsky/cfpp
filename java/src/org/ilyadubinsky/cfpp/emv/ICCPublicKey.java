package org.ilyadubinsky.cfpp.emv;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import lombok.NonNull;

/**
 * Recovers the ICC public key from a key certificate, validates the parsed
 * values and confirms the hash signature. See {@link EMVRecoverable} and
 * {@link EMVRecoverableKey}.
 * 
 * @author idubinsky
 *
 */
public class ICCPublicKey extends EMVRecoverableKey {

	private final static byte ICC_CERTIFICATE_FORMAT = 0x04;
	private static final long serialVersionUID = 8405019478995693551L;

	/**
	 * 
	 * Recovers the ICC public key from the certificate. Instantiates the object,
	 * updates the public exponent, then invokes
	 * {@link EMVRecoverable#doRecoverData(EMVRecoverable, EMVKeyPair, byte[], byte[], byte[])}.
	 * 
	 * @param issuerKey   Issuer public key.
	 * @param certificate Certificate from which to recover the ICC key.
	 * @param remainder   Key remainder, if available.
	 * @param exponent    Key exponent.
	 * @return Instantiated and validated ICC key, as recovered from the
	 *         certificate.
	 * @throws IllegalArgumentException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws SignatureException
	 */
	public static ICCPublicKey recoverKey(EMVKeyPair issuerKey, @NonNull byte[] certificate, byte[] remainder,
			int exponent)
			throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {

		/* instantiate a new object */
		EMVRecoverableKey result = new ICCPublicKey();
		result.setPublicExponent(exponent);

		return (ICCPublicKey) doRecoverData(result, issuerKey, certificate, remainder, null);

	}

	@Override
	/** {@inheritDoc } */
	protected int getEntityIdentiferLength() {
		return 10;
	}

	@Override
	/** {@inheritDoc } */
	protected String getEntityName() {
		return "   ICC";
	}

	@Override
	/** {@inheritDoc } */
	protected int getExtraDataSize() {
		return this.getPublicExponentLength();
	}

	@Override
	/** {@inheritDoc } */
	protected int getOverheadSize() {
		return 42;
	}

	/** Validates the certificate format value as recovered from the certificate. */
	@Override
	protected void validateCertificateFormat() {
		if (ICC_CERTIFICATE_FORMAT != certificateFormat)
			throw new UnsupportedOperationException(
					String.format("Unsupported certificate format: %2X", certificateFormat));
	}

}
