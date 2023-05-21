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
 * Recovers the issuer public key from a key certificate, validates the parsed
 * values and confirms the hash signature. See {@link EMVRecoverable} and
 * {@link EMVRecoverableKey}.
 * 
 * @author idubinsky
 *
 */
public class IssuerPublicKey extends EMVRecoverableKey {

	private final static byte ISSUER_CERTIFICATE_FORMAT = 0x02;

	private final static int ISSUER_IDENTIFIER_LENGTH = 4;
	private static final long serialVersionUID = -8975856968565558785L;

	/**
	 * Recovers the issuer public key from the certificate. Instantiates the object,
	 * updates the public exponent, then invokes
	 * {@link EMVRecoverable#doRecoverData(EMVRecoverable, EMVKeyPair, byte[], byte[], byte[])}.
	 * 
	 * @param caPublicKeyIndex Index of the CA public key.
	 * @param certificate      The certificate.
	 * @param remainder        Issuer public key remainder, if available.
	 * @param exponent         Issuer public key exponent.
	 * @return Instantiated and validated issuer key, as recovered from the
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
	public static EMVRecoverable recoverKey(byte caPublicKeyIndex, @NonNull byte[] certificate, byte[] remainder,
			int exponent)
			throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		/* instantiate a new object */

		/* locate and set the CA */
		CertificateAuthorityKey caKey = CertificateAuthorityKey.getCAKey(caPublicKeyIndex);
		
		EMVRecoverableKey result = new IssuerPublicKey();

		result.setPublicExponent(exponent);

		return (EMVRecoverable) doRecoverData(result, caKey, certificate, remainder, null);
	}

	@Override
	/** {@inheritDoc} */
	protected int getEntityIdentiferLength() {
		return ISSUER_IDENTIFIER_LENGTH;
	}

	@Override
	/** {@inheritDoc} */
	protected String getEntityName() {
		return "Issuer";
	}

	@Override
	/** {@inheritDoc} */
	protected int getExtraDataSize() {
		return this.getPublicExponentLength();
	}

	@Override
	/** {@inheritDoc} */
	protected int getOverheadSize() {
		return 36;
	}

	@Override
	/** Validates the certificate format value as recovered from the certificate. */
	protected void validateCertificateFormat() throws UnsupportedOperationException {
		if (ISSUER_CERTIFICATE_FORMAT != certificateFormat)
			throw new UnsupportedOperationException(
					String.format("Unsupported certificate format: %2X", certificateFormat));
	}

}
