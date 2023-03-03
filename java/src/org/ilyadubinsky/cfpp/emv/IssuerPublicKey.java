package org.ilyadubinsky.cfpp.emv;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import lombok.NonNull;

public class IssuerPublicKey extends EMVRecoverableKey {

	private final static byte ISSUER_CERTIFICATE_FORMAT = 0x02;

	protected int getEntityIdentiferLength() {
		return ISSUER_IDENTIFIER_LENGTH;
	}

	@Override
	protected void validateCertificateFormat() throws UnsupportedOperationException {
		if (ISSUER_CERTIFICATE_FORMAT != certificateFormat)
			throw new UnsupportedOperationException(String.format("Unsupported certificate format: %2X", certificateFormat));
	}

	public static EMVRecoverableKey recoverKey(byte caPublicKeyIndex, @NonNull byte[] certificate, byte[] remainder,
			int exponent)
			throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		/* instantiate a new object */

		/* locate and set the CA */
		CertificateAuthorityKey caKey = CertificateAuthorityKey.getCAKey(caPublicKeyIndex);

		EMVRecoverableKey result = new IssuerPublicKey();
		return (EMVRecoverableKey) doRecoverKey(result, caKey, certificate, exponent, remainder);

	}

	protected String getEntityName() {
		return "Issuer";
	}

	@Override
	protected int getOverheadSize() {
		return 36; 
	}
}
