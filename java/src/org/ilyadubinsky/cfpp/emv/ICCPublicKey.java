package org.ilyadubinsky.cfpp.emv;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import lombok.NonNull;

public class ICCPublicKey extends EMVRecoverableKey {

	private final static byte ICC_CERTIFICATE_FORMAT = 0x04;

	
	public static ICCPublicKey recoverKey(EMVRecoverableKey issuerKey, @NonNull byte[] certificate, byte[] remainder,
			int exponent)
			throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {

		/* instantiate a new object */
		EMVRecoverableKey result = new ICCPublicKey();

		return (ICCPublicKey) doRecoverKey(result, issuerKey, certificate, exponent, remainder);

	}

	@Override
	protected void validateCertificateFormat() {
		if (ICC_CERTIFICATE_FORMAT != certificateFormat)
			throw new UnsupportedOperationException(String.format("Unsupported certificate format: %2X", certificateFormat));
	}

	@Override
	protected int getEntityIdentiferLength() {
		return 10;
	}

	@Override
	protected String getEntityName() {
		return "   ICC";
	}

	@Override
	protected int getOverheadSize() {
		return 42;
	}

}
