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

public class EMVStaticDataCertificate extends EMVRecoverable {
	
	private final static byte SDA_CERTIFICATE_FORMAT = 0x03;

	private static final int ISSUER_AUTH_CODE_LENGTH = 2;
	
	@Getter
	@Setter(AccessLevel.PACKAGE)
	private byte[] extraData;

	@Getter
	@Setter(AccessLevel.PACKAGE)
	private byte[] issuerAuthCode;
	
	@Override
	protected void validateCertificateFormat() {
		if (SDA_CERTIFICATE_FORMAT != certificateFormat)
			throw new UnsupportedOperationException(String.format("Unsupported certificate format: %2X", certificateFormat));
	}

	public static EMVStaticDataCertificate recoverKey(IssuerPublicKey issuerPublicKey, @NonNull byte[] certificate, byte[] extraData)
			throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		/* instantiate a new object */

		EMVStaticDataCertificate result = new EMVStaticDataCertificate();
		
		result.setExtraData(extraData);
		
		return (EMVStaticDataCertificate) doRecoverData(result, issuerPublicKey, certificate, null, extraData);

	}

	@Override
	protected void doReadData(ByteBuffer fromBuffer) {
		/* read the hash algorithm */
		readHashAlgorithm(fromBuffer);
		
		/* read issuer auth code */
		readIssuerAuthCode(fromBuffer);
		
		/* skip the rest of the padding */
		int payloadSize = this.getParentKey().getModulusLength() - this.getOverheadSize();
		
		for (int i = 0; i<payloadSize; i++)
			fromBuffer.get();
	}

	protected void readIssuerAuthCode(ByteBuffer fromBuffer) {
		this.issuerAuthCode = new byte[ ISSUER_AUTH_CODE_LENGTH ];
		fromBuffer.get(issuerAuthCode);
	}

	@Override
	protected int getExtraDataSize() {
		if (null == extraData)
			return 0;
		return extraData.length;
	}

	@Override
	protected void writeExtraData(ByteBuffer extraDataBuffer) {
		extraDataBuffer.put(this.extraData);
	}

	@Override
	protected int getOverheadSize() {
		return HASH_VALUE_LENGTH + 2 /* sentinels */ + 4 /* certificate, hash algorithm and 2 bytes of issuer code */;
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getParentKey().toString());
	
		builder.append(IO.SEPARATOR).append('\n').append("SDA").append(" key\n").append(IO.SEPARATOR).append('\n');
	
		if (this.getParentKey() instanceof CertificateAuthorityKey) {
			CertificateAuthorityKey caKey = (CertificateAuthorityKey) this.getParentKey();
			builder.append("\tCA PK ID               : ").append(String.format("%02X", caKey.getIndex())).append('\n');
		}
		
		builder.append("\tSentinel               : ").append(String.format("%02X", this.getStartSentinel()))
				.append('\n');
		builder.append("\tCertificate format     : ").append(String.format("%02X", this.getCertificateFormat()))
				.append('\n');
		builder.append("\tHash algorithm         : ").append(
				String.format("%02X (%s)", this.getHashAlgorithm(), HASH_ALGORITHMS.get(this.getHashAlgorithm())))
				.append('\n');
		builder.append("\tIssuer auth code       : ")
				.append(IO.printByteArray(issuerAuthCode))
				.append('\n');
		builder.append("\tHash signature:\n").append(IO.printByteArray(getHashSignature(), "\t\t", false));
		builder.append("\tSentinel               : ").append(String.format("%02X", this.getEndSentinel())).append('\n');
	
		builder.append(IO.SEPARATOR).append('\n');
		return builder.toString();
	}

}
