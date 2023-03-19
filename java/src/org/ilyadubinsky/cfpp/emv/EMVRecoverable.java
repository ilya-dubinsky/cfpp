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

@Log
public abstract class EMVRecoverable {

	protected static final byte SHA1_HASH_ALGORITHM = 0x01;
	protected static final byte RSA_PK_ALGORITHM = 0x01;

	protected static final Map<Byte, String> HASH_ALGORITHMS = new ConcurrentHashMap<Byte, String>();
	protected static final Map<Byte, String> PK_ALGORITHMS = new ConcurrentHashMap<Byte, String>();

	static {
		HASH_ALGORITHMS.put((byte) SHA1_HASH_ALGORITHM, "SHA-1");

		PK_ALGORITHMS.put((byte) RSA_PK_ALGORITHM, "RSA");
	}

	protected static final int HASH_VALUE_LENGTH = 20;

	protected static final byte START_SENTINEL = 0x6A;
	protected static final byte END_SENTINEL = (byte) 0xBC;

	protected static EMVRecoverable doRecoverData(EMVRecoverable result, EMVKeyPair parentKey, byte[] certificate, byte[] remainder, byte[] extraData)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {
			
				result.setParentKey(parentKey);
			
				byte[] decipheredData = AsymmetricAlgorithms.decryptRSA(certificate, result.getParentKey().getModulus(),
						result.getParentKey().getPublicExponent());
			
				byte[] fullKey = new byte[decipheredData.length + ((remainder != null) ? remainder.length : 0)];
				
				log.finest("Certificate   : \n" + IO.printByteArray(certificate, "\t", true));
				log.finest("Deciphered value: \n" + IO.printByteArray(decipheredData, "\t", true));
			
				/*
				 * the order is: deciphered certificate without the hash and the sentinel, remainder, hash,
				 * sentinel
				 */
				ByteBuffer writeBuffer = ByteBuffer.wrap(fullKey);
			
				/* deciphered certificate */
				writeBuffer.put(Arrays.copyOfRange(decipheredData, 0, decipheredData.length - HASH_VALUE_LENGTH - 1));
			
				/* remainder */
				if (remainder != null)
					writeBuffer.put(remainder);
			
				/* the hash value and the sentinel */
				writeBuffer.put(
						Arrays.copyOfRange(decipheredData, decipheredData.length - HASH_VALUE_LENGTH - 1, decipheredData.length));
						
				result.readData(fullKey);
			
				return result;
			}

	@Getter
	protected byte startSentinel;
	@Getter
	protected byte endSentinel;
	@Getter
	protected byte certificateFormat;
	@Getter
	protected byte hashAlgorithm;

	@Getter
	protected byte[] hashSignature;
	
	@Getter
	@Setter(AccessLevel.PACKAGE)
	protected EMVKeyPair parentKey;
	
	protected abstract void doReadData( ByteBuffer fromBuffer );
	
	/**
	 * Reads the start sentinel from the buffer
	 * 
	 * @param fromBuffer
	 */
	protected void readStartSentinel(ByteBuffer fromBuffer) {
		startSentinel = fromBuffer.get();
	
		if (START_SENTINEL != startSentinel)
			throw new IllegalArgumentException("Key start sentinel value is incorrect - wrong CA PKI or public key?");
	}
	protected void readEndSentinel(ByteBuffer fromBuffer) {
		this.endSentinel = fromBuffer.get();
	
		if (END_SENTINEL != endSentinel)
			throw new IllegalArgumentException("Key end sentinel value is incorrect ");
	}
	protected void readCertificateFormat(ByteBuffer fromBuffer) {
		certificateFormat = fromBuffer.get();
	
		validateCertificateFormat();
	}

	
	protected abstract void validateCertificateFormat();
	
	protected void readHashSignature(ByteBuffer fromBuffer) {
		this.hashSignature = new byte[HASH_VALUE_LENGTH];
	
		fromBuffer.get(hashSignature);
	}

	protected abstract int getExtraDataSize();

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

							doReadData(buffer);
							
							/* read the hash value */
							this.readHashSignature(buffer);
							/* read the end sentinel */
							this.readEndSentinel(buffer);
						
							// TODO: this is for keys, not for SDA/DDA
							/* determine if padding is required */
			//				int paddingLength = this.getParentCertificate().getModulus().length 
			//						- this.getOverheadSize() - this.getPayloadLength() ;
			//				if (paddingLength < 0)
			//					paddingLength = 0;
			
							/* validate the hash value */
							int extraDataLen = this.getExtraDataSize();
							
							int hashInputLength = this.getParentKey().getModulusLength()- HASH_VALUE_LENGTH - 2 /* sentinels */ + 
									extraDataLen;
							
			//				hashInputLength = 1 /* certificate format */ 
			//						+ getEntityIdentiferLength() 
			//						+ 2 /* expiry date */
			//						+ CERTIFICATE_SERIAL_NO_LENGTH 
			//						+ 1 /* hash algorithm */
			//						+ 1 /* PK algorithm */
			//						+ 1 /* PK length field */
			//						+ 1 /* exponent length field */
			//						+ this.getPayloadLength()
			//						+ paddingLength
			//						+ this.getPublicExponentLength();
											
							byte[] hashInput = new byte[hashInputLength];
							
			//				log.finest("fullKey: \n" + IO.printByteArray(fullKey));
							
			//				log.finest("full key len: " + fullKey.length + " hashInput len: " + hashInputLength);
							
				
							System.arraycopy(fullKey, 1, hashInput, 0, hashInputLength - extraDataLen);
						
							/* write the exponent */
							ByteBuffer extraDataBuffer = ByteBuffer.wrap(hashInput, hashInput.length - extraDataLen,
									extraDataLen);
							
							writeExtraData(extraDataBuffer);
						
							log.finest("Hash input: \n" + IO.printByteArray(hashInput));
							byte[] hashOutput = MessageAuthenticationAlgorithms.computeSHA1(hashInput);
			//				log.finest("Hash Output: \n" + IO.printByteArray(hashOutput));
						
							/* compare the computed hash with the provided one */
							if (!Arrays.equals(hashOutput, this.getHashSignature())) {
								log.warning("The provided signature " + IO.printByteArray(this.getHashSignature())
										+ " doesn't match the computed signature " + IO.printByteArray(hashOutput));
								throw new SignatureException("The provided SHA-1hr signature doesn't match the recovered one");
							}
						
						}

	protected abstract void writeExtraData (ByteBuffer buffer);
	
	public void readHashAlgorithm(ByteBuffer fromBuffer) {
		hashAlgorithm = fromBuffer.get();
	
		if (!HASH_ALGORITHMS.containsKey(hashAlgorithm))
			throw new UnsupportedOperationException(String.format("Unsupported hash algorithm value: %2X", hashAlgorithm));
	}

	protected abstract int getOverheadSize();

}
