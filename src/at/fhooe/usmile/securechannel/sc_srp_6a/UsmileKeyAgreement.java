package at.fhooe.usmile.securechannel.sc_srp_6a;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;


/**
 * 
 * @author endalkachew.asnake
 *
 */
public class UsmileKeyAgreement {

	/**
	 *  the size of final key
	 */
	private static final short LENGTH_KEY = 0x20;
	/**
	 * size of the SRP modulus
	 */
	private final static short LENGTH_MODULUS = (short) 0x100;
	private final static short OUTPUT_OFFSET_1 = (short) 0x100;
	private final static short OUTPUT_OFFSET_2 = (short) 0x200;
 
	private MessageDigest msgDigest_SHA256;
	private final static short LENGTH_MESSAGE_DIGEST = 0x20;

	private final static short LENGTH_IV = (short)0x10;
	private final static short OFFSET_IV = (short)0x20;
	private RandomData rng;

	private Cipher rsaCipher;
	private RSAPublicKey rsaPublicKey;
	private RSAPublicKey rsaPublicKey_forSquareMul;

	byte[] tempBuffer;
	private static byte[] kv;
	private static byte[] v;
	private static byte[] salt;
	// a temporary storage for public parameter of the card
	 private static byte[] B;

	 private static final short OFFSET_u = 0x300;
	 private static final short OFFSET_b = 0x320;
	 static final byte g = 0x02;
	private static final byte[] N = new byte[] { (byte) 0xAC, (byte) 0x6B,
			(byte) 0xDB, (byte) 0x41, (byte) 0x32, (byte) 0x4A, (byte) 0x9A,
			(byte) 0x9B, (byte) 0xF1, (byte) 0x66, (byte) 0xDE, (byte) 0x5E,
			(byte) 0x13, (byte) 0x89, (byte) 0x58, (byte) 0x2F, (byte) 0xAF,
			(byte) 0x72, (byte) 0xB6, (byte) 0x65, (byte) 0x19, (byte) 0x87,
			(byte) 0xEE, (byte) 0x07, (byte) 0xFC, (byte) 0x31, (byte) 0x92,
			(byte) 0x94, (byte) 0x3D, (byte) 0xB5, (byte) 0x60, (byte) 0x50,
			(byte) 0xA3, (byte) 0x73, (byte) 0x29, (byte) 0xCB, (byte) 0xB4,
			(byte) 0xA0, (byte) 0x99, (byte) 0xED, (byte) 0x81, (byte) 0x93,
			(byte) 0xE0, (byte) 0x75, (byte) 0x77, (byte) 0x67, (byte) 0xA1,
			(byte) 0x3D, (byte) 0xD5, (byte) 0x23, (byte) 0x12, (byte) 0xAB,
			(byte) 0x4B, (byte) 0x03, (byte) 0x31, (byte) 0x0D, (byte) 0xCD,
			(byte) 0x7F, (byte) 0x48, (byte) 0xA9, (byte) 0xDA, (byte) 0x04,
			(byte) 0xFD, (byte) 0x50, (byte) 0xE8, (byte) 0x08, (byte) 0x39,
			(byte) 0x69, (byte) 0xED, (byte) 0xB7, (byte) 0x67, (byte) 0xB0,
			(byte) 0xCF, (byte) 0x60, (byte) 0x95, (byte) 0x17, (byte) 0x9A,
			(byte) 0x16, (byte) 0x3A, (byte) 0xB3, (byte) 0x66, (byte) 0x1A,
			(byte) 0x05, (byte) 0xFB, (byte) 0xD5, (byte) 0xFA, (byte) 0xAA,
			(byte) 0xE8, (byte) 0x29, (byte) 0x18, (byte) 0xA9, (byte) 0x96,
			(byte) 0x2F, (byte) 0x0B, (byte) 0x93, (byte) 0xB8, (byte) 0x55,
			(byte) 0xF9, (byte) 0x79, (byte) 0x93, (byte) 0xEC, (byte) 0x97,
			(byte) 0x5E, (byte) 0xEA, (byte) 0xA8, (byte) 0x0D, (byte) 0x74,
			(byte) 0x0A, (byte) 0xDB, (byte) 0xF4, (byte) 0xFF, (byte) 0x74,
			(byte) 0x73, (byte) 0x59, (byte) 0xD0, (byte) 0x41, (byte) 0xD5,
			(byte) 0xC3, (byte) 0x3E, (byte) 0xA7, (byte) 0x1D, (byte) 0x28,
			(byte) 0x1E, (byte) 0x44, (byte) 0x6B, (byte) 0x14, (byte) 0x77,
			(byte) 0x3B, (byte) 0xCA, (byte) 0x97, (byte) 0xB4, (byte) 0x3A,
			(byte) 0x23, (byte) 0xFB, (byte) 0x80, (byte) 0x16, (byte) 0x76,
			(byte) 0xBD, (byte) 0x20, (byte) 0x7A, (byte) 0x43, (byte) 0x6C,
			(byte) 0x64, (byte) 0x81, (byte) 0xF1, (byte) 0xD2, (byte) 0xB9,
			(byte) 0x07, (byte) 0x87, (byte) 0x17, (byte) 0x46, (byte) 0x1A,
			(byte) 0x5B, (byte) 0x9D, (byte) 0x32, (byte) 0xE6, (byte) 0x88,
			(byte) 0xF8, (byte) 0x77, (byte) 0x48, (byte) 0x54, (byte) 0x45,
			(byte) 0x23, (byte) 0xB5, (byte) 0x24, (byte) 0xB0, (byte) 0xD5,
			(byte) 0x7D, (byte) 0x5E, (byte) 0xA7, (byte) 0x7A, (byte) 0x27,
			(byte) 0x75, (byte) 0xD2, (byte) 0xEC, (byte) 0xFA, (byte) 0x03,
			(byte) 0x2C, (byte) 0xFB, (byte) 0xDB, (byte) 0xF5, (byte) 0x2F,
			(byte) 0xB3, (byte) 0x78, (byte) 0x61, (byte) 0x60, (byte) 0x27,
			(byte) 0x90, (byte) 0x04, (byte) 0xE5, (byte) 0x7A, (byte) 0xE6,
			(byte) 0xAF, (byte) 0x87, (byte) 0x4E, (byte) 0x73, (byte) 0x03,
			(byte) 0xCE, (byte) 0x53, (byte) 0x29, (byte) 0x9C, (byte) 0xCC,
			(byte) 0x04, (byte) 0x1C, (byte) 0x7B, (byte) 0xC3, (byte) 0x08,
			(byte) 0xD8, (byte) 0x2A, (byte) 0x56, (byte) 0x98, (byte) 0xF3,
			(byte) 0xA8, (byte) 0xD0, (byte) 0xC3, (byte) 0x82, (byte) 0x71,
			(byte) 0xAE, (byte) 0x35, (byte) 0xF8, (byte) 0xE9, (byte) 0xDB,
			(byte) 0xFB, (byte) 0xB6, (byte) 0x94, (byte) 0xB5, (byte) 0xC8,
			(byte) 0x03, (byte) 0xD8, (byte) 0x9F, (byte) 0x7A, (byte) 0xE4,
			(byte) 0x35, (byte) 0xDE, (byte) 0x23, (byte) 0x6D, (byte) 0x52,
			(byte) 0x5F, (byte) 0x54, (byte) 0x75, (byte) 0x9B, (byte) 0x65,
			(byte) 0xE3, (byte) 0x72, (byte) 0xFC, (byte) 0xD6, (byte) 0x8E,
			(byte) 0xF2, (byte) 0x0F, (byte) 0xA7, (byte) 0x11, (byte) 0x1F,
			(byte) 0x9E, (byte) 0x4A, (byte) 0xFF, (byte) 0x73 };

	 
	private final static byte LENGTH_SALT = 0x10;

	final static byte[] squareExponent = new byte[] { 0x02 };

	/**
	 * Constructors
	 * 
	 * <p>
	 * Performs necessary initialization and memory allocations 
	 * 
	 * @param initBuffer initialization byte array buffer, contains identity':'password
	 * 
	 */
	public UsmileKeyAgreement(byte[] initBuffer, short length) {

		tempBuffer = initBuffer;

		/**
		 * init messageDigest
		 */
		msgDigest_SHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256,
				false);
		/**
		 * init random data generator
		 */
		rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);


		rsaPublicKey = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);

		rsaPublicKey_forSquareMul = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
		rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

		rsaPublicKey_forSquareMul.setExponent(squareExponent, (short) 0x00,
				(short) 0x01);

		/**
		 * set public key modulus
		 */
		rsaPublicKey_forSquareMul.setModulus(N, (short) 0x00, LENGTH_MODULUS);

		rsaPublicKey.setModulus(N, (short) 0x00, LENGTH_MODULUS);

		/**
		 * v and KV are should be computed here from SRP 6a v = g^X X = H (salt,
		 * H(identity':'password)) .... from bouncy castle SRP 6a API K = H(N,
		 * g) ... g.. padded with leading 0s
		 */
		v = new byte[(short) 0x100];
		kv = new byte[(short) 0x100];
		salt = new byte[(short) 0x10];
		B = new byte[(short) 0x100];

		staticComputations(length);

	}
	
	/**
	 * Computes/generates Applet side parameters that are static (session independent)
	 * This values are salt, k and kv
	 * Called during from the constructor of this class (at Applet installation) 
	 * and for changing the secure channel password and/or user ID
	 */
	public void staticComputations(short length){
		/**
		 * generate salt
		 */
		rng.generateData(salt, (short) 0x00, LENGTH_SALT);

		/**
		 * compute X = H (salt, H(identity':'password))
		 */
		msgDigest_SHA256.doFinal(tempBuffer, (short) 0x00, length, tempBuffer,
				OUTPUT_OFFSET_2);
		msgDigest_SHA256.update(salt, (short) 0x00, LENGTH_SALT);
		msgDigest_SHA256.doFinal(tempBuffer, OUTPUT_OFFSET_2,
				LENGTH_MESSAGE_DIGEST, tempBuffer, OUTPUT_OFFSET_2);

		/**
		 * compute v = g^X
		 * 
		 */
		rsaPublicKey.setExponent(tempBuffer, OUTPUT_OFFSET_2, (short) 0x20);
		rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
		Util.arrayFillNonAtomic(tempBuffer, (short) 0x00, (short) 0x200,
				(byte) 0x00);
		tempBuffer[(short) 0xff] = g;
		rsaCipher.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS, v,
				(short) 0x00);

		/**
		 * compute K = H(N, g)
		 */
		msgDigest_SHA256.update(N, (short) 0x00, LENGTH_MODULUS);
		msgDigest_SHA256.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS,
				tempBuffer, (short) (OUTPUT_OFFSET_2 - 0x20));

		/**
		 * compute KV save copy of V in KV because v and tempBuffer are subject
		 * to change
		 */
		Util.arrayCopy(v, (short) 0x00, kv, (short) 0x00, LENGTH_MODULUS);
		modMultiply(v, (short) 0x00, LENGTH_MODULUS, tempBuffer,
				OUTPUT_OFFSET_1, LENGTH_MODULUS);
		Util.arrayCopy(kv, (short) 0x00, v, (short) 0x00, LENGTH_MODULUS);
		Util.arrayCopy(tempBuffer, (short) 0x00, kv, (short) 0x00,
				LENGTH_MODULUS);
	}

 
	/**
	 * Initializes SRP-6a key agreement
	 * 
	 * @param apdu reference for the APDU object used by this Applet
	 * @param incomingBuf reference to the APDU buffer that contains the client public key A
	 * @return true if key agreement initialization completes successfully. false if the client public A is zero 
	 */
	public boolean initWithSRP(APDU apdu, byte[] incomingBuf) {

		/**
		 * move the last byte of incoming public from P2 to LE
		 */
		Util.arrayCopy(incomingBuf, ISO7816.OFFSET_P1, incomingBuf, (short)(ISO7816.OFFSET_CDATA + LENGTH_MODULUS - 0x01 ), (short)0x01);
 		/**
		 * if incoming public A mod N = 0 abort
		 */
		Util.arrayCopy(N, (short) 0x00, tempBuffer, OUTPUT_OFFSET_2,
				LENGTH_MODULUS);
				if ((Util.arrayCompare(incomingBuf, ISO7816.OFFSET_CDATA, tempBuffer,
				(short) 0x00, LENGTH_MODULUS) == 0)
				| (Util.arrayCompare(incomingBuf, ISO7816.OFFSET_CDATA,
						tempBuffer, OUTPUT_OFFSET_2, LENGTH_MODULUS) == 0)) {
			
			return false;
		}
		
		// apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, LENGTH_MODULUS);

		/**
		 * generate SE secret b and compute ... B = kv + g^b
		 */
		generateRandom(tempBuffer, OFFSET_b, LENGTH_KEY);

		/**
		 * compute g^b using rsa public encryption ... b = exponent g = cipher
		 * input tempOutput array should be filled with zero before this method
		 * is invoked
		 */
		rsaPublicKey.setExponent(tempBuffer, OFFSET_b, LENGTH_KEY);
		rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);

		tempBuffer[(short) 0xFF] = g;

		rsaCipher.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
				(short) 0x00);

		Util.arrayCopy(kv, (short) 0x00, tempBuffer, OUTPUT_OFFSET_1,
				LENGTH_MODULUS);

		/**
		 * B = kv + g^b if the result has a carry or B is greater than the
		 * modulus subtract modulus from it
		 */

		boolean carry = add(tempBuffer, (short) 0x00, LENGTH_MODULUS,
				tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS);

		if (/*
			 * (tempOutput[(short) 0x00] & 0xff) > (tempOutput[OUTPUT_OFFSET_2]
			 * & 0xff)|
			 */carry) {
			subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);
		}

		/**
		 * compute u = H(A , B) incomingBuf contains A,B from ISO7816.OFFSET_CLA
		 * to 2 * LENGTH_MODULUS
		 */
		msgDigest_SHA256.update(incomingBuf, ISO7816.OFFSET_CDATA,
				LENGTH_MODULUS);
		msgDigest_SHA256.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
				OFFSET_u);

		// copy B for sending later
		Util.arrayCopy(tempBuffer, (short) 0x00, B, (short) 0x00,
				LENGTH_MODULUS);

		/**
		 * compute v^u
		 */
		rsaPublicKey.setExponent(tempBuffer, OFFSET_u, LENGTH_MESSAGE_DIGEST);
		rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);

		Util.arrayCopy(v, (short) 0x00, tempBuffer, OUTPUT_OFFSET_1,
				LENGTH_MODULUS);

		rsaCipher.doFinal(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS,
				tempBuffer, OUTPUT_OFFSET_1);

		// multiply with with A ..... A * v^u
		modMultiply(incomingBuf, ISO7816.OFFSET_CDATA, LENGTH_MODULUS,
				tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS);

		// compute S = (A * v^u ) ^b

		rsaPublicKey.setExponent(tempBuffer, OFFSET_b, LENGTH_KEY);
		rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
		rsaCipher.doFinal(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
				OUTPUT_OFFSET_1);

		/**
		 * compute K = H(S)
		 */
		msgDigest_SHA256.doFinal(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS,
				tempBuffer, (short) 0x00);

		/**
		 *  reset secret value used for key agreement
		 */
		Util.arrayFillNonAtomic(tempBuffer, OFFSET_b, (short)0x20, (byte)0x00);

		/**
		 * send public key B
		 */
		Util.arrayCopy(B, (short) 0x00, incomingBuf, ISO7816.OFFSET_CLA,
						LENGTH_MODULUS); 
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CLA, (short) LENGTH_MODULUS);

		return true;
	}
	
	/**
	 * Retrieves the salt used for the key agreement 
	 * and random initialization vector to be used in the secure channel session (secure messaging) 
	 * method which gets  salt value used and random iv to be used for the following secure session
	 * 
	 * @param out_salt_iv byte array buffer where to put the current salt value and random iv
	 * @param outOffset offset in outSalt to put current salt value and random iv
	 */
	public short getSalt_and_IV(byte[] out_salt_iv, short outOffset){
		 Util.arrayCopy(salt, (short) 0x00, out_salt_iv, outOffset,
	      	LENGTH_SALT);
		 generateRandom(tempBuffer, OFFSET_IV, LENGTH_IV); 
		 
		 Util.arrayCopy(tempBuffer, OFFSET_IV, out_salt_iv, (short)(outOffset + LENGTH_SALT), LENGTH_IV);
		
		 return (short)(LENGTH_SALT + LENGTH_IV);
	}

	/**
	 * Verifies client authentication data M1 and sends Applet authentication data M2 using the APDU reference
	 * 
	 * @param apdu reference for the APDU object used by this Applet
	 * @param incomingBuf reference to the APDU buffer that contains client Authentication data M1 
	 * @return true if authentication is successful, false otherwise
	 */
	public boolean authenticate(APDU apdu, byte[] incomingBuf) {
		short M_offset = (short)(LENGTH_MODULUS - (short)0x20);
		/**
		 * compute expected authentication data M = H(u, S)
		 */
		msgDigest_SHA256.update(tempBuffer, OFFSET_u, LENGTH_MESSAGE_DIGEST);
		msgDigest_SHA256.doFinal(tempBuffer, OUTPUT_OFFSET_1, LENGTH_MODULUS,
				tempBuffer, M_offset);

		
		/**
		 * compare with incoming Auth data if authenticated compute server ..
		 * (SE ) Authentication Data.... H (u, M, S) from the previous operation
		 * tempoutput contains M, S from offset M_offset - M_offset + LENGTH_MODULUS 
		 */
		if (Util.arrayCompare(incomingBuf, ISO7816.OFFSET_CDATA, tempBuffer,
				M_offset, LENGTH_MESSAGE_DIGEST) == 0) {
			msgDigest_SHA256.update(tempBuffer, OFFSET_u, LENGTH_MESSAGE_DIGEST);
			msgDigest_SHA256.doFinal(tempBuffer, M_offset, (short) 0x120, incomingBuf, ISO7816.OFFSET_CDATA);


			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 0x20);
			return true;
		}

		return false;
	}

	/**
	 * generates secure random byte array
	 * 
	 * @param buffer output byte array buffer  
	 * @param offset offset in the output buffer 
	 * @param length length of the random data
	 * @return true if random data is generated successfully, false otherwise
	 */
	private boolean generateRandom(byte[] buffer, short offset, short length) {
		try {
			rng.generateData(buffer, offset, length);
			return true;
		} catch (Exception ex) {
			Util.arrayFillNonAtomic(buffer, (short) 0, length, (byte) 0);
			return false;
		}
	}

	/**
	 * returns buffer containing the result of the key agreement
	 * 
	 * @return
	 */
	public byte[] getResult() {
		// TODO Auto-generated method stub
		return tempBuffer;
	}

	/**
	 * Addition of big integer x and y specified by offset and length
	 * the result is saved in x
	 * 
	 * @param x
	 * @param xOffset
	 * @param xLength
	 * @param y
	 * @param yOffset
	 * @param yLength
	 * @return
	 */
	private boolean add(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {
		short digit_mask = 0xff;
		short digit_len = 0x08;
		short result = 0;
		short i = (short) (xLength + xOffset - 1);
		short j = (short) (yLength + yOffset - 1);

		for (; i >= xOffset; i--, j--) {
			result = (short) (result + (short) (x[i] & digit_mask) + (short) (y[j] & digit_mask));

			x[i] = (byte) (result & digit_mask);
			result = (short) ((result >> digit_len) & digit_mask);
		}
		while (result > 0 && i >= xOffset) {
			result = (short) (result + (short) (x[i] & digit_mask));
			x[i] = (byte) (result & digit_mask);
			result = (short) ((result >> digit_len) & digit_mask);
			i--;
		}

		return result != 0;
	}

	/**
	 * subtracts big integer y from x specified by offset and length
	 * the result is saved in x 
	 * 
	 * @param x
	 * @param xOffset
	 * @param xLength
	 * @param y
	 * @param yOffset
	 * @param yLength
	 * @return
	 */
	private boolean subtract(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {
		short digit_mask = 0xff;
		short i = (short) (xLength + xOffset - 1);
		short j = (short) (yLength + yOffset - 1);
		short carry = 0;
		short subtraction_result = 0;

		for (; i >= xOffset && j >= yOffset; i--, j--) {
			subtraction_result = (short) ((x[i] & digit_mask)
					- (y[j] & digit_mask) - carry);
			x[i] = (byte) (subtraction_result & digit_mask);
			carry = (short) (subtraction_result < 0 ? 1 : 0);
		}
		for (; i >= xOffset && carry > 0; i--) {
			if (x[i] != 0)
				carry = 0;
			x[i] -= 1;
		}

		return carry > 0;
	}

	/**
	 * multiplies big integer x and y specified by offset and length
	 * The result is saved in the temporary output buffer (tempOutput) used by this class
	 * 
	 * @param x
	 * @param xOffset
	 * @param xLength
	 * @param y
	 * @param yOffset
	 * @param yLength
	 */
	private void modMultiply(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {

		Util.arrayCopy(x, xOffset, tempBuffer, (short) 0x00, xLength);

		/**
		 * x+y
		 */

		Util.arrayCopy(N, (short) 0x00, tempBuffer, OUTPUT_OFFSET_2,
				LENGTH_MODULUS);
		if (add(tempBuffer, (short) 0x00, xLength, y, yOffset, yLength)) {
			subtract(tempBuffer, (short) 0x00, xLength, tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);

		}
		/**
		 * (x+y)^2
		 */

		rsaCipher.init(rsaPublicKey_forSquareMul, Cipher.MODE_ENCRYPT);
		rsaCipher.doFinal(tempBuffer, (short) 0x00, xLength, tempBuffer,
				(short) 0x00);

		/**
		 * compute x^2
		 */
		rsaCipher.doFinal(x, xOffset, xLength, x, xOffset);

		/**
		 * compute (x+y)^2 - x^2
		 */
		if (subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, x, xOffset,
				xLength)) {
			add(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);
		}

		/**
		 * compute y^2
		 */
		rsaCipher.doFinal(y, yOffset, yLength, y, yOffset);

		/**
		 * compute (x+y)^2 - x^2 - y^2
		 */

		if (subtract(tempBuffer, (short) 0x00, LENGTH_MODULUS, y, yOffset,
				yLength)) {

			add(tempBuffer, (short) 0x00, LENGTH_MODULUS, tempBuffer,
					OUTPUT_OFFSET_2, LENGTH_MODULUS);

		}
		/**
		 * divide by 2
		 */

		modular_division_by_2(tempBuffer, (short) 0x00, LENGTH_MODULUS);
		 
	}

	/**
	 * performs a modular division by 2
	 * The output is of operation is saved in the input itself
	 * 
	 * @param input
	 * @param inOffset
	 * @param inLength
	 */
	private void modular_division_by_2(byte[] input, short inOffset,
			short inLength) {
		short carry = 0;
		short digit_mask = 0xff;
		short digit_first_bit_mask = 0x80;
		short lastIndex = (short) (inOffset + inLength - 1);

		short i = inOffset;
		if ((byte) (input[lastIndex] & 0x01) != 0) {
			if (add(input, inOffset, inLength, tempBuffer, OUTPUT_OFFSET_2,
					LENGTH_MODULUS)) {
				carry = digit_first_bit_mask;
			}
		}

		for (; i <= lastIndex; i++) {
			if ((input[i] & 0x01) == 0) {
				input[i] = (byte) (((input[i] & digit_mask) >> 1) | carry);
				carry = 0;
			} else {
				input[i] = (byte) (((input[i] & digit_mask) >> 1) | carry);
				carry = digit_first_bit_mask;
			}
		}
	}

}
