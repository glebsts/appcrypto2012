package hw1;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/*
 * Class with signing and signature verification methods.
 * 
 * You will have to implement 4 methods:
 *   - DSA signing
 *   - DSA verification
 *   - RSA signing
 *   - RSA verification
 * 
 * Note that you are *not* allowed to change method signatures (adding exception,
 * changing return type, etc.) in any other ways than it is requested in the task.
 * 
 * Tasks in this file will give you 4 points.
 */
public class MySigner {
	public static byte[] dsaSign(byte[] data, PrivateKey signingKey) {
		// (1p) Implement DSA signing, replace `null` with actual
		// signature value
		byte[] result = null;
		result = sign(data, signingKey, "DSA");
		return result;
	}

	// Replace Key type with a proper type from java.security.* package
	public static boolean dsaVerify(byte[] data, byte[] signature,
			PublicKey verificationKey) {
		// (1p) Implement DSA verification, replace `false` with actual
		// result (true|false)
		boolean result = false;
		result = verify(signature, verificationKey, data, "DSA");
		return result;
	}

	// Replace Key type with a proper type from java.security.* package
	public static byte[] rsaSign(byte[] data, PrivateKey signingKey) {
		// (1p) Implement RSA signing, replace `null` with actual
		// signature value
		byte[] result = null;
		result = sign(data, signingKey, "RSA");
		return result;
	}

	// Replace Key type with a proper type from java.security.* package
	public static boolean rsaVerify(byte[] data, byte[] signature,
			PublicKey verificationKey) {
		// (1p) Implement RSA verification, replace `false` with actual
		// result (true|false)
		boolean result = false;
		result = verify(signature, verificationKey, data, "RSA");
		return result;
	}
	
	/**
	 * @param data - data to sign
	 * @param signingKey - private key for signing
	 * @param alg - "DSA"/"RSA"
	 * @return signed data
	 */
	private static byte[] sign(byte[] data, PrivateKey signingKey, String alg) {
		byte[] result = null;
		try {
			Signature signature;
			signature = Signature.getInstance(alg);
			signature.initSign(signingKey);

			signature.update(data);
			result = signature.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Ready to create digital signature.
		return result;
	}

	/**
	 * @param signatureBytes - signature
	 * @param verificationKey - public key for verification
	 * @param data - data to verify
	 * @param alg - "RSA"/"DSA"
	 * @return true/false, if signatur is/not verified
	 */
	private static boolean verify(byte[] signatureBytes, PublicKey verificationKey, byte[] data, String alg) {
		boolean result = false;

		try {
			Signature signature;
			signature = Signature.getInstance(alg);
			signature.initVerify(verificationKey);

			signature.update(data);
			result = signature.verify(signatureBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;

	}

	// Hints:
	// You may want to use java.security.Signature class.
	// You may want to create private methods sign(alg, data, signingKey) and
	// verify(alg, data, signature, verificationKey) and use them from public
	// methods.
	// Signing and verification procedures for RSA nd DSA are very similar.
}
