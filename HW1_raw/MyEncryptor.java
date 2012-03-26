package hw1;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;

/*
 * Class with encryption/decryption methods.
 * 
 * You will have to implement 4 methods:
 *   - AES encryption (symmetric)
 *   - AES decryption (symmetric)
 *   - RSA encryption (asymmetric)
 *   - RSA decryption (assymetric)
 * 
 * Note that you are *not* allowed to change method signatures (adding exception,
 * changing return type, etc.) in any other ways than it is requested in the task 
 * 
 * Tasks in this file will give you 4 points.
 */
public class MyEncryptor {
	public static byte[] aesEncrypt(byte[] plaintext, SecretKey encryptionKey) {
		// (1p) Implement AES encryption, replace `null` with actual ciphertext
		byte[] result = null;
		
		try {
			// Using our custom-constant salt and iteration count
			byte[] salt = "Extr3m3lyS3cr3tSalt!".getBytes();
			int count = 20;
			Cipher cipher;
			cipher = Cipher.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
			PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
			cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, pbeParamSpec);
			result = cipher.doFinal(plaintext);
		} catch (Exception e) {
			e.printStackTrace();
		}
	
		return result;
	}

	public static byte[] aesDecrypt(byte[] ciphertext, SecretKey decryptionKey) {
		// (1p) Implement AES decryption, replace `null` with actual plaintext
		
		byte[] result = null;
		Cipher cipher;
		try {
			// Using our custom-constant salt and iteration count
			cipher = Cipher.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
			byte[] salt = "Extr3m3lyS3cr3tSalt!".getBytes();
			int count = 20;
			PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
			cipher.init(Cipher.DECRYPT_MODE, decryptionKey, pbeParamSpec);
			result = cipher.doFinal(ciphertext);
		} catch (Exception e) {
			e.printStackTrace();
		}
	
		return result;
	}

	// Replace Key type with a proper type from java.security.* package
	public static byte[] rsaEncrypt(byte[] plaintext, PublicKey encryptionKey) {
		// (1p) Implement RSA encryption, replace `null` with actual ciphertext
		byte[] result = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
			result = cipher.doFinal(plaintext);
		} catch (Exception e) {
			e.printStackTrace();
		}
	
		return result;
	}
	
	// Replace Key type with a proper type from java.security.* package
	public static byte[] rsaDecrypt(byte[] ciphertext, PrivateKey decryptionKey) {
		// (1p) Implement RSA decryption, replace `null` with actual plaintext
		byte[] result = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
			result = cipher.doFinal(ciphertext);
		} catch (Exception e) {
			e.printStackTrace();
		}
	
		return result;
	}

	// Hint: you may want to use javax.crypto.Cipher class.
}
