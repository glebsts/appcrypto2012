package hw1;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/*
 * Class with key generation methods.
 * 
 * You will have to implement AES secret key generation method. That is the trickiest task
 * of this homework. See method comments for details
 * 
 * You will also have to implement one private key pair generation method. Public methods
 * generateDsaKeyPair and generateRsaKeyPair will call it with `alg` parameter.
 * 
 * Note that you are *not* allowed to change method signatures (adding exception,
 * changing return type, etc.) in any other ways than it is requested in the task.
 * 
 * Tasks in this file will give you 6 points.
 */
public class MyKeyGenerator {

	public static SecretKey generateAesSecretKey(char[] password) {
		// FIXME (6p) Implement AES secret key generation, replace `null` with
		// actual key
		// Some interesting article about paran.. proper usage of SecureRandom:
		// http://www.cigital.com/justice-league-blog/2009/08/14/proper-use-of-javas-securerandom/

		SecretKey result=null;
		try {
			
			// How the salt SHOULD be calculated. 
			/*
			 * Random r = SecureRandom.getInstance("SHA1PRNG", "SUN");
			 * byte[] salt = new byte[20];
			 * r.nextBytes(salt);
			*/
			// But as we can't change the signature, there is no simple way to give same custom constant salt to encryptor/decryptor
			// so I will use hard-coded constant salt.
			byte[] salt = "Extr3m3lyS3cr3tSalt!".getBytes();
			// As well as using constant count.
			int count = 20;

			PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, count);
			SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
			result = keyFac.generateSecret(pbeKeySpec);
		} catch (Exception e) {
			e.printStackTrace();
		} 

		return result;

		// You will have to generate a secret key based on password provided by
		// user.
		// Note that password itself is not a key, but only one of the input
		// parameters to
		// generate the key.
		//
		// Generating just a random key (ignoring the password) will give you 1
		// point.
		//
		// Generating a password-based key with default parameters will give you
		// 3 points.
		//
		// If you will correctly use custom salt and iteration count, you will
		// get 5 points.
		//
		// If, additionally, you will use stronger algorithms not supported by
		// standard
		// Java Cryptography Architecture, you will get maximum of 6 points.
		//
		// This tutorail may be helpful:
		// http://www.javamex.com/tutorials/cryptography/password_based_encryption.shtml
	}

	public static KeyPair generateDsaKeyPair(int keySize) {
		return generateKeyPair("DSA", keySize);
	}

	public static KeyPair generateRsaKeyPair(int keySize) {
		return generateKeyPair("RSA", keySize);
	}

	private static KeyPair generateKeyPair(String alg, int keySize) {
		// (1p) Implement key pair generation, replace `null` with actual
		// key pair
		KeyPair result = null;
		try {
			KeyPairGenerator kpGen;
			kpGen = KeyPairGenerator.getInstance(alg);
			kpGen.initialize(keySize);
			result = kpGen.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return result;
	}

	// Hint: you may want to use javax.crypto.SecretKeyFactory and
	// javax.crypto.spec.PBEKeySpec.
}
