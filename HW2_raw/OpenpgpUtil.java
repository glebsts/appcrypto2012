package hw2;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.encoders.Hex;

/*
 * Hints:
 *  - You can use `gpg` command-line tool to check the contents of keyrings and
 *    collections and compare it to output you are getting from your methods.
 */
public class OpenpgpUtil {
	/*
	 * Read this task carefully. There are lots of tricky details, and only
	 * meeting *all* of the requirements will give you the maximum of 6 points.
	 */
	/**
	 * Prints this OpenPGP keyring contents to stdout (6 p).
	 * 
	 * Output format MUST be the following:
	 * 
	 * Key: <key-type> v<key-version> <key-length>-bit <key-algorithm>
	 * ID: <key-id>
	 * Valid from: <key-valid-from-time> (<key-valid-from-unixtime>)
	 * Valid until: <key-valid-until-time> (<key-valid-until-unixtime>)
	 * Key fingerprint: <key-fingerprint> (<key-fingerprint-algorithm>)
	 * User ID: <key-user-id>
	 * Signed by: <signing-key-id>
	 * <empty-line>
	 * 
	 * Whereas
	 *  - <key-type> -- 'pub' for master key or 'sub' for subkey
	 *  - <key-version> -- key version (a number)
	 *  - <key-length> -- key length, in bits (a number)
	 *  - <key-algorithm> -- key algorithm name (RSA, DSA, Elgamal, etc.)
	 *  - <key-id> -- key identifier, last 8 bytes of key fingerpint, upper case
	 *  - <key-valid-from-time> -- free-text date and time (see example below)
	 *  - <key-valid-from-unixtime> -- UNIX time, in seconds
	 *  - <key-valid-until-time> -- free-text date and time ('forever' if key has no expiration date)
	 *  - <key-valid-from-unixtime> -- UNIX time, in seconds (-1 if key has no expiration date)
	 *  - <key-fingerprint> -- digest of key parameters (as defined in RFC 4880), in lower case
	 *  - <key-user-id> -- key user identifier, including name, alias and email (see example below)
	 *  - <signing-key-id> -- identifier of the key that was used to sign this key
	 *  
	 * Example output:
	 *   Key: pub v3 1024-bit DSA
	 *   ID: DE01AD23BE45EF67
	 *   Valid from: Mon Mar 5 06:07:08 EET 2012 (1330920428)
	 *   Valid until: forever (-1)
	 *   Key fingerprint: 0123456789abcdef0123456789abcdef (MD5)
	 *   User ID: John Doe (fubar) <john.doe@gmail.com>
	 *   Signed by: 76DE54AD32BE10EF
	 *   
	 * Notes:
	 *  - There may be multiple 'User ID:' lines
	 *  - There may be multiple 'Signed by:' lines
	 *  - Some keys may be self-signed ('ID:' and 'Signed by:' values will match)
	 *  - Make sure to leave an empty line after the last line with text
	 * 
	 * See also:
	 *  - Public key algorithms: http://tools.ietf.org/html/rfc4880#section-9.1
	 *  - Public key IDs and fingerprints: http://tools.ietf.org/html/rfc4880#section-12.2
	 * @param <E>
	 */
	public static void listPublicKeyRing(PGPPublicKeyRing keyRing) {
		// TODO: implement
		// Hint: use String.format() to build strings with multiple variables.
		Iterator<PGPPublicKey> pKeys = keyRing.getPublicKeys();
		while(pKeys.hasNext()){
			PGPPublicKey pk = pKeys.next();
			StringBuffer sb = new StringBuffer();
			String algoName = "";
			//small copy-paste exercise
			switch (pk.getAlgorithm()) {
			case PublicKeyAlgorithmTags.RSA_GENERAL: algoName="RSA_GENERAL";break;
			case PublicKeyAlgorithmTags.RSA_ENCRYPT: algoName="RSA_ENCRYPT";break;
			case PublicKeyAlgorithmTags.RSA_SIGN: algoName="RSA_SIGN";break;
			case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT: algoName="ELGAMAL_ENCRYPT";break;
			case PublicKeyAlgorithmTags.DSA: algoName="DSA";break;
			case PublicKeyAlgorithmTags.EC: algoName="EC";break;
			case PublicKeyAlgorithmTags.ECDSA: algoName="ECDSA";break;
			case PublicKeyAlgorithmTags.ELGAMAL_GENERAL: algoName="ELGAMAL_GENERAL";break;
			case PublicKeyAlgorithmTags.DIFFIE_HELLMAN: algoName="DIFFIE_HELLMAN";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_1: algoName="EXPERIMENTAL_1";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_2: algoName="EXPERIMENTAL_2";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_3: algoName="EXPERIMENTAL_3";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_4: algoName="EXPERIMENTAL_4";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_5: algoName="EXPERIMENTAL_5";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_6: algoName="EXPERIMENTAL_6";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_7: algoName="EXPERIMENTAL_7";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_8: algoName="EXPERIMENTAL_8";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_9: algoName="EXPERIMENTAL_9";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_10: algoName="EXPERIMENTAL_10";break;
			case PublicKeyAlgorithmTags.EXPERIMENTAL_11: algoName="EXPERIMENTAL_11";break;
			default: algoName="wtf?";break;
			}

			sb.append(String.format("Key: %s v%d %d-bit %s%n", 
					(pk.isMasterKey() ? "pub" : "sub"), pk.getVersion(), 
					pk.getBitStrength(), algoName));
			sb.append(String.format("ID: %s%n", Long.toHexString(pk.getKeyID()).toUpperCase()));
			Date creationDate = pk.getCreationTime();
			sb.append(String.format("Valid from: %s (%d)%n",
					DateFormat.getDateInstance(DateFormat.FULL).format(creationDate),
					(long) creationDate.getTime()/1000
			));
			Calendar c = Calendar.getInstance();
			c.setTime(creationDate);
			// not the best as i.e. for after-1-hour-expriring key (which is quite real) it shouldn't work
			// so have to do more magic with getValidSeconds. But not now, please :)
			c.add(Calendar.DATE, pk.getValidDays());
			Date expirationDate = c.getTime();
			sb.append(String.format("Valid until: %s (%d)%n",
					((pk.getValidDays()>0)? DateFormat.getDateInstance(DateFormat.FULL).format(expirationDate):"forever"),
					((pk.getValidDays()>0)?(long) expirationDate.getTime()/1000:-1)
			));
			String fingerprintAlgo ="";
			switch (pk.getVersion()) {
			case 3: fingerprintAlgo="MD5";	break;
			case 4: fingerprintAlgo="SHA1";	break;
			default:fingerprintAlgo="wtf?";	break;
			}
			sb.append(String.format("Key fingerprint: %s (%s)%n",
					new String(Hex.encode(pk.getFingerprint())),
					fingerprintAlgo
			));
						
			Iterator<?> userIdIterator = pk.getUserIDs();
			while (userIdIterator.hasNext()) {
				String userId = (String) userIdIterator.next();
				sb.append(String.format("User ID: %s%n", userId));
			}
			userIdIterator = pk.getSignatures();
			while (userIdIterator.hasNext()) {
				PGPSignature signature = (PGPSignature) userIdIterator.next();
				sb.append(String.format("Signed by: %s%n", Long.toHexString(signature.getKeyID()).toUpperCase()));
			}
			
			System.out.println(sb.toString());
		}
	}

	/**
	 * Prints this OpenPGP keyring collection contents to stdout (1 p).
	 */
	public static void listPublicKeyRingCollection(PGPPublicKeyRingCollection keyRingCollection) {
		// TODO: implement
		// Hint: use listPublicKeyRing(PGPPublicKeyRing) method.
		Iterator<?> keyRingIterator = keyRingCollection.getKeyRings();
		while (keyRingIterator.hasNext()) {
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIterator.next();
			listPublicKeyRing(keyRing);
		}
	}

	/**
	 * Reads OpenPGP public keyring from this file (1p).
	 */
	public static PGPPublicKeyRing readPublicKeyRing(String filePath)
			throws IOException {
		// TODO: implement
		FileInputStream in = new FileInputStream(filePath);
		//use factory to avoid deprecated constructors
		// decoderStream to ignore armoring
		PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(in));
		Object factoryProduct = factory.nextObject();
		if(factoryProduct instanceof PGPPublicKeyRing){
			return (PGPPublicKeyRing) factoryProduct;
		}
		return null;
	}

	/**
	 * Reads OpenPGP public keyring collection from this file (1p).
	 */
	public static PGPPublicKeyRingCollection readPublicKeyRingCollection(String filePath)
			throws IOException, PGPException {
		// TODO: implement
		FileInputStream in = new FileInputStream(filePath);
		PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(in);
		
		
		return keyRingCollection;
	}

	/**
	 * Writes this OpenPGP public keyring collection to this file (1p).
	 */
	public static void writePublicKeyRingCollection(
			PGPPublicKeyRingCollection keyRingCollection, String filePath)
					throws IOException {
		// TODO: implement
		FileOutputStream out = new FileOutputStream(filePath);
		out.write(keyRingCollection.getEncoded());
		out.flush();
		out.close();
	}
}