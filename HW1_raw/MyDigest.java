package hw1;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/*
 * Class with digest computation methods.
 * 
 * You will have to implement one private digest computation method. Public methods will call it
 * with `alg` parameter.
 * 
 * Note that you are *not* allowed to change method signatures (adding exception,
 * changing return type, etc.) in any other ways than it is requested in the task.
 * 
 * Tasks in this file will give you 2 points.
 */
class MyDigest {
	public static byte[] md5(InputStream in) throws IOException {
		return digest("MD5", in);
	}

	public static byte[] ripemd160(InputStream in) throws IOException {
		return digest("RIPEMD160", in);
	}

	public static byte[] sha1(InputStream in) throws IOException {
		return digest("SHA-1", in);
	}

	public static byte[] sha256(InputStream in) throws IOException {
		return digest("SHA-256", in);
	}

	private static byte[] digest(String alg, InputStream in) throws IOException {
		// (2p) Implement digest computation, replace `null` with actual
		// digest
		byte[] result = null;
		// GS read file (chunked), calculate digest
		try {
			MessageDigest md = MessageDigest.getInstance(alg);
			byte[] dataBuffer = new byte[65536];
			int readLen;
			while ((readLen = in.read(dataBuffer)) != -1) {
				md.update(dataBuffer, 0, readLen);
			}
			in.close();
			// GS calc digest
			result = md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return result;

		// Note that you are dealing with InputStream, and you will have to read
		// data
		// as multiple chunks. If you read all the data from InputStream at
		// once,
		// you will *not* get maximum points for this task.
	}

	// Hint: you may want to use java.security.MessageDigest class.
}
