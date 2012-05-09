package hw2;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.CertPathValidatorUtilities;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.X509CertStoreSelector;

/*
 * Fix all the TODO's. Follow the Javadoc.
 * 
 * You are *not* allowed to change method signatures.
 */
public final class X509Util {
	/**
	 * Extracts first CRL distribution URL from this X.509 certificate.
	 */
	public static String getCrlUrl(X509Certificate certificate)
			throws IOException {

		String result = null;
		// getting octet string for CRL OID
		DEROctetString dos = (DEROctetString) toAsn1Object(certificate
				.getExtensionValue("2.5.29.31"));
		byte[] val2 = dos.getOctets();
		ASN1Primitive asnObj = (ASN1Primitive) toAsn1Object(val2);
		Vector<String> urls = getDERValue(asnObj);
		if (urls.size() > 0)
			result = urls.get(0);
		return result;
	}

	// honestly googled, understood and refactored. Source -
	// http://bouncy-castle.1462172.n4.nabble.com/Validating-cert-using-CRL-td1462803.html
	private static Vector<String> getDERValue(ASN1Object asnObj) {
		if (asnObj instanceof ASN1Sequence) {
			Vector<String> result = new Vector<String>();
			ASN1Sequence seq = (ASN1Sequence) asnObj;
			Enumeration<Object> sequenceItems = seq.getObjects();
			while (sequenceItems.hasMoreElements()) {
				ASN1Object nestedObj = (ASN1Object) sequenceItems.nextElement();
				Vector<String> appo = getDERValue(nestedObj);
				if (appo != null) {
					result.addAll(appo);
				}
			}
			return result;
		}

		if (asnObj instanceof DERTaggedObject) {
			ASN1TaggedObject derTag = (ASN1TaggedObject) asnObj;
			if (derTag.isExplicit() && !derTag.isEmpty()) {
				ASN1Object nestedObj = derTag.getObject();
				Vector<String> ret = getDERValue(nestedObj);
				return ret;
			} else {
				DEROctetString derOct = (DEROctetString) derTag.getObject();
				String val = new String(derOct.getOctets());
				Vector<String> ret = new Vector<String>();
				ret.add(val);
				return ret;
			}
		}
		return null;
	}

	/**
	 * Extracts OCSP service URL from this X.509 certificate.
	 */
	public static String getOcspUrl(X509Certificate certificate)
			throws IOException {
		// TODO: implement.
		//
		// Once you have implemented getCrlUrl(X509Certificate) method, this one
		// should be easy
		// to complete. The logic behind extracting values is the same, only the
		// structures are
		// slightly different.
		//
		// Check out http://tools.ietf.org/html/rfc5280#section-4.2.2.1 for
		// details.
		String result = null;
		// getting octet string for OCSP OID
		DEROctetString dos = (DEROctetString) toAsn1Object(certificate
				.getExtensionValue("1.3.6.1.5.5.7.1.1"));
		byte[] val2 = dos.getOctets();
		ASN1Primitive asnObj = (ASN1Primitive) toAsn1Object(val2);
		Vector<String> urls = getDERValue(asnObj);
		if (urls.size() > 1)
			result = urls.get(1);
		return result;
	}

	/**
	 * Reads X.509 certificate from this input stream.
	 */
	public static X509Certificate readCertificate(InputStream in)
			throws CertificateException, IOException {
		// TODO: implement.
		//
		// Challenge: make it one-liner.
		return (X509Certificate) new CertificateFactory()
				.engineGenerateCertificate(in);
	}

	/**
	 * Reads X.509 CRL object from this input stream.
	 */
	public static X509CRL readCrl(InputStream in) throws CertificateException,
			CRLException, IOException {
		// TODO: implement.
		//
		// Challenge: make it one-liner.
		return (X509CRL) new CertificateFactory().engineGenerateCRL(in);
	}

	/**
	 * Performs full certificate verification.
	 * 
	 * Properties checked: - Validity dates - Issuer DN - Public key signature -
	 * Certificate revocation status
	 * 
	 * If OCSP service is not reachable (no connection), certificate status is
	 * checked using CRL.
	 * 
	 * If CRL check is not possible, certificate considered not valid.
	 * 
	 * @throws CertificateException
	 *             in case of any verification problems.
	 */
	public static int verify(X509Certificate certificate,
			X509Certificate issuerCertificate, X509CRL crl)
			throws CertificateException {
		// TODO: implement.
		//
		// If any of verification steps fails, a CertificateException should be
		// thrown containing
		// a short but precise description of the problem.
		//
		// This method returns the number of points you will get.
		// Currently score is set to maximum, I assume you'll do the task
		// properly (:
		//
		// I'll fix these numbers while reviewing your code.
		// Should it contain any problems, the score will get lower ):
		//
		// As for now, you may use any numbers you are happy with, they
		// shouldn't affect the
		// actual certificate verification process.
		int score = 0;

		// TODO: verify certificate validity issuer
		if (!certificate.getIssuerDN().toString()
				.equals(issuerCertificate.getSubjectDN().toString())) {
			throw new CertificateException(
					"Certificate issuer DN != issuer certificate subject DN");

		}
		score += 1; // I may change these while reviewing your code.

		// TODO: verify certificate validity dates
		try {
			certificate.checkValidity(new Date());
		} catch (Exception e) {
			throw new CertificateException(
					"Error verifying public key signature (see underlying exception for details)",
					e);
		}
		score += 1;

		// TODO: verify public key signature
		try {
			certificate.verify(issuerCertificate.getPublicKey());
		} catch (Exception e) {
			throw new CertificateException(
					"Error verifying public key signature (see underlying exception for details)",
					e);
		}
		score += 1;

		// TODO: check certificate status via OCSP. report status code in case
		// of failure.
		//
		// It is okay to use some deprecated BouncyCastle classes here, if
		// needed. These will make
		// your life much easier.
		//
		// Check lab 7 code for examples.
		CertificateID certificateId;
		try {
			certificateId = new CertificateID(CertificateID.HASH_SHA1,
					issuerCertificate, certificate.getSerialNumber());

			// Create OCSP request
			OCSPReqGenerator ocspRequestGenerator = new OCSPReqGenerator();
			ocspRequestGenerator.addRequest(certificateId);
			OCSPReq ocspRequest = ocspRequestGenerator.generate();

			// Send OCSP request and receive response.
			// Service URL is available from OCSP extension of the certificate
			// being verified.
			byte[] ocspRequestBytes = ocspRequest.getEncoded();

			URL url = new URL(getOcspUrl(certificate));
			HttpURLConnection connection = (HttpURLConnection) url
					.openConnection();
			connection.setDoOutput(true);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type",
					"application/ocsp-request");
			connection.setRequestProperty("Content-Length",
					Integer.toString(ocspRequestBytes.length));
			connection.connect();

			OutputStream out = connection.getOutputStream();
			out.write(ocspRequestBytes);
			out.flush();
			out.close();

			InputStream in = connection.getInputStream();
			OCSPResp ocspResponse = new OCSPResp(in);
			BasicOCSPResp ocspBasicResponse = (BasicOCSPResp) ocspResponse
					.getResponseObject();
			SingleResp ocspSignleResponse = ocspBasicResponse.getResponses()[0];
			if (ocspSignleResponse.getCertStatus() != null) {
				throw new CertificateException("OCSP check failed, status: "
						+ ocspSignleResponse.getCertStatus());
			}

		} catch (OCSPException e) {
			throw new CertificateException("OCSP error ", e);
		} catch (IOException e) {
			throw new CertificateException("I/O error in OCSP validation", e);
		}
		score += 3;

		// TODO: verify CRL signature and check if certificate was revoked
		X509CRL crl1;
		try {
			// signature check
			crl.verify(issuerCertificate.getPublicKey());
			// revoke check
			if (crl.getRevokedCertificate(certificate) != null) {
				throw new CertificateException("CRL: Certificate was revoked!");
			}
		} catch (CRLException e) {
			throw new CertificateException("CRL exc", e);
		} catch (InvalidKeyException e) {
			throw new CertificateException("Key is invalid!", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CertificateException("No such algorithm", e);
		} catch (NoSuchProviderException e) {
			throw new CertificateException("No provider ", e);
		} catch (SignatureException e) {
			throw new CertificateException("Signature was broken.", e);
		}
		score += 3;

		return score;
	}

	/**
	 * Verifies certificate chain.
	 */
	public static int verifyChain(X509Certificate certificate,
			X509Certificate trustedCertificate,
			X509Certificate[] intermediateCertificates) throws Exception {
		// TODO: implement.
		//
		// These classes may be helpful:
		// - java.security.cert.TrustAnchor
		// - java.security.cert.CertStore
		// - java.security.cert.PKIXBuilderParameters
		// - java.security.cert.CertPathBuilder
		// - java.security.cert.CertPathValidator
		//
		// You may skip CRL checks here -- see
		// PKIXBuilderParameters.setRevocationEnabled(boolean)
		
		// Great thanks to David Hook and his book "Beginning cryptography with Java". He pointed me in the right direction.
		
		
		int score = 0;

		// TODO: verify trusted certificate public key signature
		trustedCertificate.verify(trustedCertificate.getPublicKey());
		score += 1;

		// TODO: create a set of trust anchors.
		Set<TrustAnchor> trustedSet = new HashSet<TrustAnchor>();
		trustedSet.add(new TrustAnchor(trustedCertificate, null));
				
		// TODO: create a list of all certificates being verified.
		List certList = new ArrayList();
		certList.add(trustedCertificate);
		certList.add(intermediateCertificates[0]);
		certList.add(intermediateCertificates[1]);
		certList.add(certificate);
		

		
		// TODO: create a certificate store.
		CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList),"BC");
		
		// TODO: Build the certificate chain.
		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
		X509CertSelector certSelector = new X509CertSelector();
		certSelector.setCertificate(certificate);
		PKIXBuilderParameters pbParams = new PKIXBuilderParameters(trustedSet, certSelector);
		pbParams.addCertStore(certStore);
		pbParams.setRevocationEnabled(false);
		CertPathBuilder cpBuilder = CertPathBuilder.getInstance("PKIX", "BC");
		PKIXCertPathBuilderResult pbResult = (PKIXCertPathBuilderResult) cpBuilder.build(pbParams);
		score += 2;

		// TODO: Verify the certificate chain.
		PKIXParameters pkixParams = new PKIXParameters(trustedSet);	
		pkixParams.setRevocationEnabled(false);
		CertPathValidator cpValidator = CertPathValidator.getInstance("PKIX", "BC");
		cpValidator.validate(pbResult.getCertPath(), pkixParams);
		score += 4;

		return score;
	}

	/**
	 * Encoded this X.509 certificate using DER and writes the result to this
	 * output stream.
	 */
	public static void writeDer(OutputStream out, X509Certificate certificate)
			throws CertificateEncodingException, IOException {
		out.write(certificate.getEncoded());
		out.flush();
		out.close();
	}

	/**
	 * Encoded this X.509 certificate using PEM rules and writes the result to
	 * this output stream.
	 */
	public static void writePem(OutputStream out, X509Certificate certificate)
			throws CertificateEncodingException, IOException {
		// TODO: implement.
		//
		// Hint: `org.bouncycastle.util.io.pem.*` package may be useful.
		//
		// Note that you will get penalty (2p) for using `sun.misc.*` classes
		// directly!
		org.bouncycastle.util.io.pem.PemObject po = new PemObject(
				"CERTIFICATE", certificate.getEncoded());
		StringWriter sw = new StringWriter();
		PemWriter pw = new PemWriter(sw);
		pw.writeObject(po);
		pw.close();
		out.write(sw.getBuffer().toString().getBytes());
		out.flush();
		out.close();

	}

	private static ASN1Encodable toAsn1Object(byte[] encoded)
			throws IOException {
		return new ASN1InputStream(encoded).readObject();
	}
}
