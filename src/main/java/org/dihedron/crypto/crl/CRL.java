package org.dihedron.crypto.crl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.dihedron.crypto.exceptions.CertificateVerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class that verifies CRLs for given X509 certificate. Extracts the CRL
 * distribution points from the certificate (if available) and checks the
 * certificate revocation status against the CRLs coming from the distribution
 * points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
 * 
 * @author Svetlin Nakov
 * @author Andrea Funto'
 */
public class CRL {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(CRL.class);
	
	/**
	 * Downloads the CRL from the given URL. Supports http, https, ftp and ldap 
	 * based URLs.
	 */
	public static X509CRL fromURL(String url) throws IOException, CertificateException, CRLException, CertificateVerificationException, NamingException {
		if (url.startsWith("http://") || url.startsWith("https://") || url.startsWith("ftp://")) {
			return fromWeb(url);
		} else if (url.startsWith("ldap://")) {
			return fromLDAP(url);
		} else {
			throw new CertificateVerificationException("Cannot download CRL from certificate distribution point: '" + url + "'");
		}
	}

	/**
	 * Downloads a CRL from given LDAP url, e.g.
	 * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
	 * 
	 * @throws IOException 
	 */
	public static X509CRL fromLDAP(String ldapURL) throws CertificateException, NamingException, CRLException, CertificateVerificationException, IOException {
		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapURL);

		DirContext ctx = new InitialDirContext(env);
		Attributes attributes = ctx.getAttributes("");
		Attribute attribute = attributes.get("certificateRevocationList;binary");
		byte[] value = (byte[]) attribute.get();
		if ((value == null) || (value.length == 0)) {
			throw new CertificateVerificationException("error downloading CRL from '" + ldapURL + "'");
		} else {
			try(InputStream inStream = new ByteArrayInputStream(value)) {
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				return (X509CRL) cf.generateCRL(inStream);
			}
		}
	}

	/**
	 * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
	 * http://crl.infonotary.com/crl/identity-ca.crl
	 */
	public static X509CRL fromWeb(String crlURL) throws MalformedURLException, IOException, CertificateException, CRLException {
		URL url = new URL(crlURL);		
		try (InputStream stream = url.openStream()) {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			return (X509CRL)factory.generateCRL(stream);
		}
	}
		
	/**
	 * Extracts the CRL distribution points from the certificate (if available)
	 * and checks the certificate revocation status against the CRLs coming from
	 * the distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
	 * 
	 * @param certificate
	 *   the certificate to be checked for revocation.
	 * @throws CertificateVerificationException
	 *   if the certificate is revoked.
	 */
	public static void verifyCertificateCRLs(X509Certificate certificate) throws CertificateVerificationException {
		try {
			logger.trace("verifying certificate {}...", certificate.getSubjectX500Principal());
			List<String> distributionPoints = getCrlDistributionPoints(certificate);
			for (String distributionPoint : distributionPoints) {
				try {
					logger.trace("... checking distribution point '{}'...", distributionPoint);
					X509CRL crl = fromURL(distributionPoint);
					logger.trace("... CRL downloaded...", distributionPoint);
					if (crl.isRevoked(certificate)) {
						logger.info("certificate is revoked by CRL at '{}'", distributionPoint);
						throw new CertificateVerificationException("The certificate is revoked by CRL: " + distributionPoint);
					} 
					logger.trace("... certificate is not revoked by CRL at '{}'", distributionPoint);
				} catch(IOException | CertificateException | NamingException | CRLException e) {
					logger.warn("... error verifying against distribution point '{}'", distributionPoint);
					// let's try with the next one
				}
			}
		} catch (IOException | CertificateParsingException e) {
			logger.error("error parsing certificate to get distribution points", e);
			throw new CertificateVerificationException("Cannot verify CRL for certificate: " + certificate.getSubjectX500Principal(), e);
		}
	}


	/**
	 * Extracts all CRL distribution point URLs from the "CRL Distribution Point" 
	 * extension in a X.509 certificate. If CRL distribution point extension is 
	 * unavailable, returns an empty list.
	 */
	public static List<String> getCrlDistributionPoints(X509Certificate certificate) throws CertificateParsingException, IOException {
		
		List<String> urls = new ArrayList<>();
		
		byte[] extension = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
		if (extension == null) {		
			// return an empty list
			return urls;
		}
		
		try(ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(extension))) {
			byte[] crldpExtOctets = ((DEROctetString) oAsnInStream.readObject()).getOctets();
			try(ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets))) {
				for (DistributionPoint dp : CRLDistPoint.getInstance(oAsnInStream2.readObject()).getDistributionPoints()) {
					DistributionPointName name = dp.getDistributionPoint();
					// look for URIs in fullName
					if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
						GeneralName[] generalNames = GeneralNames.getInstance(name.getName()).getNames();
						// look for an URI
						for(GeneralName generalName : generalNames) {
							if(generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
								String url = DERIA5String.getInstance(generalName.getName()).getString();
								urls.add(url);
							}
						}
					}
				}
				return urls;
			}
		}
	}

}