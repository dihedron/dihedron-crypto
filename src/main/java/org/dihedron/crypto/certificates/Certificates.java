/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved.
 * 
 * This file is part of the Crypto library ("Crypto").
 *
 * Crypto is free software: you can redistribute it and/or modify it under 
 * the terms of the GNU Lesser General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option) 
 * any later version.
 *
 * Crypto is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR 
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License 
 * along with Crypto. If not, see <http://www.gnu.org/licenses/>.
 */
package org.dihedron.crypto.certificates;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.dihedron.crypto.constants.DigestAlgorithm;
import org.dihedron.crypto.crl.CRL;
import org.dihedron.crypto.exceptions.CertificateVerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Collection of utilities to manipulate certificates; it provides ways to 
 * get the certificate usage, to build a certification chain for a given 
 * certificate and to verify it. The verification process relies on a set of 
 * root CA certificates and intermediate certificates that will be used for 
 * building the certification chain; it assumes that all self-signed certificates 
 * in the set are trusted root CA certificates and all other certificates in the 
 * set are intermediate certificates.
 * 
 * @author Svetlin Nakov
 * @author Andrea Funto'
 */
public final class Certificates {
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(Certificates.class);
	
	/**
	 * Possible values of certificates usage.
	 * 
	 * @author Andrea Funto'
	 */
	private enum KeyUsage {
		digitalSignature, 
		nonRepudiation, 
		keyEncipherment, 
		dataEncipherment, 
		keyAgreement, 
		keyCertSign, 
		cRLSign, 
		encipherOnly, 
		decipherOnly;
	};
	
	/**
	 * Checks if the given certificate has all the necessary extensions to be used 
	 * as a signing certificate.
	 * 
	 * @param certificate
	 *   the certificate to test.
	 * @return
	 *   whether the certificate is good for signing.
	 */
	public static boolean isSignatureX509Certificate(X509Certificate certificate) {
		boolean[] usage = certificate.getKeyUsage();
		
		for (KeyUsage u : KeyUsage.values()) {
			if (usage[u.ordinal()]) {
				logger.trace("bit '{}' set", u.name());
			}
		}
		if (usage != null && usage[KeyUsage.keyEncipherment.ordinal()] && usage[KeyUsage.digitalSignature.ordinal()]) {
			logger.trace("this is a signing certificate (bits set)");
			return true;
		}
		return false;	
	}
	
	
	/**
	 * Checks if the given certificate has all the necessary extensions to be used 
	 * as a signing certificate (non repudiation).
	 * 
	 * @param certificate
	 *   the certificate to test.
	 * @return
	 *   whether the certificate is good for signing.
	 */
	public static boolean isNonRepudiationX509Certificate(X509Certificate certificate) {
		boolean[] usage = certificate.getKeyUsage();
		
		for (KeyUsage u : KeyUsage.values()) {
			if (usage[u.ordinal()]) {
				logger.trace("bit '{}' set", u.name());
			}
		}
		if (usage != null && usage[KeyUsage.nonRepudiation.ordinal()]) {
			logger.trace("this is a non repudiation certificate (bits set)");
			return true;
		}
		return false;	
	}
	
	/**
	 * Checks whether given X.509 certificate is self-signed.
	 */
	public static boolean isSelfSigned(X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		try {
			// try to verify certificate signature with its own public key
			PublicKey key = certificate.getPublicKey();
			certificate.verify(key);
			return true;
		} catch (SignatureException | InvalidKeyException e) {
			// invalid signature or key --> not self-signed
			return false;
		}
	}		
	
	/**
	 * Checks if the given certificate has the given OID among its critical 
	 * extensions.
	 * 
	 * @param certificate
	 *   the certificate on which to look for the critical extensio OID.
	 * @param oid
	 *   the critical extension OID to lookup.
	 * @return
	 *   whether the extension was found.
	 */
	public static boolean hasCriticalExtension(X509Certificate certificate, String oid) {
		logger.debug("looking for critical extension OID '{}'...", oid);
		Set<String> extensions = certificate.getCriticalExtensionOIDs();
		for(String extension : extensions) {			
			logger.trace("... analysing critical extension '{}'", extension);
			if(extension.contains(oid)) {
				logger.trace("... OID found!");
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Attempts to build a certification chain for given certificate and to
	 * verify it. Relies on a set of root CA certificates and intermediate
	 * certificates that will be used for building the certification chain. The
	 * verification process assumes that all self-signed certificates in the set
	 * are trusted root CA certificates and all other certificates in the set
	 * are intermediate certificates.
	 * 
	 * @param certificate
	 *   certificate for validation.
	 * @param additionalCerts
	 *   set of trusted root CA certificates that will be used as "trust anchors" 
	 *   and intermediate CA certificates that will be used as part of the 
	 *   certification chain. All self-signed certificates are considered to be 
	 *   trusted root CA certificates. All the rest are considered to be 
	 *   intermediate CA certificates.
	 * @return 
	 *   the certification chain (if verification is successful).
	 * @throws CertificateVerificationException
	 *   if the certification is not successful (e.g. certification path cannot 
	 *   be built or some certificate in the chain is expired or CRL checks are 
	 *   failed).
	 */
	public static PKIXCertPathBuilderResult verifyCertificate(X509Certificate certificate, Collection<X509Certificate> additionalCerts) throws CertificateVerificationException {
		try {
			
			logger.trace("verifying certificate:\n{}", certificate);
			
			// check for self-signed certificate
			if (isSelfSigned(certificate)) {
				logger.error("certificate is self signed");
				throw new CertificateVerificationException("the certificate is self-signed");
			}

			// prepare a set of trusted root CA certificates and a set of
			// intermediate certificates
			Set<X509Certificate> trustedRootCerts = new HashSet<>();
			Set<X509Certificate> intermediateCerts = new HashSet<>();
			for (X509Certificate additionalCert : additionalCerts) {
				if (isSelfSigned(additionalCert)) {
//					logger.trace("adding certificate '{}' to trusted root CAs", additionalCert.getSubjectX500Principal());
					trustedRootCerts.add(additionalCert);
				} else {
//					logger.trace("adding certificate '{}' to certificate chain", additionalCert.getSubjectX500Principal());
					intermediateCerts.add(additionalCert);
				}
			}

			// attempt to build the certification chain and verify it
			PKIXCertPathBuilderResult verifiedCertChain = verifyCertificate(certificate, trustedRootCerts, intermediateCerts);

			logger.info("certification chain verified");
			
			// check whether the certificate is revoked by the CRL given in its 
			// CRL distribution point extension
			CRL.verifyCertificateCRLs(certificate);
			
			logger.info("CRL verified");

			// the chain is built and verified; return it as a result
			return verifiedCertChain;
		} catch (CertPathBuilderException e) {
			logger.error("error building certification path for " + certificate.getSubjectX500Principal(), e);
			throw new CertificateVerificationException("Error building certification path: " + certificate.getSubjectX500Principal(), e);
		} catch (Exception e) {
			logger.error("error verifying certificate " + certificate.getSubjectX500Principal(), e);
			throw new CertificateVerificationException("Error verifying the certificate: " + certificate.getSubjectX500Principal(), e);
		}
	}

	/**
	 * Attempts to build a certification chain for given certificate and to
	 * verify it. Relies on a set of root CA certificates (trust anchors) and a
	 * set of intermediate certificates (to be used as part of the chain).
	 * 
	 * @param certificate
	 *   certificate for validation.
	 * @param trustedRootCerts
	 *   set of trusted root CA certificates.
	 * @param intermediateCerts
	 *   set of intermediate certificates.
	 * @return 
	 *   the certification chain (if verification is successful).
	 * @throws GeneralSecurityException
	 *   if the verification is not successful (e.g. certification path cannot 
	 *   be built or some certificate in the chain is expired).
	 */
	private static PKIXCertPathBuilderResult verifyCertificate(X509Certificate certificate, Collection<X509Certificate> trustedRootCerts, Collection<X509Certificate> intermediateCerts) throws GeneralSecurityException {

		// create the selector that specifies the starting certificate
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(certificate);

		// create the trust anchors (set of root CA certificates)
		Set<TrustAnchor> trustAnchors = new HashSet<>();
		for (X509Certificate trustedRootCert : trustedRootCerts) {
			trustAnchors.add(new TrustAnchor(trustedRootCert, null));
		}

		// configure the PKIX certificate builder algorithm parameters
		PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);

		// disable CRL checks (this is done manually as an additional step)
		pkixParams.setRevocationEnabled(false);

		// specify a list of intermediate certificates
		CertStore intermediateCertStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(intermediateCerts), "BC");
		pkixParams.addCertStore(intermediateCertStore);

		// build and verify the certification chain
		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
		return (PKIXCertPathBuilderResult) builder.build(pkixParams);
	}	
	
    /**
     * @param certificate	
     *   the certificate in which to look to the extension value.
     * @param oid 
     *   the Object Identifier of the extension.
     * @return	
     *   the extension value as an {@code ASN1Primitive} object.
     * @throws IOException
     */
    public static ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
        byte[] bytes = certificate.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octets = (ASN1OctetString) stream.readObject();
        stream = new ASN1InputStream(new ByteArrayInputStream(octets.getOctets()));
        return stream.readObject();
    }
    
	/**
	 * Creates an IssuerSerial object for the given certificate.
	 * 
	 * @param x509certificate
	 *   the certificate whose issuer serial must be retrieved.
	 * @return
	 *   the IssuerSerial object for the certificate.
	 * @throws CertificateEncodingException
	 * @throws IOException
	 */
	public static IssuerSerial makeIssuerSerial(X509Certificate x509certificate) throws CertificateEncodingException, IOException {

		// get the certificate issuer and serial
		X509CertificateHolder holder = new JcaX509CertificateHolder(x509certificate);
		
		// get the certificate serial number
		ASN1Integer serial = new ASN1Integer(holder.getSerialNumber());
		logger.debug("signer's certificate serial no.: '{}'", serial);
		
		// get the certificate issuer
		X500Name issuer = holder.getIssuer();
		logger.debug("signer's certificate principal: '{}'", issuer);

		// create the issuer and serial combination to put in the SigningCertificate[V2]
		return new IssuerSerial(issuer, holder.getSerialNumber());
	}
	
	public static ESSCertID makeESSCertIdV1(X509Certificate x509certificate, IssuerSerial issuerSerial, DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException, CertificateEncodingException {
    	logger.info("adding signing certificate v1 to signed attributes");
    	MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getAsn1Id());
    	ESSCertID essCertIdV1 = new ESSCertID(digest.digest(x509certificate.getEncoded()), issuerSerial);
    	return essCertIdV1;
    } 
	
	public static ESSCertIDv2[] makeESSCertIdV2(X509Certificate x509certificate, IssuerSerial issuerSerial, DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException, CertificateEncodingException {
    	logger.info("adding signing certificate v2 to signed attributes");    	
    	MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getAsn1Id());
    	ESSCertIDv2 essCertIdv2 = new ESSCertIDv2(digest.digest(x509certificate.getEncoded()), issuerSerial);
    	ESSCertIDv2 essCertIdv2s[] = new ESSCertIDv2[1];
    	essCertIdv2s[0] = essCertIdv2;
    	return essCertIdv2s;
    }
	
	public static CertStore makeCertificateStore(Certificate certificate) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		List<Certificate> certificates = new ArrayList<Certificate>();      	      
		certificates.add(certificate);			
		CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificates), "BC");
		return store;
	}
	
	public static boolean writeToFile(Certificate certificate, String filename) {
		boolean result = false;
		FileOutputStream fos = null;
		try {
			byte[] data = certificate.getEncoded();
			fos = new FileOutputStream(filename); 
			fos.write(data);	
			result = true;
		} catch (CertificateEncodingException e) {
			logger.error("certificate encoding error", e);
		} catch (FileNotFoundException e) {
			logger.error("file not found", e);
		} catch (IOException e) {
			logger.error("error writing certificate to disk", e);
		} finally {
			try {
				fos.flush();
				fos.close();
			} catch(IOException e) {
				logger.error("error closing output stream", e);
			}
		}
		return result;
	}
	
	/**
	 * Private constructor to prevent construction.
	 */
	private Certificates() {
		
	}	
}
