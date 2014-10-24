/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */
package org.dihedron.crypto.operations.sign;

import java.security.Key;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.dihedron.core.License;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.certificates.Certificates;
import org.dihedron.crypto.constants.SignatureAlgorithm;
import org.dihedron.crypto.exceptions.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@License
public class SignerOutputStreamConfigurator {
	
	/**
	 * Whether by default data should be encapsulated along with the signature.
	 */
	public static final boolean DEFAULT_ENCAPSULATE_DATA = true;
	
	/**
	 * Whether by default the signing certificate must be verified. 
	 */
	public static final boolean DEFAULT_VERIFY_CERTIFICATE = true;
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(SignerOutputStreamConfigurator.class);
	
	/**
	 * The digest and encryption algorithm combination used to create the signature.
	 */
	protected SignatureAlgorithm algorithm;
	
	/**
	 * The alias identifying the certificate to be used for signing.
	 */
	protected String alias;
	
	/**
	 * The key ring (as a wrapper and helper to access the key store).
	 */
	protected KeyRing keyring = null;

	/**
	 * The security provider.
	 */
	protected Provider provider = null;
	
	/**
	 * A collection of certificates to be used as trust anchors in PKIX certification
	 * path buildup and verification.
	 */
	protected List<X509Certificate> trustAnchors = new ArrayList<>(); 

	/**
	 * Whether the signer should encapsulate data along with the signature. 	
	 */
	protected boolean encapsulateData = DEFAULT_ENCAPSULATE_DATA;

	/**
	 * Whether the signer should verify the certificate before signing. 	
	 */
	protected boolean verifyCertificate = DEFAULT_VERIFY_CERTIFICATE;
	
	/**
	 * Default constructor.
	 */
	public SignerOutputStreamConfigurator() {		
	}

	/**
	 * Returns the value of the algorithm.
	 *
	 * @return 
	 *   the value of the algorithm.
	 */
	public SignatureAlgorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * Sets the new value of the algorithm.
	 *
	 * @param algorithm 
	 *   the algorithm to set.
	 * @return
	 *   the object itself, for method chaining.
	 */
	public SignerOutputStreamConfigurator setAlgorithm(SignatureAlgorithm algorithm) {
		this.algorithm = algorithm;
		return this;
	}

	/**
	 * Returns the value of the alias.
	 *
	 * @return 
	 *   the value of the alias.
	 */
	public String getAlias() {
		return alias;
	}

	/**
	 * Sets the new value of the signing certificate alias.
	 *
	 * @param alias 
	 *   the alias to set.
 	 * @return
	 *   the object itself, for method chaining.
	 */
	public SignerOutputStreamConfigurator setAlias(String alias) {
		this.alias = alias;
		return this;
	}

	/**
	 * Returns the value of the key ring.
	 *
	 * @return 
	 *   the value of the key ring.
	 */
	public KeyRing getKeyRing() {
		return keyring;
	}

	/**
	 * Sets the new value of the key ring.
	 *
	 * @param keyring 
	 *   the key ring to set.
	 * @return
	 *   the object itself, for chaining.
	 */
	public SignerOutputStreamConfigurator setKeyRing(KeyRing keyring) {
		this.keyring = keyring;
		return this;
	}

	/**
	 * Returns the value of the provider.
	 *
	 * @return 
	 *   the value of the provider.
	 */
	public Provider getProvider() {
		return provider;
	}

	/**
	 * Sets the new value of the provider.
	 *
	 * @param provider 
	 *   the provider to set.
	 * @return  
	 *   the object itself, for method chaining.
	 */
	public SignerOutputStreamConfigurator setProvider(Provider provider) {
		this.provider = provider;
		return this;
	}

	/**
	 * Returns whether the signer should encapsulate data along with the signature.
	 *
	 * @return 
	 *   whether the signer should encapsulate data along with the signature.
	 */
	public boolean isEncapsulateData() {
		logger.trace("encapsulate data: {}", encapsulateData);
		return encapsulateData;
	}

	/**
	 * Sets whether the signer should encapsulate data along with the signature.
	 *
	 * @param encapsulateData 
	 *   whether the signer should encapsulate data along with the signature.
	 * @return
	 *   the object itself, for method chaining.
	 */
	public SignerOutputStreamConfigurator setEncapsulateData(boolean encapsulateData) {
		this.encapsulateData = encapsulateData;
		return this;
	}

	/**
	 * Returns whether the signer should verify the certificate before signing.
	 *
	 * @return 
	 *   whether the signer should verify the certificate before signing.
	 */
	public boolean isVerifyCertificate() {
		return verifyCertificate;
	}

	/**
	 * Sets whether the signer should verify the certificate before signing.
	 *
	 * @param verifyCertificate 
	 *   whether the signer should verify the certificate before signing.
	 * @return
	 *   the object itself, for method chaining.
	 */
	public SignerOutputStreamConfigurator setVerifyCertificate(boolean verifyCertificate) {
		this.verifyCertificate = verifyCertificate;
		return this;
	}
	
	/**
	 * Returns the collection of trust anchor certificates.
	 *
	 * @return 
	 *   the collection of trust anchor certificates.
	 */
	public Collection<X509Certificate> getTrustAnchors() {
		return trustAnchors;
	}

	/**
	 * Adds the given trust anchor certificate to the set that will be used for 
	 * PKIX certificate verification path buildup.
	 *
	 * @param trustAnchor 
	 *   the trust anchor certificate to add.
	 * @return 
	 *   the object itself, for method chaining.
	 */
	public SignerOutputStreamConfigurator addTrustAnchor(Certificate trustAnchor) {
		if(trustAnchor != null && trustAnchor instanceof X509Certificate) {
			this.trustAnchors.add((X509Certificate)trustAnchor);
		}
		return this;
	}
	
	/**
	 * Adds the given collection of trust anchor certificates to the set that will
	 * be used for PKIX certificate verification path buildup.
	 *
	 * @param trustAnchors 
	 *   the collection of trust anchor certificates to add.
	 * @return 
	 *   the object itself, for method chaining.
	 */
	public SignerOutputStreamConfigurator addTrustAnchors(Collection<X509Certificate> trustAnchors) {
		if(trustAnchors != null) {
			this.trustAnchors.addAll(trustAnchors);
		}
		return this;
	}
	
	/**
	 * Resets the collection of trust anchor certificates to be used for PKIX
	 * certificate verification path buildup.
	 *
	 * @return 
	 *   the object itself, for method chaining.
	 */
	public SignerOutputStreamConfigurator clearTrustAnchors() {
		trustAnchors.clear();
		return this;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer.append("{\n");
		buffer.append("\talias            : '" ).append(alias).append("',\n");
		buffer.append("\tprovider         : '" ).append(provider.getName()).append("',\n");
		buffer.append("\talgorithm        : '" ).append(algorithm.toString()).append("',\n");
		buffer.append("\tencapsulate data : '" ).append(encapsulateData).append("',\n");
		buffer.append("\tverify certif.   : '" ).append(verifyCertificate).append("',\n");
		buffer.append("\ttrust anchors    : '" ).append(trustAnchors.isEmpty() ? "empty" : trustAnchors.size() + " elements").append("'\n");
		buffer.append("}");
		return buffer.toString();
	}
	
	/**
	 * Returns the private key corresponding to the given alias.
	 * 
	 * @return
	 *   the private key corresponding to the given alias.
	 * @throws CryptoException 
	 */
	public Key getPrivateKey() throws CryptoException {
		return keyring.getPrivateKey(alias);
	}
	
	/**
	 * Retrieves the signing certificate, possibly checking it against the list
	 * of trust anchor certificates (if provided).
	 * 
	 * @param trustAnchors
	 *   an optional list of trust anchor certificate collections. 
	 * @return
	 *   the certificate, if validated.
	 * @throws CryptoException 
	 */
	public X509Certificate getCertificate() throws CryptoException {
		
		X509Certificate certificate = null;
		try {
			// retrieve the certificate from the keystore
			certificate = (X509Certificate)keyring.getCertificate(alias);
			
			// this may throw a CertificateExpiredException or CertificateNotYetValidException
			certificate.checkValidity();			
			logger.info("certificate is valid at current date");
			
			if(verifyCertificate) {
				
				logger.info("performing extensive certificate verification through TLS and CRLs...");
				
				// create a set of trust anchor and intermediate certificates by 
				// cloning the input list of trust anchors and then adding the 
				// certificates in the certificate's own certification chain
				// NOTE: we need to clone the user-provided list of trust anchors
				// because we want to be able to reuse this method multiple times 
				// without side effects				
				List<X509Certificate> anchors = new ArrayList<>();
				if(trustAnchors != null) {
					anchors.addAll(trustAnchors);
				}				
				for(Certificate c : keyring.getCertificateChain(alias)) {
					if(c != null && c instanceof X509Certificate) {
						anchors.add((X509Certificate)c);
					}
				}
		
				// now verify the certification path and the CRLs
				PKIXCertPathBuilderResult verified = Certificates.verifyCertificate(certificate, anchors);
				logger.info("... certificate has valid certification path and is not revoked (CRL check ok)");
			
				// dump certification path
				logger.trace("... certification path: ");
				for(Certificate step : verified.getCertPath().getCertificates()) {
					logger.trace("...  - step in certification path:\n{}", step);
				}
				
				// dump trust anchor
				logger.trace("... trust anchor: '{}'\n{}", verified.getTrustAnchor().getCAName(), verified.getTrustAnchor().getTrustedCert());
						
				// dump verified certificate
				logger.trace("... public key:\n{}", verified.getPublicKey());
				
				logger.info("... verification complete");
			}
			
			return certificate;
			
		} catch(CertificateExpiredException e) {
			logger.error("certificate expired at the current date (valid from " + certificate.getNotBefore() + " to " + certificate.getNotAfter() +")", e);
			throw new org.dihedron.crypto.exceptions.CertificateExpiredException("Certificate expired at the current date (valid from " + certificate.getNotBefore() + " to " + certificate.getNotAfter() +")", e);		
		} catch(CertificateNotYetValidException e) {
			logger.error("certificate not yet valid at the current date (valid from " + certificate.getNotBefore() + " to " + certificate.getNotAfter() +")", e);
			throw new org.dihedron.crypto.exceptions.CertificateNotYetValidException("Certificate not yet valid at the current date (valid from " + certificate.getNotBefore() + " to " + certificate.getNotAfter() +")", e);		
		}
	}
}
