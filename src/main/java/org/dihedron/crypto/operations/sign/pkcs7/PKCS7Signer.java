/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.sign.pkcs7;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.dihedron.core.License;
import org.dihedron.core.streams.Streams;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.constants.SignatureAlgorithm;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.operations.sign.Signer;
import org.dihedron.crypto.providers.AutoCloseableProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class PKCS7Signer extends Signer {
	
	/**
	 * The logger.
	 */
	private static Logger logger = LoggerFactory.getLogger(PKCS7Signer.class);
	
//	/**
//	 * The digest and encryption algorithm combination used to create the signature.
//	 */
//	private SignatureAlgorithm algorithm;
	
//	/**
//	 * A BouncyCastle to create signature data.
//	 */
//	private SignerInfoGenerator signerInfoGenerator = null;
	
	/**
	 * The underlying BouncyCastle stream data signer.
	 */
	private CMSSignedDataStreamGenerator generator = null;

	/**
	 * Constructor.
	 * 
	 * @param alias
	 *   the alias of the certificate to be used for signing.
	 * @param keyring
	 *   the key ring containing the private key used for signing.
	 * @param provider
	 *   the security provider backing up the key ring functionalities.
	 * @param algorithm
	 *   the digest and encryption algorithm combination used to create the 
	 *   signature.
	 * @throws CryptoException
	 *   if any among alias, key ring and provider is null. 
	 */
	public PKCS7Signer(String alias, KeyRing keyring, Provider provider, SignatureAlgorithm algorithm) throws CryptoException {
		super(alias, keyring, provider);
		logger.debug("creating PKCS#7 signer with '{}' signature algorithm", algorithm);
		try {
			logger.info("signing with alias '{}'", alias);

			// retrieve key and certificate
			Key key = keyring.getPrivateKey(alias);
			X509Certificate x509certificate = (X509Certificate)keyring.getCertificate(alias);
			
			// this may throw a CertificateExpiredException or CertificateNotYetValidException
			x509certificate.checkValidity();			
			logger.info("certificate is valid at current date");
			
			// TODO: check CRL
			
			logger.info("certificate is active at current date (CRL check successful)");
			
			// prepare the certificates store
			List<Certificate> certificates = new ArrayList<>();      	      
			certificates.add(x509certificate);			
			Store store = new JcaCertStore(certificates);									

			logger.info("certificate store is ready");
			
			ContentSigner signer = new JcaContentSignerBuilder(algorithm.toBouncyCastleCode())
					.setProvider((provider instanceof AutoCloseableProvider) ? ((AutoCloseableProvider)provider).getWrappedProvider() : provider)
					.build((PrivateKey)key);	
			
			DigestCalculatorProvider digest = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
			
			SignerInfoGenerator signerinfo = 
					new SignerInfoGeneratorBuilder(digest)
						.setDirectSignature(false) 	// include signed attributes; if true it signs data only
						.setSignedAttributeGenerator(
							new PKCS7AttributeTableGenerator(algorithm.getDigestAlgorithm(), x509certificate)
						)  // this generates the attributes that will be signed along with the data
						.build(signer, new JcaX509CertificateHolder(x509certificate));	// and then we build the generator
			
			logger.info("signer info generator is ready");
			
			generator = new CMSSignedDataStreamGenerator();
			generator.addSignerInfoGenerator(signerinfo);
			generator.addCertificates(store);
			//generator.addCRLs(crlStore);
						
			logger.debug("signed data stream generator for PKCS#7 is ready");
			
    	} catch (OperatorCreationException e) {
			logger.error("error creating operator", e);
			throw new CryptoException("error creating signing operator (BouncyCastle)", e);
		} catch (CertificateEncodingException e) {
			logger.error("invalid certificate encoding", e);
			throw new org.dihedron.crypto.exceptions.CertificateEncodingException("invalid certificate encoding", e);
		} catch (CertificateExpiredException e) {
			logger.error("expired certificate", e);
			throw new org.dihedron.crypto.exceptions.CertificateExpiredException("expired certificate", e);
		} catch (CertificateNotYetValidException e) {
			logger.error("certificate is not yet valid (may still need to be activated?)", e);
			throw new org.dihedron.crypto.exceptions.CertificateNotYetValidException("certificate not yet valid", e);
		} catch (CMSException e) {
			logger.error("error adding certificates to signature generator", e);
			throw new CryptoException("CMS error", e);
		}
	}
	
	/**
	 * Constructor.
	 * 
	 * @param alias
	 *   the alias of the certificate to be used for signing.
	 * @param keyring
	 *   the key ring containing the private key used for signing.
	 * @param provider
	 *   the security provider backing up the key ring functionalities.
	 * @param digest
	 *   the algorithm used to hash the data.
	 * @param encryption
	 *   the algorithm used to encrypt the hash.
	 * @throws CryptoException
	 *   if any among alias, key ring and provider is null. 
	 */
	public PKCS7Signer(String alias, KeyRing keyring, Provider provider, String digest, String encryption) throws CryptoException {
		  this(alias, keyring, provider, SignatureAlgorithm.fromAlgorithmDescriptions(digest, encryption));
	}

	/**
	 * Signs the given byte array, returning the signed version.
	 * 
	 * @param data
	 *   the array of bytes to sign.
	 * @return 
	 *   the signed data, as a byte array.
	 */
	@Override
	public byte [] sign(byte [] data) throws CryptoException {
		try(ByteArrayInputStream input = new ByteArrayInputStream(data); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
			sign(input, output);
			return output.toByteArray();
		} catch (IOException e) {
			logger.error("error copying data from input stream to signature generator wrapper stream");
			throw new CryptoException("error copying data from input stream to signature generator wrapper stream", e); 
		}
	}
	
	/**
	 * Signs whatever can be read from the given input stream, writing the signed 
	 * version into the given output stream.
	 * 
	 * @param input
	 *   an input stream from which data to be signed can be read.
	 * @param output
	 *   an output stream into which signed data will be written.
	 */
	@Override
	public void sign(InputStream input, OutputStream output) throws CryptoException {
		try(OutputStream stream = generator.open(output, encapsulate)) {
			logger.trace("copying data into generator filter stream...");
			long copied = Streams.copy(input, stream);
			logger.trace("... done copying {} bytes into generator filter stream", copied);
		} catch (IOException e) {
			logger.error("error opening signature generator wrapper output stream", e);
			throw new CryptoException("error opening signature generator wrapper output stream", e);
		}
	}
}
