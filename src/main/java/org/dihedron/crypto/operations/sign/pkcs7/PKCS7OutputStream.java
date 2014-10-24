/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */
package org.dihedron.crypto.operations.sign.pkcs7;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.dihedron.core.License;
import org.dihedron.crypto.constants.SignatureAlgorithm;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.operations.sign.SignerOutputStream;
import org.dihedron.crypto.operations.sign.SignerOutputStreamConfigurator;
import org.dihedron.crypto.providers.AutoCloseableProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class PKCS7OutputStream extends SignerOutputStream {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(PKCS7OutputStream.class);
	
	/**
	 * The underlying BouncyCastle stream data signer.
	 */
	private CMSSignedDataStreamGenerator generator = null;	
	
	/**
	 * The internal signing stream.
	 */
	private OutputStream stream = null; 

	/**
	 * Constructor.
	 * 
	 * @param output
	 *   the output stream to which data will be eventually written.
	 * @param configurator
	 *   the output signing stream configurator.
	 * @throws CryptoException
	 *   if any of the input parameters is null.
	 */
	public PKCS7OutputStream(OutputStream output, SignerOutputStreamConfigurator configurator) throws CryptoException {
		super(output, configurator);
		
		logger.info("creating PKCS#7 signer with '{}' signature algorithm, using certificate alias '{}'", configurator.getAlgorithm(), configurator.getAlias());
		
		try {
			logger.info("signing with alias '{}'", configurator.getAlias());

			// retrieve key, certificate and provider (for simplicity)
			Key key = configurator.getPrivateKey();
			X509Certificate x509certificate = configurator.getCertificate();
			Provider provider = configurator.getProvider();
			SignatureAlgorithm algorithm = configurator.getAlgorithm();
			
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
			
			stream = generator.open(output, configurator.isEncapsulateData());
			
    	} catch (OperatorCreationException e) {
			logger.error("error creating operator", e);
			throw new CryptoException("error creating signing operator (BouncyCastle)", e);
		} catch (CertificateEncodingException e) {
			logger.error("invalid certificate encoding", e);
			throw new org.dihedron.crypto.exceptions.CertificateEncodingException("invalid certificate encoding", e);
//		} catch (CertificateExpiredException e) {
//			logger.error("expired certificate", e);
//			throw new org.dihedron.crypto.exceptions.CertificateExpiredException("expired certificate", e);
//		} catch (CertificateNotYetValidException e) {
//			logger.error("certificate is not yet valid (may still need to be activated?)", e);
//			throw new org.dihedron.crypto.exceptions.CertificateNotYetValidException("certificate not yet valid", e);
		} catch (CMSException e) {
			logger.error("error adding certificates to signature generator", e);
			throw new CryptoException("CMS error", e);
		} catch (IOException e) {
			logger.error("error establishing signature generator wrapper around output stream", e);
			throw new CryptoException("Error establishing signature generator wrapper around output stream", e);
		}
	}	
	
	/**
	 * Writes the specified byte to this output stream. 
	 * 
	 * @throws IOException 
	 */
	public void write(int b) throws IOException {
		logger.trace("writing 1 byte to stream");
		stream.write(b);
	}
	
	/**
	 * Writes bytes.length bytes to this output stream.
	 * 
	 * @param bytes
	 *   the data to be written.
	 * @throws IOException 
	 */
	@Override
	public void write(byte[] bytes) throws IOException {
		logger.trace("writing {} bytes to stream", bytes.length);
		stream.write(bytes);
	}
	
	/**
	 * Writes length bytes from the specified byte array starting at the given
	 * offset to this output stream.
	 * 
	 * @param bytes
	 *   an array holding the data to be written.
	 * @param offset
	 *   the offset at which to start writing data.
	 * @param length
	 *   the number of bytes to write starting at the given offset.
	 */
	@Override
	public void write(byte[] bytes, int offset, int length) throws IOException {
		logger.trace("writing {} bytes at offset {} to stream", length, offset);
		stream.write(bytes, offset, length);
	}
	
	/**
	 * Flushes this output stream and forces any buffered output bytes to be 
	 * written out to the stream.
	 * 
	 * @throws IOException 
	 */
	@Override
	public void flush() throws IOException {
		stream.flush();
		super.flush();
	}	
	
	/**
	 * Closes this output stream and releases any system resources associated 
	 * with the stream.
	 * 
	 * @throws IOException 
	 */
	@Override
	public void close() throws IOException {
		stream.close();
		super.close();
	}
}
