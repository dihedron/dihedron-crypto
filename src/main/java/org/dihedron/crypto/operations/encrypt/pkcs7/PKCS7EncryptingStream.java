/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */
package org.dihedron.crypto.operations.encrypt.pkcs7;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.dihedron.crypto.operations.encrypt.EncryptingStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public class PKCS7EncryptingStream extends EncryptingStream {
	/**
	 * The logger.
	 */
	public static final Logger logger = LoggerFactory.getLogger(PKCS7EncryptingStream.class);

	/**
	 * The wrapped output stream.
	 */
	private OutputStream stream;
	
	/**
	 * Constructor.
	 * 
	 * @param output
	 *   the output stream, to which encrypted data will be written.
	 * @param certificate
	 *   the certificate to be used for encryption.
	 */
	public PKCS7EncryptingStream(OutputStream output, Certificate certificate) {
		super(output, certificate);
		
		logger.info("encrypting data through certificate supporting algorithm: '{}'", certificate.getPublicKey().getAlgorithm());
		 
		if(certificate instanceof X509Certificate) {
			String[] issuerInfo = ((X509Certificate)certificate).getIssuerDN().getName().split("(=|, )", -1);
			String[] subjectInfo = ((X509Certificate)certificate).getSubjectDN().getName().split("(=|, )", -1);
	
			logger.debug("common name (CN) : '{}'", subjectInfo[3]);
			logger.debug("address          : '{}'", subjectInfo[1]);
	
			for (int i = 0; i < issuerInfo.length; i += 2){
				if (issuerInfo[i].equals("C")) {
					logger.debug("CountryName : '{}'", issuerInfo[i + 1]);
				}
			  	if (issuerInfo[i].equals("O")) {
			  		logger.debug("OrganizationName : '{}'", issuerInfo[i + 1]);
			  	}
			  	if (issuerInfo[i].equals("CN")) {
			  		logger.debug("CommonName : '{}'", issuerInfo[i + 1]);
			  	}
			}
			logger.debug("certificate is valid from {} until {}", ((X509Certificate)certificate).getNotBefore(), ((X509Certificate)certificate).getNotAfter());
		}
	
		try {
			logger.info("preparing encrypting stream...");
			CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();
			generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator((X509Certificate)certificate).setProvider("BC"));  
			stream = generator.open(output, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build());
			logger.info("encrypting stream ready!");
		} catch(CMSException ex){
			 logger.error("CMSException: ", ex.getUnderlyingException());
		} catch (IOException e) {
			 logger.error("couldn't generate enveloped signature");
		} catch (CertificateEncodingException e) {
			logger.error("certificate encoding error", e);
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
