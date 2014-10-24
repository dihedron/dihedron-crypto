/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.verify.pkcs7;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.dihedron.core.License;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.operations.verify.Verifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class PKCS7Verifier extends Verifier {
	
	/**
	 * The logger.
	 */
	private static Logger logger = LoggerFactory.getLogger(PKCS7Verifier.class);

	/**
	 * @see org.dihedron.crypto.operations.verify.Verifier#verify(byte[])
	 */
	@Override
	public boolean verify(byte [] signed) throws CryptoException {
		return verify(signed, null);
	}
	
	/**
	 * @see org.dihedron.crypto.operations.verify.Verifier#verify(byte[], byte[])
	 */
	@Override
	public boolean verify(byte [] data, byte [] signature) throws CryptoException {
		try {
			return verify(new CMSSignedData(new CMSProcessableByteArray(data), signature));
		} catch (CMSException e) {
			logger.error("error creating CMSSignedData object", e);
			throw new CryptoException("Error creating CMSSignedData object", e);
		}
	}

	/**
	 * @see org.dihedron.crypto.operations.verify.Verifier#verify(java.io.InputStream)
	 */
	@Override
	public boolean verify(InputStream signed) throws CryptoException {
		boolean result = true;
		try {
			CMSSignedDataParser parser = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), signed);
			parser.getSignedContent().drain();
			Store store = parser.getCertificates();
		
			for(Object signer : parser.getSignerInfos().getSigners()) {				
				for(Object object : store.getMatches(((SignerInformation)signer).getSID())) {					
					X509CertificateHolder cert = (X509CertificateHolder)object;
					logger.trace("verifying signer '{}'", cert.getSubject());
					result = result && ((SignerInformation)signer).verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
					logger.trace("verify returns: {}", result);
				}
			}
			logger.trace("data {} verified", result ? "was" : "was not");
			return result;
		} catch (OperatorCreationException | CMSException | IOException | CertificateException e) {
			throw new CryptoException("error verifying the signature in streaming mode", e);
		}
	}	
	
	/**
	 * Verifies a detached signature, given the array of bytes on which it was 
	 * originally calculated.
	 *  
	 * @param data
	 *   the object containing the data and its signature.
	 * @return
	 *   whether the data has not been tampered with.
	 * @throws CryptoException
	 */
	public boolean verify(CMSSignedData data) throws CryptoException {
		try {
			logger.debug("starting CMSSignedData verification ... ");
			
			return data.verifySignatures(new SignerInformationVerifierProvider() {
				
				private final Logger logger = LoggerFactory.getLogger(SignerInformationVerifierProvider.class);
				
				private CMSSignedData data = null;
				
				public SignerInformationVerifierProvider setData(CMSSignedData data) {
					this.data = data;					
					return this;
				}			
	
				@Override
				public SignerInformationVerifier get(SignerId sid) throws OperatorCreationException {
					logger.trace("checking signature by SID: '{}'", sid);
					@SuppressWarnings("unchecked")
					Collection<X509CertificateHolder> certificates = (Collection<X509CertificateHolder>)data.getCertificates().getMatches(sid);
					logger.debug("{} certificates found", certificates.size());
					try {
						return new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificates.iterator().next());
					} catch (CertificateException e) {
						throw new OperatorCreationException("error creating signer information verifier", e);
					}
				}			
			}.setData(data));
		} catch(CMSException e) {
			logger.error("CMS exception verifying signatures", e);
			throw new CryptoException("CMS exception verifying signatures", e);    		 
		}
	}	
}
