/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.verify.pkcs7;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
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
					X509CertificateHolder holder = (X509CertificateHolder)object;
					logger.trace("verifying signer '{}'", holder.getSubject());
					result = result && ((SignerInformation)signer).verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(holder));
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
	 * @see org.dihedron.crypto.operations.verify.Verifier#verify(byte[])
	 */
	@Override
	public boolean verify(byte [] signed) throws CryptoException {
		try {
			return verify(new CMSSignedData(signed), null);
		} catch (CMSException e) {
			logger.error("error creating CMSSignedData object", e);
			throw new CryptoException("Error creating CMSSignedData object", e);
		}
	}
	
	/**
	 * @see org.dihedron.crypto.operations.verify.Verifier#verify(byte[], byte[])
	 */
	@Override	
	public boolean verify(byte [] signed, byte [] data) throws CryptoException {
		try {
			return verify(new CMSSignedData(signed), data);
		} catch (CMSException e) {
			logger.error("error creating CMSSignedData object", e);
			throw new CryptoException("Error creating CMSSignedData object", e);
		}
	}
	
	@SuppressWarnings("unchecked")
	private boolean verify(CMSSignedData signed, byte [] data) throws CryptoException {
		
    	try {
    		logger.debug("starting CMSSignedData verification ... ");
    		    		
        	SignerInformationStore signers = signed.getSignerInfos();
        	Store certificates = signed.getCertificates();

        	logger.debug("{} signers found", signers.getSigners().size()); 
    		
        	// loop over signers and their respective certificates and check if
        	// the signature is verified (no check is made on certificates); exit
        	// as soon as a verification fails, otherwise return a sound "verified" 
	    	for (SignerInformation signer : (Iterable<SignerInformation>)signers.getSigners()) {
	    		logger.debug("{} certificates found for signer '{}'", certificates.getMatches(signer.getSID()).size(), signer.getSID());
	    		for (Object certificate : certificates.getMatches(signer.getSID())) {
	    			if(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build((X509CertificateHolder)certificate))) {
						logger.info("signature verified for signer '{}'", signer.getSID());
	    			} else {
						logger.error("signature verification failed for signer '{}'", signer.getSID());
						return false;
	    			}
	    		}
	    	}
	    	logger.info("all signatures successfully verified");
	    	return true;
    	} catch (OperatorCreationException e) {
			logger.error("error creating operator", e);
			throw new CryptoException("Error creating operator", e);
		} catch (CertificateException e) {
			logger.error("invalid certificate", e);
			throw new CryptoException("Invalid certificate", e);
		} catch (CMSException e) {
			logger.error("CMS error", e);
			throw new CryptoException("CMS error", e);
		}
	}		
	
//	/**
//	 * Verifies a detached signature, given the array of bytes on which it was 
//	 * originally calculated.
//	 *  
//	 * @param data
//	 *   the object containing the data and its signature.
//	 * @return
//	 *   whether the data has not been tampered with.
//	 * @throws CryptoException
//	 */
//	public boolean verify(CMSSignedData data) throws CryptoException {
//		try {
//			logger.debug("starting CMSSignedData verification ... ");
//			
//			return data.verifySignatures(new SignerInformationVerifierProvider() {
//				
//				private final Logger logger = LoggerFactory.getLogger(SignerInformationVerifierProvider.class);
//				
//				private CMSSignedData data = null;
//				
//				public SignerInformationVerifierProvider setData(CMSSignedData data) {
//					this.data = data;					
//					return this;
//				}			
//	
//				@Override
//				public SignerInformationVerifier get(SignerId sid) throws OperatorCreationException {
//					logger.trace("checking signature by SID: '{}'", sid);
//					@SuppressWarnings("unchecked")
//					Collection<X509CertificateHolder> certificates = (Collection<X509CertificateHolder>)data.getCertificates().getMatches(sid);
//					logger.debug("{} certificates found", certificates.size());
//					try {
//						return new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificates.iterator().next());
//					} catch (CertificateException e) {
//						throw new OperatorCreationException("error creating signer information verifier", e);
//					}
//				}			
//			}.setData(data));
//		} catch(CMSException e) {
//			logger.error("CMS exception verifying signatures", e);
//			throw new CryptoException("CMS exception verifying signatures", e);    		 
//		}
//	}	
}
