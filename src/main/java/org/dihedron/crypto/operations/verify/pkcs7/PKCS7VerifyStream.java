/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.verify.pkcs7;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.dihedron.core.License;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.operations.verify.VerifyInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class PKCS7VerifyStream extends VerifyInputStream {
	
	/**
	 * The logger.
	 */
	private static Logger logger = LoggerFactory.getLogger(PKCS7VerifyStream.class);

	/**
	 * Whether the input stream contains a verified signature.
	 */
	private boolean verified = true;

	/**
	 * Constructor.
	 * 
	 * @param input
	 *   the input stream.
	 * @throws CryptoException
	 */
	public PKCS7VerifyStream(InputStream input) throws CryptoException {
		super(input);
		try {
			CMSSignedDataParser parser = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), input);
			parser.getSignedContent().drain();
			Store store = parser.getCertificates();
		
			for(Object signer : parser.getSignerInfos().getSigners()) {				
				for(Object object : store.getMatches(((SignerInformation)signer).getSID())) {					
					X509CertificateHolder holder = (X509CertificateHolder)object;
					logger.trace("verifying signer '{}'", holder.getSubject());
					verified = verified && ((SignerInformation)signer).verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(holder));
					logger.trace("verify returns: {}", verified);
				}
			}
			logger.trace("data {} verified", verified ? "was" : "was not");
		} catch (OperatorCreationException | CMSException | IOException | CertificateException e) {
			throw new CryptoException("error verifying the signature in streaming mode", e);
		}
	}

	/**
	 * @see org.dihedron.crypto.operations.verify.VerifyInputStream#isVerified()
	 */
	@Override
	public boolean isVerified() {
		return verified;
	}	
}
