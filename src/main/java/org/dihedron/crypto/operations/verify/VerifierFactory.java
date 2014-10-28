/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.verify;


import org.dihedron.core.License;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.exceptions.UnsupportedFormatException;
import org.dihedron.crypto.operations.SignatureFormat;
import org.dihedron.crypto.operations.verify.pkcs7.PKCS7Verifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory class for verifier; depending on the requested signature format, it
 * will create the appropriate verifier.
 *  
 * @author Andrea Funto'
 */
@License
public class VerifierFactory {
	
	private static Logger logger = LoggerFactory.getLogger(VerifierFactory.class);
	
	/**
	 * Creates a verifier of the given type.
	 * 
	 * @param format
	 *   the type of verifier to instantiate (the signature format).
	 * @return
	 *   A Verifier object.
	 * @throws CryptoException
	 */
	public static Verifier makeVerifier(SignatureFormat format) throws CryptoException {
		
		Verifier verifier = null;
		
		switch(format) {
		case PKCS7:
			verifier = new PKCS7Verifier();
			break;
		default:
			logger.error("unsupported verifier type: '{}'", format);
			throw new UnsupportedFormatException("unsupported verifier type: " + format);
		}		 
		return verifier;
	}	
}
