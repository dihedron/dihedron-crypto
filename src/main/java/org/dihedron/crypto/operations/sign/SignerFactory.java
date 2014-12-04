/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.sign;


import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

import org.dihedron.core.License;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.constants.SignatureAlgorithm;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.exceptions.UnsupportedFormatException;
import org.dihedron.crypto.operations.EnvelopeFormat;
import org.dihedron.crypto.operations.sign.pkcs7.PKCS7Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory class for signers; depending on the requested signature format, it
 * will create the appropriate signer.
 *  
 * @author Andrea Funto'
 */
@License
public class SignerFactory {
	
	private static Logger logger = LoggerFactory.getLogger(SignerFactory.class);
	
	/**
	 * Creates a signer of the given type, initialising it with the given 
	 * algorithm information and the given key store to access the private key.
	 * 
	 * @param format
	 *   the type of signer to instantiate (the signature format).
	 * @param alias
	 *   the alias of the certificate to be used for signing.
	 * @param keyring
	 *   the key store containing the private key.
	 * @param provider
	 *   the security provider backing up the key store.
	 * @param algorithm
	 *   the algorithm to be used for signing.
	 * @return
	 *   A Signer object.
	 * @throws CryptoException
	 * @throws KeyStoreException 
	 * @throws CertificateNotYetValidException 
	 * @throws CertificateEncodingException 
	 * @throws CertificateExpiredException 
	 */
	public static Signer makeSigner(EnvelopeFormat format, String alias, KeyRing keyring, Provider provider, SignatureAlgorithm algorithm) throws CryptoException, CertificateEncodingException, CertificateNotYetValidException, KeyStoreException, CertificateExpiredException {
		
		Signer signer = null;
		
		switch(format) {
		case PKCS7:
			signer = new PKCS7Signer(alias, keyring, provider, algorithm);
			break;
		default:
			logger.error("unsupported signer type: '{}'", format);
			throw new UnsupportedFormatException("unsupported signer type: " + format);
		}		 
		return signer;
	}	
}
