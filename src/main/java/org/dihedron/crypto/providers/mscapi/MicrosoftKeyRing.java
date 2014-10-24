/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.mscapi;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.dihedron.core.License;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class MicrosoftKeyRing extends KeyRing {
	/**
	 * The logger
	 */
	private static final Logger logger = LoggerFactory.getLogger(MicrosoftKeyRing.class);

	/**
	 * The name of the key store used by Microsoft CryptoAPI to propagate 
	 * certificates from the smart card. 
	 */
	public static final String MSCAPI_PERSONAL_KEYSTORE = "Windows-MY";
	
	/**
	 * Constructor.
	 * 
	 * @param password
	 *   the provider PIN.
	 */
	public MicrosoftKeyRing(String password) throws CryptoException {
		try {
			if(keystore != null) {
				logger.info("reopening key store, need to cllose previous reference first");
				close();
			}			
			logger.info("getting the keystore for MSCryptoAPI provider...");
			keystore = KeyStore.getInstance(MSCAPI_PERSONAL_KEYSTORE);
			logger.info("... keystore for MSCryptoAPI provider retrieved");
			keystore.load(null, password != null ? password.toCharArray() : null);
			logger.info("... keystore for MSCryptoAPI provider logged into");			
		} catch (KeyStoreException e) {
			logger.error("error accessing the keystore", e);
			throw new CryptoException("Error accessing the keystore", e);
		} catch (NoSuchAlgorithmException e) {
			logger.error("invalid algorithm specified in keystore access", e);
			throw new CryptoException("Invalid algorithm specified in keystore access", e);
		} catch (CertificateException e) {
			logger.error("error accessing the certificate", e);
			throw new CryptoException("Error accessing the certificate", e);
		} catch (IOException e) {
			logger.error("I/O exception while accessing the keystore", e);
			throw new CryptoException("I/O exception accessing the keystore", e);
		}
	}

	/**
	 * @see AutoCloseable#close()
	 */
	@Override
	public void close(){
	}
}
