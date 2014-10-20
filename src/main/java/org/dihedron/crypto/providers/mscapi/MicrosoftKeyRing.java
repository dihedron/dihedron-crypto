/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved.
 * 
 * This file is part of the Crypto library ("Crypto").
 *
 * Crypto is free software: you can redistribute it and/or modify it under 
 * the terms of the GNU Lesser General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option) 
 * any later version.
 *
 * Crypto is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR 
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License 
 * along with Crypto. If not, see <http://www.gnu.org/licenses/>.
 */
package org.dihedron.crypto.providers.mscapi;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
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
