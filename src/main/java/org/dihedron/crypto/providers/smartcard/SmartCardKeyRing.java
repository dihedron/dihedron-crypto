/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;

import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.dihedron.core.License;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.exceptions.InvalidPinException;
import org.dihedron.crypto.exceptions.LockedPinException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class SmartCardKeyRing extends KeyRing {
	/**
	 * The logger
	 */
	private static final Logger logger = LoggerFactory.getLogger(SmartCardKeyRing.class);

	/**
	 * The type of the PKCS#11 key store.
	 */
	private static final String SUN_PKCS11_KEYSTORE_TYPE = "PKCS11";
		
	/**
	 * Constructor.
	 * 
	 * @param provider
	 *   the Provider used to acquire a reference to the KeyStore.
	 * @param password
	 *   the key store password (PIN).
	 * @throws InvalidPinException 
	 * @throws LockedPinException 
	 * @throws CryptoException
	 */
	public SmartCardKeyRing(Provider provider, String password) throws InvalidPinException, LockedPinException, CryptoException {
		try {
			
			if(keystore != null) {
				logger.info("reopening key store, need to close previous reference first");
				close();
			}
			
			logger.info("getting the keystore for PKCS#11 provider '{}'...", provider != null ? provider.getName() : "<null>");

			// NOTE: looks like you cannot use a wrapper here, probably because 
			// the engine uses reflection to do its job; unwrapping on the fly
			// is really ugly, but it's effective 
			keystore = KeyStore.getInstance(SUN_PKCS11_KEYSTORE_TYPE, (provider instanceof SmartCardProvider) ? ((SmartCardProvider)provider).getWrappedProvider() : provider);
			
//			CallbackHandler callback = new PKCS11CallbackHandler(password);
//			java.security.KeyStore.Builder builder = java.security.KeyStore.Builder.newInstance(SUN_PKCS11_KEYSTORE_TYPE, provider, new CallbackHandlerProtection(callback));
//			KeyStore keystore = builder.getKeyStore();
			
			logger.info("... keystore for PKCS#11 provider '{}' retrieved", provider.getName());
			keystore.load(null, password != null ? password.toCharArray() : null);
			logger.info("... keystore for PKCS#11 provider '{}' logged into", provider.getName());
		} catch (KeyStoreException e) {
			logger.error("error accessing keystore from provider '" + provider.getName() + "'", e);
			throw new CryptoException("error accessing the keystore on provider '" + provider.getName() + "'", e);
		} catch (NoSuchAlgorithmException e) {
			logger.error("non existing algorithm accessing keystore from provider '" + provider.getName() + "'", e);
			throw new CryptoException("non existing algorithm accessing the keystore on provider '" + provider.getName() + "'", e);
		} catch (CertificateException e) {
			logger.error("certificate error accessing keystore from provider '" + provider.getName() + "'", e);
			throw new CryptoException("certificate error accessing the keystore on provider '" + provider.getName() + "'", e);
		} catch (IOException e) {
			if(e.getCause() != null && e.getCause() instanceof FailedLoginException) {
				FailedLoginException cause = (FailedLoginException)e.getCause();
				logger.error("cannot login to smart card, message: '" + cause.getCause().getMessage() + "'", e.getCause());
				if(cause.getCause() != null && "CKR_PIN_INCORRECT".equalsIgnoreCase(cause.getCause().getMessage())) {
					logger.error("the smart card PIN is incorrect");
					throw new InvalidPinException("error logging on to smart card: invalid PIN", cause);
				}
			} else if(e.getCause() != null && e.getCause() instanceof LoginException) {
				LoginException cause = (LoginException)e.getCause();
				if(cause.getCause() != null && "CKR_PIN_LOCKED".equalsIgnoreCase(cause.getCause().getMessage())) {
					logger.error("the smart card PIN is locked");
					throw new LockedPinException("error logging on to smart card: PIN locked", cause);					
				}				
			}
			logger.error("communication error accessing keystore from provider '" + provider.getName() + "'", e);
			throw new CryptoException("communication error accessing the key store on provider '" + provider.getName() + "'", e);
		}
	}

	/**
	 * @see AutoCloseable#close()
	 */
	@Override
	public void close() {
		logger.trace("nothing to do to release PKCS#11 key store");
	}
}
