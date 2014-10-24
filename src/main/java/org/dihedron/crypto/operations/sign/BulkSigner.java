/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.sign;

import java.security.Provider;

import org.dihedron.core.License;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;

/**
 * @author Andrea Funto'
 */
@License
public abstract class BulkSigner extends Signer {

	/**
	 * Constructor.
	 * 
	 * @param alias
	 *   the alias of the certificate to be used for signing.
	 * @param keyring
	 *   the key ring, as a wrapper and helper to access the key store.
	 * @param provider
	 *   the security provider supporting and exposing the key store capabilities.
	 * @throws CryptoException
	 *   if any of the input parameters is null.
	 */
	public BulkSigner(String alias, KeyRing keyring, Provider provider) throws CryptoException {
		super(alias, keyring, provider);
	}

	/**
	 * Signs the given set of data.
	 * 
	 * @param data
	 *   the data to be signed.
	 * @return
	 *   the signed data as a byte array.
	 * @throws CryptoException
	 */
	public abstract byte [] sign(byte [] data) throws CryptoException;	
}
