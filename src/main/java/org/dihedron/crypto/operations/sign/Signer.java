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

package org.dihedron.crypto.operations.sign;


import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;

import org.dihedron.crypto.CryptoService;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class acts as the base class, providing common functionalities, to all 
 * fashions of signers.
 */
public abstract class Signer extends CryptoService {

	/**
	 * The logger.
	 */
	private static Logger logger = LoggerFactory.getLogger(Signer.class);

	/**
	 * The alias identifying the certificate to be used for signing.
	 */
	protected String alias;
	
	/**
	 * The key ring (as a wrapper and helper to access the key store).
	 */
	protected KeyRing keyring = null;

	/**
	 * The security provider.
	 */
	protected Provider provider = null;

	/**
	 * Whether the signer should encapsulate data along with the signature. 	
	 */
	protected boolean encapsulate = true;
		
	/**
	 * Constructor.
	 * 
	 * @param alias
	 *   the alias of the certificate to be used for signing.
	 * @param keyring
	 *   the key ring, as a wrapper and helper to acces the key store.
	 * @param provider
	 *   the security provider supporting and exposing the key store capabilities.
	 * @throws CryptoException
	 *   if any of the input parameters is null. 
	 */
	protected Signer(String alias, KeyRing keyring, Provider provider) throws CryptoException {
		if(alias == null || keyring == null || provider == null) {
			throw new CryptoException("invalid initialisation data");
		}
		this.alias = alias;
		this.keyring = keyring;
		this.provider = provider;
	}
	
	/**
	 * Sets whether the data should be encapsulated along with the signature,
	 * or the signature is detached.
	 * 
	 * @param encapsulate
	 *   whether the data is encapsulated along with the signature.
	 */
	public void setEncapsulateData(boolean encapsulate) {
		this.encapsulate = encapsulate;
	}
	
	/**
	 * Returns whether the data is going to be encapsulated along with the signature.
	 * 
	 * @return
	 *   whether the data is going to be encapsulated along with the signature.
	 */
	public boolean isEncapsulateData() {
		logger.debug("data {} being encapsulated with the signature", (this.encapsulate ? "is" : "is not" ));
		return this.encapsulate;
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
	
	/**
	 * Signs the given set of data; the caller must make sure both input and 
	 * output stream are properly closed once the processing is complete.
	 * 
	 * @param input
	 *   the stream providing the data to be signed, as an input stream.
	 * @param output
	 *   a stream to write to.  
	 * @throws CryptoException
	 */
	public abstract void sign(InputStream input, OutputStream output) throws CryptoException;
	
	
	/**
	 * Verifies the signature of the given set of encapsulated data.
	 * 
	 * @param signed
	 *   the encapsulated data.
	 * @return
	 *   whether the signature is valid.
	 * @throws CryptoException
	 */
	public abstract boolean verify(byte [] signed) throws CryptoException;
	
	/**
	 * Verifies the signature of the given set of encapsulated data.
	 * 
	 * @param signed
	 *   the encapsulated data.
	 * @return
	 *   whether the signature is valid.
	 * @throws CryptoException
	 */
	public abstract boolean verify(InputStream signed) throws CryptoException;
	
	/**
	 * Verifies the signature of the given set of detached data.
	 * 
	 * @param data
	 *   the data whose signature is to be verified.
	 * @param signature
	 *   the detached signature block.
	 * @return
	 *   whethe rthe signature verification was successful.
	 * @throws CryptoException
	 */
	public abstract boolean verify(byte [] data, byte [] signature) throws CryptoException;
}
