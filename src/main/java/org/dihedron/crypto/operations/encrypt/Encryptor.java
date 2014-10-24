/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.encrypt;

import org.dihedron.core.License;
import org.dihedron.crypto.CryptoService;
import org.dihedron.crypto.exceptions.CryptoException;

/**
 * Base abstract classes for all classes providing encryption services.
 * 
 * @author Andrea Funto'
 */
@License
public abstract class Encryptor extends CryptoService {
	
	/**
	 * Initialises the class with a set of (optional) parameters.
	 * 
	 * @param parameters
	 *   a set of optional parameters.
	 * @return
	 *   whether the object was successfully initialised.
	 */
	public abstract boolean initialise(Object... parameters) throws CryptoException;
	
	/**
	 * Encrypts the given byte array, returning the encrypted bytes.
	 * 
	 * @param plaintext
	 *   the plain text data to be encrypted.
	 * @return
	 *   the encrypted data.
	 */
	public abstract byte[] encrypt(byte [] plaintext) throws CryptoException; 
}
