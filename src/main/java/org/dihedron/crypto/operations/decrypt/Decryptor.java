/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.decrypt;

import org.dihedron.core.License;
import org.dihedron.crypto.exceptions.CryptoException;

/**
 * Base abstract classes for all classes providing decryption services.
 * 
 * @author Andrea Funto'
 */
@License
public abstract class Decryptor {
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
	 * @param ciphertext
	 *   the encrypted data to be decrypted.
	 * @return
	 *   the plain text data.
	 */
	public abstract byte[] decrypt(byte [] ciphertext) throws CryptoException; 
}

