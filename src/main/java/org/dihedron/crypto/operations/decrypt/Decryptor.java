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
package org.dihedron.crypto.operations.decrypt;

import org.dihedron.crypto.exceptions.CryptoException;

/**
 * Base abstract classes for all classes providing decryption services.
 * 
 * @author Andrea Funto'
 */
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

