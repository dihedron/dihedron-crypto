/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 

package org.dihedron.crypto.operations.verify;


import java.io.InputStream;

import org.dihedron.core.License;
import org.dihedron.crypto.CryptoService;
import org.dihedron.crypto.exceptions.CryptoException;

/**
 * This class acts as the base class, providing common functionalities to all 
 * fashions of verifiers. It is an abstract class and not an interface because
 * we want it to extend CryptoService, which in turn ensures that BouncyCastle 
 * is loaded automatically among the security providers without our having to
 * do anything.
 */
@License
public abstract class Verifier extends CryptoService {
		
	/**
	 * Verifies that the signed data in the input array has not been tampered with.
	 * 
	 * @param signed
	 *   an array of bytes containing a signed file.
	 * @return
	 *   whether the verification was successful.
	 */
	public abstract boolean verify(byte [] signed) throws CryptoException;
	
	/**
	 * Verifies a detached signature, given the data upon which it was originally 
	 * calculated and the detached signature bytes.
	 * 
	 * @param data
	 *   the data on which the signature was originally calculated.
	 * @param signature
	 *   the (detached) signature as a byte array.
	 * @return
	 *   whether the verification was successful.
	 */
	public abstract boolean verify(byte [] data, byte [] signature) throws CryptoException;
	
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
}
