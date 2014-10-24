/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.verify;

import org.dihedron.core.License;

/**
 * @author Andrea Funto'
 */
@License
public interface VerifyInputStream {

	boolean isVerified();
	
//	/**
//	 * Verifies the signature of the given set of encapsulated data.
//	 * 
//	 * @param signed
//	 *   the encapsulated data.
//	 * @return
//	 *   whether the signature is valid.
//	 * @throws CryptoException
//	 */
//	public abstract boolean verify(InputStream signed) throws CryptoException;
}
