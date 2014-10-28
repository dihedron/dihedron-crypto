/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.verify;

import java.io.FilterInputStream;
import java.io.InputStream;

import org.dihedron.core.License;

/**
 * Creates a wrapper around an input stream that verifies whether the input data 
 * has a valid signature as it reads it in.
 * 
 * @author Andrea Funto'
 */
@License
public abstract class VerifyInputStream extends FilterInputStream {

	/**
	 * Constructor.
	 * 
	 * @param input
	 *   the wrapped input stream.
	 */
	public VerifyInputStream(InputStream input) {
		super(input);
	}
	
	/**
	 * Returns whether the signed data verification was successful.
	 *  
	 * @return
	 *   whether the signed data verification was successful.
	 */
	public abstract boolean isVerified();
}
