/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;

/**
 * The root of the exception hierarchy in the Crypto library.
 * 
 * @author Andrea Funto'
 */
@License
public class CryptoException extends Exception {

	/**
	 * Serial version UID.
	 */
	private static final long serialVersionUID = -4421245068091639737L;

	/**
	 * Default constructor.
	 */
	public CryptoException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param messages
	 *   the exception message.
	 */
	public CryptoException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the root cause of the exception.
	 */
	public CryptoException(Throwable cause) {
		super(cause);
	}

	/**
	 * Constructor.
	 * 
	 * @param messages
	 *   the exception messages.
	 * @param cause
	 *   the root cause of the exception.
	 */
	public CryptoException(String message, Throwable cause) {
		super(message, cause);
	}
}
