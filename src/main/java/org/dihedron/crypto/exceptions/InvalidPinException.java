/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;


/**
 * @author Andrea Funto'
 */
@License
public class InvalidPinException extends CryptoException {
	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 3808034523694902814L;

	/**
	 * Constructor.
	 */
	public InvalidPinException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public InvalidPinException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the exception root cause.
	 */
	public InvalidPinException(Throwable cause) {
		super(cause);
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 * @param cause
	 *   the exception cause.
	 */
	public InvalidPinException(String message, Throwable cause) {
		super(message, cause);
	}
}
