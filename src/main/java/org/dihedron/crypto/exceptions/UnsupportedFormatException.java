/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;

/**
 * @author Andrea Funto'
 */
@License
public class UnsupportedFormatException extends CryptoException {
	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = -2733565527210803329L;
	
	/**
	 * Constructor.
	 */
	public UnsupportedFormatException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public UnsupportedFormatException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the causing exception.
	 */
	public UnsupportedFormatException(Throwable cause) {
		super(cause);
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 * @param cause
	 *   the causing exception.
	 */
	public UnsupportedFormatException(String message, Throwable cause) {
		super(message, cause);
	}
}
