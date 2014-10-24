/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;


/**
 * @author Andrea Funto'
 */
@License
public class LockedPinException extends CryptoException {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 4969232597469388560L;

	/**
	 * Constructor.
	 */
	public LockedPinException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public LockedPinException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the exception root cause.
	 */
	public LockedPinException(Throwable cause) {
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
	public LockedPinException(String message, Throwable cause) {
		super(message, cause);
	}
}
