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
public class ProviderException extends CryptoException {

	/**
	 * Serial version UID.
	 */
	private static final long serialVersionUID = 8264009910893108288L;

	/**
	 * Default constructor.
	 */
	public ProviderException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param messages
	 *   the exception message.
	 */
	public ProviderException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the root cause of the exception.
	 */
	public ProviderException(Throwable cause) {
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
	public ProviderException(String message, Throwable cause) {
		super(message, cause);
	}
}
