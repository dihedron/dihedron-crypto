/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;


/**
 * The root of the smart card provider-specific exceptions.
 * 
 * @author Andrea Funto'
 */
@License
public class SmartCardException extends ProviderException {

	/**
	 * Serial version UID.
	 */
	private static final long serialVersionUID = -7288748941476941001L;

	/**
	 * Default constructor.
	 */
	public SmartCardException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param messages
	 *   the exception message.
	 */
	public SmartCardException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the root cause of the exception.
	 */
	public SmartCardException(Throwable cause) {
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
	public SmartCardException(String message, Throwable cause) {
		super(message, cause);
	}
}
