/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;

/**
 * The base class for all exceptions related to certificate validity or
 * availability.
 * 
 * @author Andrea Funto'
 */
@License
public class CertificateException extends CryptoException {
	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 3606361021865746930L;

	/**
	 * Constructor.
	 */
	public CertificateException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public CertificateException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the causing exception.
	 */
	public CertificateException(Throwable cause) {
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
	public CertificateException(String message, Throwable cause) {
		super(message, cause);
	}
}
