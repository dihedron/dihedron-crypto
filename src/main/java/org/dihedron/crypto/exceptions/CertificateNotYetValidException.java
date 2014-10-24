/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;

/**
 * @author Andrea Funto'
 */
@License
public class CertificateNotYetValidException extends CertificateException {
	
	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 6057504357427705700L;

	/**
	 * Constructor.
	 */
	public CertificateNotYetValidException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public CertificateNotYetValidException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the causing exception.
	 */
	public CertificateNotYetValidException(Throwable cause) {
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
	public CertificateNotYetValidException(String message, Throwable cause) {
		super(message, cause);
	}
}
