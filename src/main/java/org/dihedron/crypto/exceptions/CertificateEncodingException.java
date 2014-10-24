/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;


/**
 * @author Andrea Funto'
 */
@License
public class CertificateEncodingException extends CertificateException {
	
	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = -7623686324206323131L;

	/**
	 * Constructor.
	 */
	public CertificateEncodingException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public CertificateEncodingException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the causing exception.
	 */
	public CertificateEncodingException(Throwable cause) {
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
	public CertificateEncodingException(String message, Throwable cause) {
		super(message, cause);
	}
}
