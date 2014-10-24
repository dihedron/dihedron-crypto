/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;


/**
 * This class wraps an exception that could be thrown during the certificate
 * verification process.
 * 
 * @author Andrea Funto'
 * @author Svetlin Nakov
 */

@License(copyright="Copyright (c) 2012-2014, Andrea Funto, Svetlin Nakov") 
public class CertificateVerificationException extends CertificateException {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = -1184561130864502980L;

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public CertificateVerificationException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 * @param cause
	 *   the root cause of the exception.
	 */
	public CertificateVerificationException(String message, Throwable cause) {
		super(message, cause);
	}
}