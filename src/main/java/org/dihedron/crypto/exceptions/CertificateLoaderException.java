/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.exceptions;

import org.dihedron.core.License;

/**
 * @author Andrea Funto'
 */
@License
public class CertificateLoaderException extends CryptoException {

	/** 
	 * Serialization version ID. 
	 */
	private static final long serialVersionUID = -5587019135150726252L;

	public CertificateLoaderException() {
	}

	public CertificateLoaderException(String message) {
		super(message);
	}

	public CertificateLoaderException(Throwable cause) {
		super(cause);
	}

	public CertificateLoaderException(String message, Throwable cause) {
		super(message, cause);
	}
}
