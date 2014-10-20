/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved.
 * 
 * This file is part of the Crypto library ("Crypto").
 *
 * Crypto is free software: you can redistribute it and/or modify it under 
 * the terms of the GNU Lesser General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option) 
 * any later version.
 *
 * Crypto is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR 
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License 
 * along with Crypto. If not, see <http://www.gnu.org/licenses/>.
 */
package org.dihedron.crypto.exceptions;


/**
 * @author Andrea Funto'
 */
public class CertificateExpiredException extends CertificateException {
	
	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = -7623686324206323131L;

	/**
	 * Constructor.
	 */
	public CertificateExpiredException() {
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public CertificateExpiredException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param cause
	 *   the causing exception.
	 */
	public CertificateExpiredException(Throwable cause) {
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
	public CertificateExpiredException(String message, Throwable cause) {
		super(message, cause);
	}
}
