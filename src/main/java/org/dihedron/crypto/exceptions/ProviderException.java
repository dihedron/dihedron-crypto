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
 * The root of the exception hierarchy in the Crypto library.
 * 
 * @author Andrea Funto'
 */
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
