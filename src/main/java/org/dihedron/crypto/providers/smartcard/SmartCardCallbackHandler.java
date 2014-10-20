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
package org.dihedron.crypto.providers.smartcard;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public class SmartCardCallbackHandler implements CallbackHandler {
	/**
	 * The logger
	 */
	private static final Logger logger = LoggerFactory.getLogger(SmartCardCallbackHandler.class);

	/**
	 * The smartcard PIN.
	 */
	private String password;

	/**
	 * Constructor.
	 * 
	 * @param password
	 *   the smartcard PIN.
	 */
	public SmartCardCallbackHandler(String password) {
		this.password = password;
	}

	/**
	 * Handles the callback request.
	 * 
	 * @param callbacks
	 *   a list of request messages.  
	 */
	public void handle(Callback[] callbacks) {
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof PasswordCallback) {				
				PasswordCallback callback = (PasswordCallback) callbacks[i];
				logger.trace("requesting smartcard password with message: '{}'", callback.getPrompt());
				callback.setPassword(password.toCharArray());
			} else {
				logger.warn("unsupported callback type: '{}'", callbacks[i].getClass().getSimpleName());
			}
		}
	}

}
