/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import org.dihedron.core.License;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
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
