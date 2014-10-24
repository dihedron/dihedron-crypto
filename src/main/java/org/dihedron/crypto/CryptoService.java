/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.dihedron.core.License;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public abstract class CryptoService {
	
	/**
	 * The logger
	 */
	private static final Logger logger = LoggerFactory.getLogger(CryptoService.class);

	/**
	 * The library startup method; this method installs the required security 
	 * providers and should be invoked prior to any operations pertaining to 
	 * cryptography and digital signature.
	 */
	static {
		logger.info("installing BouncyCastle security provider...");		
		if(Security.addProvider(new BouncyCastleProvider()) == -1) {
			logger.info("... provider was already available!");
		} else {
			logger.info("... done installing provider!");
		}
	}
	
	/**
	 * Protected constructor, to be used only by inheriting classes.
	 */
	protected CryptoService() {
	}
}
