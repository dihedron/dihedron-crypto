/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.sign;

import java.io.FilterOutputStream;
import java.io.OutputStream;

import org.dihedron.core.License;
import org.dihedron.crypto.exceptions.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public abstract class SigningStream extends FilterOutputStream {
	
	/**
	 * The logger.
	 */
	private static Logger logger = LoggerFactory.getLogger(SigningStream.class);

	/**
	 * The signing stream configurator.
	 */
	protected SigningStreamConfigurator configurator;
	
	/**
	 * Constructor.
	 * 
	 * @param output
	 *   the output stream to which data will be eventually written.
	 *   the digest and encryption algorithm combination used to sign.
	 * @param configurator
	 *   the output signing stream configurator.
	 * @throws CryptoException
	 *   if any of the input parameters is null.
	 */
	public SigningStream(OutputStream output, SigningStreamConfigurator configurator) throws CryptoException {
		super(output);
		if(output == null || configurator == null) {
			logger.error("input parameters must not be null");
			throw new CryptoException("invalid initialisation data");
		}
		this.configurator = configurator;
	}
}
