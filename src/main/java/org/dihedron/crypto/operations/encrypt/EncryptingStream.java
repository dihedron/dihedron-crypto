/**
 * Copyright (c) 2012-2015, Andrea Funto'. All rights reserved. See LICENSE for details.
 */
package org.dihedron.crypto.operations.encrypt;

import java.io.FilterOutputStream;
import java.io.OutputStream;
import java.security.cert.Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public abstract class EncryptingStream extends FilterOutputStream {
	/**
	 * The logger.
	 */
	public static final Logger logger = LoggerFactory.getLogger(EncryptingStream.class);

	/**
	 * The certificate used for encryption.
	 */
	protected Certificate certificate;
	
	/**
	 * Constructor.
	 * 
	 * @param output
	 *   the wrapped output stream.
	 * @param certificate
	 *   the certificate to be used for signing.
	 */
	public EncryptingStream(OutputStream output, Certificate certificate) {
		super(output);
		this.certificate = certificate;
	}
}
