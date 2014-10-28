/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */
package org.dihedron.crypto.operations;


/**
 * The set of available signature formats.
 * 
 * @author Andrea Funto'
 */
public enum EnvelopeFormat {
	/**
	 * The PKCS#7/CMS envelope format.
	 */
	PKCS7,
	
	/**
	 * The PDF digital signature format.
	 */
	PDF,
	
	/**
	 * The XML signature format.
	 */
	XML
}