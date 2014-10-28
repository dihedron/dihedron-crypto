/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */
package org.dihedron.crypto.operations;


/**
 * The set of available signature formats.
 * 
 * @author Andrea Funto'
 */
public enum SignatureFormat {
	/**
	 * A verifier that provides PKCS#7/CMS signatures.
	 */
	PKCS7,
	
	/**
	 * A verifier that provides PDF digital signatures.
	 */
	PDF,
	
	/**
	 * A verifier that provides XML signatures.
	 */
	XML
}