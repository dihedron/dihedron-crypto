/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.constants;

import org.dihedron.core.License;


/** 
 * Signature types.
 * 
 *  @author Andrea Funto'
 */
@License
public enum SignatureFormat {
	/** 
	 * PKCS#7 signature type (.p7m extension), with embedded data. 
	 */
	PKCS7_ATTACHED("cms-explicit"),
	
	/** 
	 * Detached PKCS#7 signature type (.p7m extension), no data. 
	 */
	PKCS7_DETACHED("cms-implicit"),
	
	/** 
	 * PDF signature type (.pdf extension), attached to the PDF. 
	 */
	PDF_ATTACHED("pdf-explicit"),
	
	/** 
	 * PDF signature type (.pdf extension), with no PDF data. 
	 */
	PDF_DETACHED("pdf-implicit");
	
	/**
	 * Tries to find a {@code SignatureFormat} value corresponding to the given
	 * textual description; the comparison is performed case insensitively.
	 * 
	 * @param description
	 *   a text description of the signature format, e.g. "cms-implicit".
	 * @return
	 *   an enumeration value, or null if none corresponds to the given description.
	 */
	public static SignatureFormat fromString(String description) {
		for (SignatureFormat format : SignatureFormat.values()) {
			if(format.getDescription().equalsIgnoreCase(description)) {
				return format;
			}
		}
		return null;
	}
		
	/**
	 * Returns the format as a descriptive string.
	 * 
	 * @return
	 *   the format as a descriptive string.
	 */
	public String getDescription() {
		return description;
	}
	
	/**
	 * Returns the format as a descriptive string.
	 * 
	 * @return
	 *   the format as a descriptive string.
	 */
	@Override
	public String toString() {
		return description;
	}
	
	/**
	 * Constructor.
	 * 
	 * @param description
	 */
	private SignatureFormat(String description) {
		this.description = description;
	}
	
	/**
	 * The format as a descriptive string.
	 */
	private String description;
}
