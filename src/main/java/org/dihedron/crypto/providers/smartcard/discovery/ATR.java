/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard.discovery;

import org.dihedron.core.License;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Objects of class ATR represent the unique identifier of the smart card make 
 * and model; each smart card has its own byte sequence. The sequence can be
 * represented as a String.
 * 
 * @author Andrea Funto'
 */
@License
public class ATR {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(ATR.class);

	/**
	 * The unique byte sequence representing the Answer-To-Reset, as a string.
	 */
	private String atr;
	
	/**
	 * Constructor.
	 * 
	 * @param atr
	 *   a string version of the unique byte sequence representing the 
	 *   Answer-To-Reset byte sequence.
	 */
	public ATR(String atr) {
		this.atr = atr.toUpperCase();
	}
	
	/**
	 * Constructor.
	 * 
	 * @param bytes
	 *   the unique byte sequence representing the Answer-To-Reset.
	 */
	public ATR(byte [] bytes) {
		this(bytes, "");
	}
	
	/**
	 * Constructor.
	 * 
	 * @param bytes
	 *   the unique byte sequence representing the Answer-To-Reset.
	 * @param separator
	 *   a character sequence used as a separator between individual bytes in the
	 *   byte sequence.
	 */
	public ATR(byte [] bytes, String separator) {
		StringBuilder buffer = new StringBuilder();
		for (int n = 0; n < bytes.length; n++) {
			int x = (int) (0x000000FF & bytes[n]);
			String w = Integer.toHexString(x).toUpperCase();
			if (w.length() == 1) {
				w = "0" + w;
			}
			buffer.append(w).append(((n + 1 == bytes.length) ? "" : separator));
		} 
		this.atr = buffer.toString().toUpperCase();
	}
	
	/**
	 * Checks if two ATRs are equal; comparison is performed case-insensitively
	 * on the String representation with a blank separator.
	 */
	@Override
	public boolean equals(Object other) {
		logger.trace("checking equality between '{}' (this) and '{}' (other)...", this.atr, ((ATR)other).atr);
		boolean result = other != null && other instanceof ATR && ((ATR)other).atr.equals(this.atr);
		logger.trace("... objects {} equal", result ? "are" : "are not");
		return result;
	}
	
	/**
	 * Returns a hash calculated on the upper-cased string representation of the
	 * byte sequence. 
	 */
	@Override
	public int hashCode() {
		return atr.hashCode();
	}
	
	/**
	 * Returns a String representation of the ATR.
	 */
	@Override
	public String toString() {
		return atr;
	}
}
