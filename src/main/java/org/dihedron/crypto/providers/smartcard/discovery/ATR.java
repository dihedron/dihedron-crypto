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
package org.dihedron.crypto.providers.smartcard.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Objects of class ATR represent the unique identifier of the smart card make 
 * and model; each smart card has its own byte sequence. The sequence can be
 * represented as a String.
 * 
 * @author Andrea Funto'
 */
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
