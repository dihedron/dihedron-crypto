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



import java.util.HashMap;
import java.util.Map.Entry;

/**
 * The database of supported smart cards, along with their supporting PKCS#11 drivers.
 * 
 * @author Andrea Funto'
 */
public class DataBase extends HashMap<ATR, SmartCard> {
	
	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 7028902675694888070L;

	/**
	 * Constructor; package visibility ensures that only the loader can
	 * construct an instance of this class.
	 */
	DataBase() {
		super();
	}
	
	/**
	 * Returns a pretty printed, complex representation of the object as a string.
	 */
	public String toString() {
		
		StringBuilder buffer = new StringBuilder();
		for(Entry<ATR, SmartCard> entry : this.entrySet()) {
			buffer.append(entry.getValue().toString()).append("\n");
		}		
		return buffer.toString();
	}
}
