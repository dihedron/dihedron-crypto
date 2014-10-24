/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard.discovery;



import java.util.HashMap;
import java.util.Map.Entry;

import org.dihedron.core.License;

/**
 * The database of supported smart cards, along with their supporting PKCS#11 drivers.
 * 
 * @author Andrea Funto'
 */
@License
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
