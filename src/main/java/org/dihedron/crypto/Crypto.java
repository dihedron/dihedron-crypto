/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto;

import org.dihedron.core.License;
import org.dihedron.core.library.Library;
import org.dihedron.core.library.Traits;


/**
 * @author Andrea Funto'
 */
@License
public class Crypto extends Library {
		
	/**
	 * Returns the value of the give trait.
	 * 
	 * @param trait
	 *   the trait to retrieve.
	 * @return
	 *   the value of the trait.
	 */
	public static String valueOf(Traits trait) {
		synchronized(Crypto.class) {
			if(singleton == null) {
				singleton = new Crypto();
			}}
		return singleton.get(trait);
	}
	
	/**
	 * The name of the library.
	 */
	private static final String LIBRARY_NAME = "crypto";
	
	/**
	 * The single instance.
	 */
	private static Crypto singleton = new Crypto();

	/**
	 * Constructor.
	 */
	private Crypto() {
		super(LIBRARY_NAME);
	}
}
