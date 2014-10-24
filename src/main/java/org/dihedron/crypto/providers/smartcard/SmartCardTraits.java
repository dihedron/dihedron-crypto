/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard;

import org.dihedron.core.License;
import org.dihedron.crypto.providers.ProviderTraits;
import org.dihedron.crypto.providers.smartcard.discovery.Reader;
import org.dihedron.crypto.providers.smartcard.discovery.SmartCard;

/**
 * The set of characteristics of a smart card based PKCS#11 security provider.
 * 
 * @author Andrea Funto'
 */
@License
public class SmartCardTraits implements ProviderTraits {

	/**
	 * The name of the underlying Sun PKCS#11 provider class; the class gets
	 * loaded at run-time to avoid errors when running on an unsupported JVM
	 * (such as IBM's).
	 */		
	// TODO: may want to transform this into an array in order to be able to
	// handle IBM's PKCS#11 provider too (reflectively).
	final static String SUN_PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";
	
	/**
	 * Whether by default the hashing should be executed on card; by default (due
	 * to performance and reliability) the digest is produced in Java code.
	 */
	private static final boolean DEFAULT_HASH_ON_CARD = false;
	
	/**
	 * The reader holding the smart card.
	 */
	private Reader reader;
	
	/**
	 * The database entry for the smart card in the reader.
	 */
	private SmartCard smartcard;
	
	/**
	 * Whether the new provider will hash data in code or on the smart card.
	 */
	private boolean hashOnCard;
	
	/**
	 * Constructor.
	 * 
	 * @param reader
	 *   the reader holding the smart card.
	 * @param smartcard
	 *   the database entry for the smart card in the reader.
	 */
	public SmartCardTraits(Reader reader, SmartCard smartcard) {
		this(reader, smartcard, DEFAULT_HASH_ON_CARD);
	}

	/**
	 * Constructor.
	 * 
	 * @param reader
	 *   the reader holding the smart card.
	 * @param smartcard
	 *   the database entry for the smart card in the reader.
	 * @param hashOnCard
	 *   whether the new provider will hash data in code or on the smart card.
	 */
	public SmartCardTraits(Reader reader, SmartCard smartcard, boolean hashOnCard) {
		this.reader = reader;
		this.smartcard = smartcard;
		this.hashOnCard = hashOnCard;
	}	
	
	/**
	 * Returns the reader holding the smart card.
	 * 
	 * @return
	 *   the reader holding the smart card.
	 */
	public Reader getReader() {
		return reader;
	}

	/**
	 * Returns the database entry for the smart card in the reader.
	 * 
	 * @return
	 *   the database entry for the smart card in the reader.
	 */
	public SmartCard getSmartCard() {
		return smartcard;
	}
	
	/**
	 * Returns whether the new provider will hash data in code or on the smart card.
	 * 
	 * @return
	 *   whether the new provider will hash data in code or on the smart card.
	 */
	public boolean isHashOnCard() {
		return this.hashOnCard;
	}
}
