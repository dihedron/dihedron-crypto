/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.mscapi;

import org.dihedron.core.License;
import org.dihedron.crypto.providers.ProviderTraits;

/**
 * The set of characteristics of a Microsoft CryptoAPI-based security provider.
 * 
 * @author Andrea Funtò
 */
@License
public class MicrosoftTraits implements ProviderTraits {
	/**
	 * The name of the class supporting the Microsoft CryptoAPI provider.
	 */
	final static String SUN_MSCAPI_PROVIDER_CLASS = "sun.security.mscapi.SunMSCAPI";
}
