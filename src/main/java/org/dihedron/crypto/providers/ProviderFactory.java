/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers;

import org.dihedron.core.License;
import org.dihedron.crypto.exceptions.ProviderException;
import org.dihedron.crypto.exceptions.SmartCardException;

/**
 * Base class for all security provider factory objects.
 * 
 * @author Andrea Funtò
 */
@License
public abstract class ProviderFactory<T extends ProviderTraits> {
	
	/**
	 * Creates and installs a security provider of the specific type, using the
	 * given traits to perform its configuration.
	 * 
	 * @param traits
	 *   the provider-specific set of configuration parameters.
	 * @return
	 *   a {@code Provider} if successful, null otherwise.
	 * @throws SmartCardException
	 */
	public abstract AutoCloseableProvider getProvider(T traits) throws ProviderException;
}
