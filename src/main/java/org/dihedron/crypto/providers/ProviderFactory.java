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
package org.dihedron.crypto.providers;

import org.dihedron.crypto.exceptions.ProviderException;
import org.dihedron.crypto.exceptions.SmartCardException;

/**
 * Base class for all security provider factory objects.
 * 
 * @author Andrea Funtò
 */
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
