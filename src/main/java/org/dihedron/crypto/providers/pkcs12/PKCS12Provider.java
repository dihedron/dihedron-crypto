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
package org.dihedron.crypto.providers.pkcs12;

import org.dihedron.crypto.exceptions.ProviderException;
import org.dihedron.crypto.providers.AutoCloseableProvider;
import org.dihedron.crypto.providers.ProviderFactory;

/**
 * @author Andrea Funto'
 */
public final class PKCS12Provider extends ProviderFactory<PKCS12Traits> {
	
	/**
	 * This is a do-nothing implementation since PKCS#12 key stores are self-
	 * contained and need no supporting security provider to be accessed: everything 
	 * is stored in a file (or in a byte array, for what matters) and can be
	 * loaded directly into a {@code KeyStore} through the key store's own API.
	 * 
	 * @return
	 *   always {@code null.}
	 * @throws ProviderException  
	 */
	@Override
	public AutoCloseableProvider getProvider(PKCS12Traits traits) {
		return new AutoCloseableProvider(null);
	}
}
