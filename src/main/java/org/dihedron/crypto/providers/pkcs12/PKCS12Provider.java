/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.pkcs12;

import org.dihedron.core.License;
import org.dihedron.crypto.exceptions.ProviderException;
import org.dihedron.crypto.providers.AutoCloseableProvider;
import org.dihedron.crypto.providers.ProviderFactory;

/**
 * @author Andrea Funto'
 */
@License
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
