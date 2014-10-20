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
package org.dihedron.crypto.providers.mscapi;

import java.security.Provider;

import org.dihedron.crypto.exceptions.ProviderException;
import org.dihedron.crypto.exceptions.SmartCardException;
import org.dihedron.crypto.providers.AutoCloseableProvider;
import org.dihedron.crypto.providers.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public final class MicrosoftProvider extends ProviderFactory<MicrosoftTraits> {
	
	/**
	 * The logger
	 */
	private static final Logger logger = LoggerFactory.getLogger(MicrosoftProvider.class);
		
	/**
	 * Installs a new Microsoft CryptoAPI security provider; the provider may
	 * provide access to smart card devices if these have certificate propagation 
	 * enabled.
	 * 
	 * @return
	 *   the new {@code Provider}, or {@code null} if none valid could be installed.
	 * @throws SmartCardException  
	 */
	@Override
	public AutoCloseableProvider getProvider(MicrosoftTraits traits) throws ProviderException {
		try {
			Class<?> clazz = Class.forName(MicrosoftTraits.SUN_MSCAPI_PROVIDER_CLASS);
			return new AutoCloseableProvider((Provider)clazz.newInstance());
		} catch (InstantiationException e) {
			logger.error("error invoking Sun PKCS#11 constructor", e);
			throw new SmartCardException("error invoking Sun PKCS#11 constructor", e);
		} catch (IllegalAccessException e) {
			logger.error("error invoking inaccessible Sun PKCS#11 constructor", e);
			throw new SmartCardException("error invoking inaccessible Sun PKCS#11 constructor", e);
		} catch (ClassNotFoundException e) {
			logger.error("Microsoft CryptoAPI supporting class ot found in classpath", e);
			throw new SmartCardException("Microsoft CryptoAPI supporting class ot found in classpath", e);
		}
	}
}
