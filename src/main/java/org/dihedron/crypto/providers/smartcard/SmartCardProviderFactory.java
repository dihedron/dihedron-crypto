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
package org.dihedron.crypto.providers.smartcard;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Provider;

import org.dihedron.core.os.Platform;
import org.dihedron.crypto.exceptions.ProviderException;
import org.dihedron.crypto.exceptions.SmartCardException;
import org.dihedron.crypto.exceptions.UnavailableDriverException;
import org.dihedron.crypto.providers.AutoCloseableProvider;
import org.dihedron.crypto.providers.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Smart card securoty provider factory class: helps install a security provider 
 * for PKCS#11 providers, once the reader in which the PKCS#11 token is available
 * has been detected and information about the smart card (in the form of a 
 * {@code SmartCard} database entry) has been retrieved.
 *  
 * @author Andrea Funto'
 */
public class SmartCardProviderFactory extends ProviderFactory<SmartCardTraits> {
	
	/**
	 * The logger
	 */
	private static final Logger logger = LoggerFactory.getLogger(SmartCardProviderFactory.class);
		
	/**
	 * Installs a new PKCS#11 security provider supporting the smart card model
	 * and make specified in the initialisation traits, which must provide a
	 * reference to the smart card reader in which the card is present and to 
	 * the database entry corresponding to the card's model.
	 * 
	 * @param traits
	 *   the characteristics traits of the smart card whose capabilities the 
	 *   provider will expose.
	 * @return
	 *   the new {@code Provider}, or {@code null} if none valid could be installed.
	 * @throws SmartCardException 
	 * @throws UnavailableDriverException 
	 */
	@Override
	public AutoCloseableProvider getProvider(SmartCardTraits traits) throws ProviderException {
		if(traits == null) {
			logger.warn("invalid smart card traits");
			return null;
		}
		
		String name = "SmartCard-" + traits.getSmartCard().getATR() + "-" + traits.getReader().getSlot();		
		logger.info("installing PKCS#11 provider '(SunPKCS11-){}'...", name);
		
		InputStream stream = null;
		
		try {
			// find the driver on disk
			File driver = traits.getSmartCard().getDriver(Platform.getCurrent());			
			if (driver != null) {
				logger.info("... file driver is available on disk at '{}'", driver.getAbsolutePath());
			
				// prepare configuration as stream
				Configuration configuration = new Configuration()
						.setName(name)
						.setLibrary(driver)
						.setOnCardHashing(traits.isHashOnCard())
						.setSlot(traits.getReader().getSlot());
				logger.info("... provider configuration: \n{}", configuration);
				stream = configuration.toStream();
				
				// load the class dynamically (to avoid errors when not running on Sun JDK)
				Class<?> clazz = Class.forName(SmartCardTraits.SUN_PKCS11_PROVIDER_CLASS);
				Constructor<?> constructor = clazz.getConstructor(String.class, InputStream.class);				
				Provider provider = (Provider) constructor.newInstance(name + "-configuration", stream);
				logger.info("... PKCS#11 provider '{}' loaded!", provider.getName());
				return new SmartCardProvider(provider);
			} else {
				logger.error("driver for smartcard '{}' and platform '{}' not available on disk", traits.getSmartCard().getATR(), Platform.getCurrent());
				throw new UnavailableDriverException("No valid smartcard PKCS#11 driver could be found on disk");
			}
		} catch (ClassNotFoundException e) {
			logger.error("Sun PKCS#11 supporting classes not available", e);
			throw new SmartCardException("Sun PKCS#11 supporting classes not available", e);
		} catch (NoSuchMethodException e) {
			logger.error("no constructor with (String, InputStream) parameter for Sun PKCS#11 available", e);
			throw new SmartCardException("no constructor with (String, InputStream) parameter for Sun PKCS#11 available", e);
		} catch (SecurityException e) {
			logger.error("security exception accessing Sun PKCS#11 constructor", e);
			throw new SmartCardException("security exception accessing Sun PKCS#11 constructor", e);
		} catch (InstantiationException e) {
			logger.error("error invoking Sun PKCS#11 constructor", e);
			throw new SmartCardException("error invoking Sun PKCS#11 constructor", e);
		} catch (IllegalAccessException e) {
			logger.error("error invoking inaccessible Sun PKCS#11 constructor", e);
			throw new SmartCardException("error invoking inaccessible Sun PKCS#11 constructor", e);
		} catch (IllegalArgumentException e) {
			logger.error("illegal argument to Sun PKCS#11 constructor", e);
			throw new SmartCardException("illegal argument to Sun PKCS#11 constructor", e);
		} catch (InvocationTargetException e) {
			logger.error("generic error invoking Sun PKCS#11 constructor", e);
			throw new SmartCardException("generic error invoking Sun PKCS#11 constructor", e);
		} finally {
			if(stream != null) {
				try {
					stream.close();
				} catch (IOException e) {
					logger.warn("error closing PKCS#11 provider configuration input stream", e);
				}
			}
		}
	}

//	/**
//	 * Uninstalls the given provider; smart cards instantiate a new provider for 
//	 * each different smart card, in order to support multiple initialisation 
//	 * parameters, and these custom providers need to be uninstalled once one is 
//	 * done using them. 
//	 * 
//	 * @param provider
//	 *   the provider to uninstall.
//	 */
//	@Override
//	public void release(Provider provider) {
//		if(provider != null) {
//			try {
//				if(provider.getClass().getName().equals(SmartCardTraits.SUN_PKCS11_PROVIDER_CLASS)) {
//					logger.info("Sun PKCS#11 provider detected, trying to log out...");
//					Method logout = null;
//					Class<?> clazz = provider.getClass();
//					while(clazz != null && clazz != Object.class && logout == null) {
//						logout = clazz.getDeclaredMethod("logout");
//						clazz = clazz.getSuperclass();
//					}
//					if(logout != null) {
//						logger.trace("... invoking logout() on provider");
//						logout.invoke(provider);
//						logger.info("... logged out of provider");
//					}
//				}
//			} catch(NoSuchMethodException e) {
//				logger.error("no method logout() on Sun PKCS#11 provider", e);
//			} catch (IllegalAccessException e) {
//				logger.error("illegal access to method logout() on Sun PKCS#11 provider", e);
//			} catch (IllegalArgumentException e) {
//				logger.error("illegal arguments to method logout() on Sun PKCS#11 provider", e);
//			} catch (InvocationTargetException e) {
//				logger.error("error trying to invoke logout() method on Sun PKCS#11 provider", e);
//			}
//		}		
//	}
	
	/**
	 * Helper class to format a PKCS#11 configuration file.
	 * 
	 * @author Andrea Funtò
	 */
	private static class Configuration {
		
		/**
		 * The buffer holding the configuration.
		 */
		private StringBuilder buffer = null;
		
		/**
		 * Constructor.
		 */
		Configuration() {
			buffer = new StringBuilder();
		}
		
		/**
		 * Sets the PKCS#11 provider name into the configuration.
		 * 
		 * @param name
		 *   the PKCS#11 provider name.
		 * @return
		 *   the object, for method chaining.
		 */
		Configuration setName(String name) {
			buffer.append("name=").append(name).append("\n");
			return this;
		}

		/**
		 * Adds the path to the supporting PKCS#11 driver to the configuration.
		 * 
		 * @param driver
		 *   the path to the supporting driver.
		 * @return 
		 *   the object, for method chaining.
		 * @throws IOException 
		 */
		Configuration setLibrary(File driver) {
			buffer.append("library=").append(driver.getAbsolutePath()).append("\n");
			return this;
		}
		
		/**
		 * Adds the slot indication to the configuration; if none specified, by
		 * default the provider will assume the slot to be 0.
		 * 
		 * @param slot
		 *   the 0-based slot index.
		 * @return 
		 *   the object, for method chaining.
		 */
		Configuration setSlot(int slot) {
			buffer.append("slot=").append(slot).append("\n");
			return this;
		}

		/**
		 * Disables the mechanisms that perform hashing on the smart card; on-card
		 * digesting has proven to be slow, and faulty on some smart cards, so it's
		 * better to disable it and perform hashing in Java code.
		 * 
		 * @return 
		 *   the object, for method chaining.
		 */
		Configuration setOnCardHashing(boolean enabled) {
			if(!enabled) {
				buffer.append("disabledMechanisms = {\n");
				buffer.append("    CKM_SHA1_RSA_PKCS\n");
				buffer.append("    CKM_SHA256_RSA_PKCS\n");
				buffer.append("    CKM_SHA384_RSA_PKCS\n");
				buffer.append("    CKM_SHA512_RSA_PKCS\n");
				buffer.append("}\n");			
			}
			return this;
		}

		@Override
		public String toString() {
			String configuration = buffer.toString();
			logger.trace("PKCS#11 configuration:\n{}", configuration);
			return configuration;
		}

		/**
		 * Returns the PKCS#11 configuration file as an input stream.
		 * 
		 * @return 
		 *   the PKCS#11 file as an input stream.
		 */
		public InputStream toStream() {
			return new ByteArrayInputStream(buffer.toString().getBytes());
		}
	}	
}
