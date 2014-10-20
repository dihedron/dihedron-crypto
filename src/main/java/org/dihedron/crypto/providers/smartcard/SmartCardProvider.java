/**
 * 
 */
package org.dihedron.crypto.providers.smartcard;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Provider;

import org.dihedron.crypto.providers.AutoCloseableProvider;
import org.dihedron.crypto.providers.smartcard.SmartCardTraits;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public class SmartCardProvider extends AutoCloseableProvider {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = 4194148068514268505L;

	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(SmartCardProvider.class);
	
	/**
	 * Constructor.
	 * 
	 * @param provider
	 *   the wrapped provider, which will be automatically closed when out of
	 *   the "try-with-resources" block, with an implementation specific mechanism. 
	 */
	public SmartCardProvider(Provider provider) {
		super(provider);
	}
		
	/**
	 * Implements the {@code AutoCloseable#close()} methos in a smart-card specific way.
	 * 
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() throws Exception {
		if(provider != null) {
			logger.info("closing provider '{}'...", this.getName());
			try {
				if(provider.getClass().getName().equals(SmartCardTraits.SUN_PKCS11_PROVIDER_CLASS)) {
					logger.info("Sun PKCS#11 provider detected, trying to log out...");
					Method logout = null;
					Class<?> clazz = provider.getClass();
					while(clazz != null && clazz != Object.class && logout == null) {
						logout = clazz.getDeclaredMethod("logout");
						clazz = clazz.getSuperclass();
					}
					if(logout != null) {
						logger.trace("... invoking logout() on provider");
						logout.invoke(provider);
						logger.info("... logged out of provider");
					}
				}
			} catch(NoSuchMethodException e) {
				logger.error("no method logout() on Sun PKCS#11 provider", e);
			} catch (IllegalAccessException e) {
				logger.error("illegal access to method logout() on Sun PKCS#11 provider", e);
			} catch (IllegalArgumentException e) {
				logger.error("illegal arguments to method logout() on Sun PKCS#11 provider", e);
			} catch (InvocationTargetException e) {
				logger.error("error trying to invoke logout() method on Sun PKCS#11 provider", e);
			}
		}		
	}
}
