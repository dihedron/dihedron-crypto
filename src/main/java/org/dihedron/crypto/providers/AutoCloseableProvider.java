/**
 * 
 */
package org.dihedron.crypto.providers;

import java.security.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public class AutoCloseableProvider extends Provider implements AutoCloseable {
	
	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = -846600572294464148L;
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(AutoCloseableProvider.class);
	
	/**
	 * The wrapped provider; it will be automatically uninstalled when out of 
	 * the "try-with-resources" block.
	 */
	protected Provider provider;
	
	/**
	 * Constructor.
	 * 
	 * @param provider
	 *   the wrapped provider, which will be automatically closed when out of
	 *   the "try-with-resources" block, with an implementation specific mechanism. 
	 */
	public AutoCloseableProvider(Provider provider) {
		super(provider.getName(), provider.getVersion(), provider.getInfo());
		this.provider = provider; 
	}
	
	/**
	 * Returns the name of the underlying provider.
	 */
	public String getName() {
		String name = provider != null ? provider.getName() : null; 
		logger.trace("returning provider name: '{}'", name);
		return name;
	}
	
	/**
	 * Returns information about the underlying provider.
	 */
	public String getInfo() {
		return provider != null ? provider.getInfo() : null;
	}
	
	/**
	 * Returns the version of the underlying provider.
	 */
	public double getVersion() {
		return provider != null ? provider.getVersion() : null;
	}
	
	/**
	 * Clears the state of the underlying provider.
	 */
	public void clear() {
		if(provider != null) {
			provider.clear();
		}
	}
	
	/**
	 * @see AutoCloseable#close()
	 */
	@Override
	public void close() throws Exception {
		// by default do nothing
	}
	
	/**
	 * Returns a reference to the wrapped provider; this method is internal; do 
	 * not use it.
	 * 
	 * @return
	 *   a reference to the wrapped provider.
	 */	
	public Provider getWrappedProvider() {
		return provider;
	}
}
