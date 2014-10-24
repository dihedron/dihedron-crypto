/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.certificates;

import org.dihedron.core.License;
import org.dihedron.core.variables.SystemPropertyValueProvider;
import org.dihedron.core.variables.Variables;
import org.dihedron.crypto.exceptions.CryptoException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class RootCAsTest {
	
	private static final Logger logger = LoggerFactory.getLogger(RootCAsTest.class);

	@Test
	public void test() throws CryptoException {
		String truststore = Variables.replaceVariables("${javax.net.ssl.trustStore}", new SystemPropertyValueProvider());
		logger.info("javax.net.ssl.trustStore: '{}'", truststore);
		TrustAnchors.fromJavaRootCAs();
	}
}
