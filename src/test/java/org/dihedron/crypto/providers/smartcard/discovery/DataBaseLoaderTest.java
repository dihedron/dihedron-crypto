/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard.discovery;

import java.io.IOException;

import org.dihedron.core.License;
import org.dihedron.core.streams.Streams;
import org.dihedron.crypto.exceptions.SmartCardException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class DataBaseLoaderTest {

	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(DataBaseLoaderTest.class);
	
	/**
	 * Test method for {@link org.dihedron.crypto.providers.smartcard.discovery.DataBaseLoader#loadFromClassPath(java.lang.String)}.
	 * @throws SmartCardException 
	 */
	@Test
	public void testLoadFromClassPath() throws SmartCardException {
		DataBase database = DataBaseLoader.load("classpath:org/dihedron/crypto/providers/smartcard/discovery/smartcards.xml");
		logger.trace("database:\n {}", database);
	}
	
	@Test
	public void testLoadFromURL() throws SmartCardException, IOException {
		DataBase database = DataBaseLoader.load(Streams.fromURL("classpath:org/dihedron/crypto/providers/smartcard/discovery/smartcards.xml"));
		logger.trace("database:\n {}", database);
	}
	

	/**
	 * Test method for {@link org.dihedron.crypto.providers.smartcard.discovery.DataBaseLoader#loadFromClassPath(java.lang.String)}.
	 * @throws SmartCardException 
	 * @throws IOException 
	 */
	@Test
	public void testLoadDefault() throws SmartCardException, IOException {
		DataBase database = DataBaseLoader.load();
		logger.trace("database:\n {}", database);
	}	
}
