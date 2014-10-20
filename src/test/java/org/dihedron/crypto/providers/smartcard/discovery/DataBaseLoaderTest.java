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
package org.dihedron.crypto.providers.smartcard.discovery;

import java.io.IOException;

import org.dihedron.core.streams.Streams;
import org.dihedron.crypto.exceptions.SmartCardException;
import org.dihedron.crypto.providers.smartcard.discovery.DataBase;
import org.dihedron.crypto.providers.smartcard.discovery.DataBaseLoader;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
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
