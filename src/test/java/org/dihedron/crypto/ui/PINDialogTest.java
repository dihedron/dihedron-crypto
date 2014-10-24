/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.ui;

import org.dihedron.core.License;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class PINDialogTest {

	private static final Logger logger = LoggerFactory.getLogger(PINDialogTest.class);
	
	@Test
	@Ignore
	public void testGetPIN() {
		try {
			logger.trace("PIN: '{}'", new PINDialog("Insert PIN", "Set PIN for smartcard Athena").getPIN());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
