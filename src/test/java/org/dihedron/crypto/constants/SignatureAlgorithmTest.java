/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.constants;

import static org.junit.Assert.assertTrue;

import org.dihedron.core.License;
import org.junit.Test;

/**
 * @author Andrea Funto'
 */
@License
public class SignatureAlgorithmTest {
	@Test
	public void test() {
		assertTrue(SignatureAlgorithm.fromBouncyCastleCode("MD5withRSA").equals(SignatureAlgorithm.MD5_WITH_RSA));
		assertTrue(SignatureAlgorithm.fromBouncyCastleCode("SHA1withRSA").equals(SignatureAlgorithm.SHA1_WITH_RSA));
		assertTrue(SignatureAlgorithm.fromBouncyCastleCode("SHA224withRSA").equals(SignatureAlgorithm.SHA224_WITH_RSA));
		assertTrue(SignatureAlgorithm.fromBouncyCastleCode("SHA256withRSA").equals(SignatureAlgorithm.SHA256_WITH_RSA));
		assertTrue(SignatureAlgorithm.fromBouncyCastleCode("SHA384withRSA").equals(SignatureAlgorithm.SHA384_WITH_RSA));
		assertTrue(SignatureAlgorithm.fromBouncyCastleCode("SHA512withRSA").equals(SignatureAlgorithm.SHA512_WITH_RSA));
	}
}
