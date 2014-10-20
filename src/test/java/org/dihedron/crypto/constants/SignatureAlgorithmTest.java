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
package org.dihedron.crypto.constants;

import static org.junit.Assert.assertTrue;

import org.dihedron.crypto.constants.SignatureAlgorithm;
import org.junit.Test;

/**
 * @author Andrea Funto'
 */
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
