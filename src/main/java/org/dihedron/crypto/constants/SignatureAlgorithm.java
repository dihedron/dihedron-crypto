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


import java.util.List;

import org.dihedron.core.regex.Regex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author Andrea Funto'
 */
public enum SignatureAlgorithm {
	
	/**
	 * The MD5 with RSA digital signature algorithm. 
	 */
	MD5_WITH_RSA(DigestAlgorithm.MD5, EncryptionAlgorithm.RSA),
	
	/**
	 * The SHA1 with RSA digital signature algorithm. 
	 */
	SHA1_WITH_RSA(DigestAlgorithm.SHA1, EncryptionAlgorithm.RSA),
	
	/**
	 * The SHA224 with RSA digital signature algorithm. 
	 */
	SHA224_WITH_RSA(DigestAlgorithm.SHA224, EncryptionAlgorithm.RSA),
	
	/**
	 * The SHA256 with RSA digital signature algorithm (default). 
	 */
	SHA256_WITH_RSA(DigestAlgorithm.SHA256, EncryptionAlgorithm.RSA),
	
	/**
	 * The SHA384 with RSA digital signature algorithm. 
	 */
	SHA384_WITH_RSA(DigestAlgorithm.SHA384, EncryptionAlgorithm.RSA),
	
	/**
	 * The SHA512 with RSA digital signature algorithm. 
	 */
	SHA512_WITH_RSA(DigestAlgorithm.SHA512, EncryptionAlgorithm.RSA);
		
	/** 
	 * The logger. 
	 */
	private Logger logger = LoggerFactory.getLogger(SignatureAlgorithm.class);
	
	/**
	 * The algorithm used to calculate the data checksum (hash). 
	 */
	private DigestAlgorithm digestAlgorithm;
	
	/**
	 * The algorithm used to encrypt the checksum (hash).
	 */
	private EncryptionAlgorithm encryptionAlgorithm;
	
	/**
	 * Attempts to translate the BouncyCastle code of a signature algorithm (in 
	 * the "SHA1withRSA" format into an enumeration value.
	 * 
	 * @param bcCode
	 *   the BouncyCastle code for the signature algorithm.
	 * @return
	 *   the corresponding enumeration value, or null if none found.
	 */
	public static SignatureAlgorithm fromBouncyCastleCode(String bcCode) {
		Regex regex = new Regex("(.*)with(.*)");
		if(regex.matches(bcCode)) {
			List<String[]> matches = regex.getAllMatches(bcCode);
			return fromBouncyCastleCodes(matches.get(0)[0], matches.get(0)[1]);
		}
		return null;
	}
	
	/**
	 * Factory method, returns the enumeration value corresponding to the two
	 * given algorithm descriptions.
	 * 
	 * @param digestAlgorithm
	 *   the description of the algorithm used to calculate the data checksum (hash),
	 *   e.g. "sha-1".
	 * @param encryptionAlgorithm
	 *   the description of the algorithm used to encrypt the hash in the signature,
	 *   e.g. "rsa".
	 */
	public static SignatureAlgorithm fromAlgorithmDescriptions(String digestAlgorithm, String encryptionAlgorithm) {
		DigestAlgorithm digest = DigestAlgorithm.fromDescription(digestAlgorithm);
		EncryptionAlgorithm encryption = EncryptionAlgorithm.fromDescription(encryptionAlgorithm);
		for(SignatureAlgorithm signature : SignatureAlgorithm.values()) {
			if(digest == signature.digestAlgorithm && encryption == signature.encryptionAlgorithm) {
				return signature;
			}
		}
		return null; 
	}

	/**
	 * Factory method, returns the enumeration value corresponding to the two
	 * given algorithm descriptions.
	 * 
	 * @param digestAlgorithm
	 *   the ASN.1 code of the algorithm used to calculate the data checksum (hash),
	 *   e.g. "sha-1".
	 * @param encryptionAlgorithm
	 *   the ASN.1 code of the algorithm used to encrypt the hash in the signature,
	 *   e.g. "rsa".
	 */
	public static SignatureAlgorithm fromAlgorithmAsn1Ids(String digestAlgorithm, String encryptionAlgorithm) {
		DigestAlgorithm digest = DigestAlgorithm.fromAsn1Id(digestAlgorithm);
		EncryptionAlgorithm encryption = EncryptionAlgorithm.fromAsn1Id(encryptionAlgorithm);
		for(SignatureAlgorithm signature : SignatureAlgorithm.values()) {
			if(digest == signature.digestAlgorithm && encryption == signature.encryptionAlgorithm) {
				return signature;
			}
		}
		return null; 
	}

	/**
	 * Factory method, returns the enumeration value corresponding to the two
	 * given algorithm descriptions.
	 * 
	 * @param digestAlgorithm
	 *   the BouncyCastle code of the algorithm used to calculate the data 
	 *   checksum (hash), e.g. "SHA256".
	 * @param encryptionAlgorithm
	 *   the BouncyCastle code of the algorithm used to encrypt the hash in the 
	 *   signature, e.g. "RSA".
	 */
	public static SignatureAlgorithm fromBouncyCastleCodes(String digestAlgorithm, String encryptionAlgorithm) {
		DigestAlgorithm digest = DigestAlgorithm.fromBouncyCastleCode(digestAlgorithm);
		EncryptionAlgorithm encryption = EncryptionAlgorithm.fromBouncyCastleCode(encryptionAlgorithm);
		for(SignatureAlgorithm signature : SignatureAlgorithm.values()) {
			if(digest == signature.digestAlgorithm && encryption == signature.encryptionAlgorithm) {
				return signature;
			}
		}
		return null; 
	}
	
	/**
	 * Returns the algorithm used to hash the data.
	 *  
	 * @return
	 *   the algorithm used to hash the data.
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return this.digestAlgorithm;
	}
	
	/**
	 * Returns the algorithm used to encrypt the hashed data. 
	 * 
	 * @return
	 *   the algorithm used to encrypt the hashed data.
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return this.encryptionAlgorithm;
	}
	
	/**
	 * Provides a string representation of the signature algorithm in the format
	 * used by BouncyCastle to identify it, e.g. "SHA256withRSA".
	 * 
	 * @return
	 *   the digest and encryption algorithm combination as BoucnyCastle expects 
	 *   it, e.g. "SHA1withRSA".
	 */
	public String toBouncyCastleCode() {
		StringBuffer algorithm = new StringBuffer();
		algorithm
			.append(digestAlgorithm.getBouncyCastleCode())		
			.append("with")
			.append(encryptionAlgorithm.getBouncyCastleCode());
		logger.debug("signature algorithm: '{}'", algorithm.toString());
		return algorithm.toString();		
	}
	
	/**
	 * Returns the algorithm string representation, such as "SHA256withRSA".
	 * 
	 * @return
	 *   the algorithm string representation, such as "SHA256withRSA".
	 */
	@Override
	public String toString() {
		return this.toBouncyCastleCode();
	}
	
	/**
	 * Constructor.
	 * 
	 * @param digestAlgorithm
	 *   the algorithm used to calculate the data checksum (hash).
	 * @param encryptionAlgorithm
	 *   the algorithm used to encrypt the hash in the signature.
	 */
	private SignatureAlgorithm(DigestAlgorithm digestAlgorithm, EncryptionAlgorithm encryptionAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
		this.encryptionAlgorithm = encryptionAlgorithm;
		logger.debug("digest algorithm: '{}', encryption algorithm: '{}'", digestAlgorithm, encryptionAlgorithm);		
	}
}
