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

import org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 * An enumeration of supported digest algorithms.
 * 
 * @author Andrea Funto'
 */
public enum DigestAlgorithm {
	
	/** 
	 * SHA-1 digest algorithm. 
	 */
	SHA1("sha-1", "SHA1", CMSSignedDataGenerator.DIGEST_SHA1),
	
	/** 
	 * SHA-224 digest algorithm. 
	 */
	SHA224("sha-224", "SHA224", CMSSignedDataGenerator.DIGEST_SHA224),
	
	/** 
	 * SHA-256 digest algorithm. 
	 */
	SHA256("sha-256", "SHA256", CMSSignedDataGenerator.DIGEST_SHA256),
	
	/** 
	 * SHA-384 digest algorithm. 
	 */
	SHA384("sha-384", "SHA384", CMSSignedDataGenerator.DIGEST_SHA384),
	
	/** 
	 * SHA-512 digest algorithm. 
	 */
	SHA512("sha-512", "SHA512", CMSSignedDataGenerator.DIGEST_SHA512),
	
	/** 
	 * MD5 digest algorithm. 
	 */
	MD5("md5", "MD5", CMSSignedDataGenerator.DIGEST_MD5);
	
	/**
	 * Factory method: returns the Digest object corresponding to the given text 
	 * description.
	 * 
	 * @param description
	 *   the algorithm description, e.g. "sha-1".
	 * @return
	 *   the Digest object, or null if none found corresponding to the given 
	 *   algorithm description.
	 */
	public static DigestAlgorithm fromDescription(String description) {
		for (DigestAlgorithm digest : DigestAlgorithm.values()) {
			if(digest.getDescription().equalsIgnoreCase(description)) {
				return digest;
			}
		}
		return null;
	}
	
	/**
	 * Factory method: returns the Digest object corresponding to the given 
	 * algorithm id (in ASN.1 format).
	 * 
	 * @param asn1
	 *   the algorithm ASN.1 code, e.g. "1.3.26.1.13".
	 * @return
	 *   the Digest object, or null if none found corresponding to the given 
	 *   algorithm id.
	 */
	public static DigestAlgorithm fromAsn1Id(String asn1) {
		for (DigestAlgorithm digest : DigestAlgorithm.values()) {
			if(digest.getAsn1Id().equalsIgnoreCase(asn1)) {
				return digest;
			}
		}
		return null;
	}
	
	/**
	 * Factory method: returns the Digest object corresponding to the given 
	 * BouncyCastle algorithm id (e.g. "SHA256").
	 * 
	 * @param algorithmCode
	 *   the BouncyCastle algorithm code, e.g. "MD5".
	 * @return
	 *   the Digest object, or null if none found corresponding to the given 
	 *   algorithm code.
	 */
	public static DigestAlgorithm fromBouncyCastleCode(String algorithmCode) {
		for (DigestAlgorithm digest : DigestAlgorithm.values()) {
			if(digest.getBouncyCastleCode().equalsIgnoreCase(algorithmCode)) {
				return digest;
			}
		}
		return null;
	}	
		
	/**
	 * Returns the text description of the digest algorithm.
	 *  
	 * @return
	 *   the text description of the digest algorithm.
	 */
	public String getDescription() {
		return description;
	}
	
	/**
	 * Returns the BouncyCastle code for the given algorithm.
	 * 
	 * @return
	 *   the BouncyCastle code for the given algorithm, e.g. "SHA256".
	 */
	public String getBouncyCastleCode() {
		return bcCode;
	}
	
	/**
	 * Returns the numeric (in text form) id of the digest algorithm.
	 *  
	 * @return
	 *   the id of the digest algorithm.
	 */
	public String getAsn1Id() {
		return asn1Id;
	}
	
	/**
	 * Formats the object as a string.
	 */
	@Override
	public String toString() {
		return description + " ('" + bcCode + "', '" + asn1Id + "')";
	}
	
	/**
	 * Constructor.
	 * 
	 * @param description
	 *   the digest algorithm text description, e.g. "sha-1".
	 * @param bcCode
	 *   the digest algorithm code, according to BouncyCastle, e.g. "SHA1". 
	 * @param algorithmId
	 *   the digest algorithm identifier, e.g. "1.3.26.1.13".
	 */
	private DigestAlgorithm(String description, String bcCode, String algorithmId) {
		this.description = description;
		this.bcCode = bcCode;
		this.asn1Id = algorithmId;
	}	
	
	/**
	 * The algorithm textual description.
	 */
	private String description;		
	
	/**
	 * The BouncyCastle code for the algorithm, e.g. "SHA256".
	 */
	private String bcCode;
	
	/**
	 * The algorithm id, in ASN.1 format.
	 */
	private String asn1Id;
}
