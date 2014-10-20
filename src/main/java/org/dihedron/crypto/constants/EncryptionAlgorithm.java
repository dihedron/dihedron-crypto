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
 * An enumeration of supported encryption algorithms.
 * 
 * @author Andrea Funto'
 */
public enum EncryptionAlgorithm {
	
	/** 
	 * RSA asymmetric key encryption algorithm. 
	 */
	RSA("rsa", "RSA", CMSSignedDataGenerator.ENCRYPTION_RSA);
	
	/**
	 * Factory method: returns the Encryption object corresponding to the given 
	 * text description.
	 * 
	 * @param description
	 *   the algorithm description, e.g. "rsa".
	 * @return
	 *   the Encryption object, or null if none found corresponding to the given
	 *   algorithm description.
	 */
	public static EncryptionAlgorithm fromDescription(String description) {
		for (EncryptionAlgorithm encryption : EncryptionAlgorithm.values()) {
			if(encryption.getDescription().equalsIgnoreCase(description)) {
				return encryption;
			}
		}
		return null;
	}
	
	/**
	 * Factory method: returns the Encryption object corresponding to the given 
	 * ASN.1 algorithm code (e.g. "1.3.26.1.13").
	 * 
	 * @param bcCode
	 *   the ASN.1 algorithm BouncyCastle code, e.g. "1.3.13.2.26".
	 * @return
	 *   the Encryption object, or null if none found corresponding to the given
	 *   algorithm ASN.1 code.
	 */
	public static EncryptionAlgorithm fromAsn1Id(String asn1) {
		for (EncryptionAlgorithm encryption : EncryptionAlgorithm.values()) {
			if(encryption.getAsn1Id().equalsIgnoreCase(asn1)) {
				return encryption;
			}
		}
		return null;
	}
	
	/**
	 * Factory method: returns the Encryption object corresponding to the given 
	 * BouncyCastle algorithm code (e.g. "RSA").
	 * 
	 * @param bcCode
	 *   the algorithm BouncyCastle code, e.g. "RSA".
	 * @return
	 *   the Encryption object, or null if none found corresponding to the given
	 *   algorithm description.
	 */
	public static EncryptionAlgorithm fromBouncyCastleCode(String bcCode) {
		for (EncryptionAlgorithm encryption : EncryptionAlgorithm.values()) {
			if(encryption.getBouncyCastleCode().equalsIgnoreCase(bcCode)) {
				return encryption;
			}
		}
		return null;
	}		
		
	/**
	 * Returns the text description of the encryption algorithm.
	 *  
	 * @return
	 *   the text description of the encryption algorithm.
	 */
	public String getDescription() {
		return description;
	}
	
	/**
	 * returns the BouncyCastle code for the given encryption algorithm.
	 * 
	 * @return
	 *   the BouncyCastle code for the given encryption algorithm.
	 */
	public String getBouncyCastleCode() {
		return bcCode;
	}
	
	/**
	 * Returns the numeric (in text form) id of the encryption algorithm.
	 *  
	 * @return
	 *   the id of the encryption algorithm.
	 */
	public String getAsn1Id() {
		return asn1Id;
	}
	
	/**
	 * Formats the object as a string.
	 */
	@Override
	public String toString() {
		return description + " (" + asn1Id + ")";
	}

	/**
	 * Constructor.
	 * 
	 * @param description
	 *   the algorithm description.
	 * @param code
	 *   the BouncyCastle code for the given encryption algorithm, e.g. "RSA".
	 * @param asn1Id
	 *   the algorithm ASN.1 id.
	 */
	private EncryptionAlgorithm(String description, String code, String asn1Id) {
		this.description = description;
		this.bcCode = code;
		this.asn1Id = asn1Id;
	}
	
	/**
	 * The algorithm textual description.
	 */
	private String description;		
	
	/**
	 * The BouncyCastle code for the given encryption algorithm, e.g. "RSA".
	 */
	private String bcCode;
	
	/**
	 * The algorithm id, in ASN.1 format.
	 */
	private String asn1Id;
}

