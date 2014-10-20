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
package org.dihedron.crypto.operations.sign.pkcs7;


import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.dihedron.crypto.certificates.Certificates;
import org.dihedron.crypto.constants.DigestAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public class PKCS7AttributeTableGenerator extends DefaultSignedAttributeTableGenerator {
	
	/** The logger. */
	private static Logger logger = LoggerFactory.getLogger(PKCS7AttributeTableGenerator.class);

	private DigestAlgorithm digestAlgorithm;
	private X509Certificate x509certificate;

	public PKCS7AttributeTableGenerator(DigestAlgorithm digestAlgorithm, X509Certificate certificate) {
		this.digestAlgorithm = digestAlgorithm;
		this.x509certificate = certificate;
		
		logger.info("creating signed attributes table generator with algorithm \"" + digestAlgorithm  + "\"");
	}
	
	@SuppressWarnings({"unchecked", "rawtypes"})
	public AttributeTable getAttributes(Map parameters) throws CMSAttributeTableGenerationException {
		
		AttributeTable result = super.getAttributes(parameters);
		Hashtable table = result.toHashtable();

		try {
	        
	        if(!table.containsKey(SignedData.id_aa_signingCertificate) && !table.containsKey(SignedData.id_aa_signingCertificateV2)) {
	        	logger.debug("signed attributes table does not contain SigningCertificate[V2]: adding...");
	       
	        	IssuerSerial issuerSerial = Certificates.makeIssuerSerial(x509certificate);
	        	
	        	Attribute attribute = null;
	        	// create the ESSCertId[V2] objects to embed as SigningCertificate[V2]
	        	switch(digestAlgorithm) {
	        	case SHA1:
	        		logger.info("adding signing certificate v1 to signed attributes");
	        		ESSCertID essCertId = Certificates.makeESSCertIdV1(x509certificate, issuerSerial, digestAlgorithm);
	        		attribute = new Attribute(SignedData.id_aa_signingCertificate, new DERSet(new SigningCertificate(essCertId)));
	        		break;
	        	case SHA256:
	        	case SHA384:
	        	case SHA512:
	        		logger.info("adding signing certificate v2 to signed attributes");
	        		ESSCertIDv2 essCertIdv2s[] = Certificates.makeESSCertIdV2(x509certificate, issuerSerial, digestAlgorithm); 
	            	attribute = new Attribute(SignedData.id_aa_signingCertificateV2, new DERSet(new SigningCertificateV2(essCertIdv2s)));
	            	break;
	            default:
	            	logger.info("unsupported digest algorithm: {}", digestAlgorithm);	
	        	}	        	
	        	table.put(attribute.getAttrType(), attribute);
	        }
	        
	        return new AttributeTable(table);
	        
		} catch (CertificateEncodingException e) {
			logger.error("error reading certificate encoding", e);
		} catch (NoSuchAlgorithmException e) {
			logger.error("unsupported digest algorithm: " + digestAlgorithm, e);
		} catch (IOException e) {
			logger.error("I/O error reading certificate structure", e);
		}
		return null;
	}
}
