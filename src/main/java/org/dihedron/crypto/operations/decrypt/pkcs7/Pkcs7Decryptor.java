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
package org.dihedron.crypto.operations.decrypt.pkcs7;

import org.dihedron.crypto.exceptions.CertificateLoaderException;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.operations.decrypt.Decryptor;

/**
 * @author Andrea Funto'
 */
public class Pkcs7Decryptor extends Decryptor {
	
	/**
	 * The logger
	 */
//	private static final Logger logger = LoggerFactory.getLogger(Pkcs7Decryptor.class);

	/**
	 * Initialises the object and prepares it for signing.
	 * 
	 * @param parameters
	 *   can be one of the following options:<ol>
	 *   <li>an X.509 certificate</li>
	 *   <li>a CertificateLoade and its associated Properties</li>
	 *   </ol>
	 * @return
	 *   whether the object has been properly initialised.
	 * @throws CertificateLoaderException 
	 * @see org.dihedron.crypto.operations.encrypt.Encryptor#initialise(java.lang.Object[])
	 */
	@Override
	public boolean initialise(Object... parameters) throws CertificateLoaderException {
		// TODO: implement
		/*
		if(parameters.length == 1) {
			if(parameters[0] != null && parameters[0] instanceof X509Certificate) {
				certificate = (X509Certificate)parameters[0];
				return true;
			} else {
				logger.error("invalid input parameters: expected X509Certificate, got {}", parameters[0] == null ? "null" : parameters[0].getClass().getName());
			}
		} else if(parameters.length == 2) {
			CertificateLoader loader = null;
			Properties properties = null;
			if(parameters[0] != null && parameters[0] instanceof CertificateLoader) {
				loader = (CertificateLoader)parameters[0];				
			} else {
				logger.error("invalid input parameters: expected CertificateLoader, got {}", parameters[0] == null ? "null" : parameters[0].getClass().getName());
			}
			if(parameters[1] != null && parameters[1] instanceof Properties) {
				properties = (Properties)parameters[1];
			} else {
				logger.error("invalid input parameters: expected Properties, got {}", parameters[0] == null ? "null" : parameters[0].getClass().getName());
			}
			certificate = (X509Certificate)loader.loadCertificate(properties);
		}
		return false;
		*/
		return true;
	}

	@Override
	public byte[] decrypt(byte[] ciphertext) throws CryptoException {
		// TODO: implement
		/*
		try {
			logger.info("decrypting data through certificate supporting algorithm: '{}'", certificate.getPublicKey().getAlgorithm());
			
//			X509CertificateEngine generator = new X509CertificateEngine(  
//                    "CA.p12", "PASSWORD",  
//                    "IdentityGardenCA");  
			
			CMSEnvelopedData ced = new CMSEnvelopedData(ciphertext);  
            Collection recip = ced.getRecipientInfos().getRecipients();  
  
            KeyTransRecipientInformation rinfo = (KeyTransRecipientInformation)recip.iterator().next();  
  
            byte[] contents = rinfo .getContent(generator.getCertificatePrivateKey( user2P12,  
                            "testUsr2Pwd"), "BC");  
  
            System.out.println(contents);  			
			  
			String[] issuerInfo = certificate.getIssuerDN().getName().split("(=|, )", -1);
			String[] subjectInfo = certificate.getSubjectDN().getName().split("(=|, )", -1);
	
			logger.debug("common name (CN) : '{}'", subjectInfo[3]);
			logger.debug("address          : '{}'", subjectInfo[1]);
	
			for (int i = 0; i < issuerInfo.length; i += 2){
				if (issuerInfo[i].equals("C")) {
					logger.debug("CountryName : '{}'", issuerInfo[i + 1]);
				}
			  	if (issuerInfo[i].equals("O")) {
			  		logger.debug("OrganizationName : '{}'", issuerInfo[i + 1]);
			  	}
			  	if (issuerInfo[i].equals("CN")) {
			  		logger.debug("CommonName : '{}'", issuerInfo[i + 1]);
			  	}
			}
			logger.info("certificate is valid from {} until {}, encrypting data...", certificate.getNotBefore(), certificate.getNotAfter());
			
			ASN1ObjectIdentifier algorithm = CMSAlgorithm.DES_EDE3_CBC;
			
			CMSTypedData messages = new CMSProcessableByteArray(plaintext);
			CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
			generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(certificate).setProvider("BC"));
			CMSEnvelopedData ed = generator.generate(messages, new JceCMSContentEncryptorBuilder(algorithm).setProvider("BC").build());			
			
			logger.info("... processing done!");
			return ed.getEncoded() ;
						
		} catch (CMSException e){
			 logger.error("CMS exception", e);
			 throw new CryptoException("Error generating enveloped signature", e);
		} catch (IOException e) {
			 logger.error("couldn't generate enveloped signature");
			 throw new CryptoException("Error generating enveloped signature", e);
		} catch (CertificateEncodingException e) {
			logger.error("invalid certificate encoding", e);
			throw new CryptoException("Invalid certificate encoding", e);
		} catch (OperatorCreationException e) {
			logger.error("error creating operator", e);
			throw new CryptoException("Error creating operator", e);
		}
		*/
		return null;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}
}
