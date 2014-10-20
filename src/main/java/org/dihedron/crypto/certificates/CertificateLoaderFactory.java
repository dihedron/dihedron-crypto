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
package org.dihedron.crypto.certificates;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.dihedron.crypto.certificates.impl.FileCertificateLoader;
import org.dihedron.crypto.certificates.impl.LDAPCertificateLoader;
import org.dihedron.crypto.exceptions.CertificateLoaderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CertificateLoader factory class; in order to create new instances, it uses the
 * set of properties provided as input; no state is kept between invocations, so 
 * the class is fully re-entrant.
 * NOTE: before invoking methods from this class, the BouncyCastle security
 * provider must have been laoded.
 * 
 * @author Andrea Funto'
 */
public class CertificateLoaderFactory {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(CertificateLoaderFactory.class);
	
	/**
	 * The name of the default properties file.
	 */
	private final static String DEFAULT_PROPERTIES_FILENAME = "certificate_loader.properties"; 
	
	/**
	 * Creates a new CertificateLoader loading its property set from the given file. 
	 * 
	 * @param properties
	 *   a set of properties used to initialise the new Certificateloader.
	 * @return
	 *   a CertificateLoadrer instance.
	 * @throws CertificateLoaderException
	 */
	static public CertificateLoader makeCertificateLoader(String filename) throws FileNotFoundException, IOException, CertificateLoaderException {
		String file = filename;
		if(file == null){
			file = DEFAULT_PROPERTIES_FILENAME;
		}		
		FileInputStream stream = null;
		try {
			Properties properties = new Properties();
			stream = new FileInputStream(file);
			properties.load(stream);
			return makeCertificateLoader(properties);
		} finally {
			if(stream != null) {
				try {
					stream.close();
				} catch(IOException e) {
					logger.error("error closing properties file stream");
				}
			}
		}				
	}
	
	/**
	 * Creates a new CertificateLoader using the given property set. 
	 * 
	 * @param properties
	 *   a set of properties used to initialise the new CertificateLoader.
	 * @return
	 *   a CertificateLoadrer instance.
	 * @throws CertificateLoaderException
	 */
	static public CertificateLoader makeCertificateLoader(Properties properties) throws CertificateLoaderException {		
		assert(properties != null);		
		String provider = (String) properties.get("provider");		
		if(provider.equalsIgnoreCase("file")) {
			logger.info("instantiating a FileCertificateLoader...");
			return new FileCertificateLoader();
		} else if(provider.equalsIgnoreCase("ldap")) {
			logger.info("instantiating a LDAPCertificateLoader...");
			if(properties.containsKey("ldap.url")) {
				String ldapUrl = (String) properties.get("ldap.url");
				return new LDAPCertificateLoader(ldapUrl);
			} else {			
				String ldapServer = (String) properties.get("ldap.server");
				String ldapPort = (String) properties.get("ldap.port");
				return new LDAPCertificateLoader(ldapServer, Integer.parseInt(ldapPort));
			}		
		}
		return null;
	}
	
	/**
	 * Private constructor to prevent construction.
	 */
	private CertificateLoaderFactory() {		
	}	
}
