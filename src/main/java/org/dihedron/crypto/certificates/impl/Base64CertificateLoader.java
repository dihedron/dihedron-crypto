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
package org.dihedron.crypto.certificates.impl;


import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.xml.bind.DatatypeConverter;

import org.dihedron.crypto.certificates.CertificateLoader;
import org.dihedron.crypto.exceptions.CertificateLoaderException;


/**
 * @author Andrea Funto'
 */
public class Base64CertificateLoader implements CertificateLoader {

	/**
	 * The name of the property holding the BASE64 representation of the certificate.
	 */
	public static final String BASE64 = "base64"; 
	
	private CertificateFactory certificateFactory;
			
	public Base64CertificateLoader() throws CertificateLoaderException {
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new CertificateLoaderException("error instantiating the certificate factory", e);
		}
	}
	
	public byte[] loadCertificateData(String base64) throws CertificateLoaderException {
		Properties properties = new Properties();
		properties.put(BASE64, base64);
		return loadCertificateData(properties); 		
	}
	
	public Certificate loadCertificate(String base64) throws CertificateLoaderException {	
		Properties properties = new Properties();
		properties.put(BASE64, base64);
		return loadCertificate(properties); 				
	}

	@Override
	public Certificate loadCertificate(Properties properties) throws CertificateLoaderException {
		X509Certificate x509certificate = null;
		
		byte [] data = loadCertificateData(properties);
		if (data!=null){
			try {
				x509certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(data));
			} catch (CertificateException e) {
				throw new CertificateLoaderException("error parsing certificate" , e);
			}
		}
		return x509certificate;
	}

	@Override
	public byte[] loadCertificateData(Properties properties) throws CertificateLoaderException {
		String base64 = properties.getProperty(BASE64);
		return DatatypeConverter.parseBase64Binary(base64);
	}	
}
