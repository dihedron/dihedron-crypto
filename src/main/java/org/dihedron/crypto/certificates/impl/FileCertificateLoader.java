/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.certificates.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Properties;

import org.dihedron.core.License;
import org.dihedron.crypto.certificates.CertificateLoader;
import org.dihedron.crypto.exceptions.CertificateLoaderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
@License
public class FileCertificateLoader implements CertificateLoader {
	
	/**
	 * the name of the property holding the file name.
	 */
	public static final String FILENAME = "filename";
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(FileCertificateLoader.class);
	
	private CertificateFactory certificateFactory;

	public FileCertificateLoader() throws CertificateLoaderException {
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new CertificateLoaderException("error instantiating certificate factory", e);
		}
	}
	
	public byte[] loadCertificateData(String filename) throws CertificateLoaderException {
		Properties properties = new Properties();
		properties.put(FILENAME, filename);
		return loadCertificateData(properties);
	}
	
	public Certificate loadCertificate(String filename) throws CertificateLoaderException {
		Properties properties = new Properties();
		properties.put("filename", filename);
		return loadCertificate(properties);	
	}
	
	//Override
	public Certificate loadCertificate(Properties properties) throws CertificateLoaderException {
		Certificate certificate = null;		
		try {
			byte [] data = loadCertificateData(properties);
			certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(data));
		} catch (CertificateException e) {
			throw new CertificateLoaderException("error parsing certificate from file", e);
		}
		return certificate;
	}
	
	//Override
	public byte[] loadCertificateData(Properties properties)throws CertificateLoaderException {
		byte [] data = null;
		String filename = properties.getProperty(FILENAME);
		if (filename != null) {
			File f = new File(filename);
			try(InputStream fis = new FileInputStream(f)) {
				data = new byte[(int)f.length()];
				if(fis.read(data) != (int)f.length()){
					logger.error("error reading data from file");
					throw new CertificateLoaderException("error reading data from file");
				}
			} catch (FileNotFoundException e) {
				logger.error("file '" + filename + "' not found", e);
				throw new CertificateLoaderException("error loading file " + filename, e);
			} catch (IOException e) {
				logger.error("error reading from file '" + filename + "'", e);
				throw new CertificateLoaderException("error reading certificate from " + filename, e);
			}
		} else {
			logger.error("no valid filename supplied for certificate"); 
			throw new CertificateLoaderException("no valid filename supplied for certificate");
		}
		return data;
	}
}
