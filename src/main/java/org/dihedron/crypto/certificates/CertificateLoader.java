/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.certificates;

import java.security.cert.Certificate;
import java.util.Properties;

import org.dihedron.core.License;
import org.dihedron.crypto.exceptions.CertificateLoaderException;

@License
public interface CertificateLoader {
	
	Certificate loadCertificate(Properties properties) throws CertificateLoaderException;
	
	byte [] loadCertificateData(Properties properties) throws CertificateLoaderException;
}
