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
import java.util.Hashtable;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.dihedron.crypto.certificates.CertificateLoader;
import org.dihedron.crypto.certificates.Certificates;
import org.dihedron.crypto.exceptions.CertificateLoaderException;


/**
 * @author Andrea Funto'
 */
public class LDAPCertificateLoader implements CertificateLoader {

	private CertificateFactory certificateFactory;
	private DirContext ldapContext;
	private SearchControls controls;
		
	public LDAPCertificateLoader(String ldapServer, int port) throws CertificateLoaderException {
		String providerUrl = new String("ldap://" + ldapServer + ":" + port + "/");		
		initialise(providerUrl);
	}
	
	public LDAPCertificateLoader(String ldapProviderUrl) throws CertificateLoaderException {
		initialise(ldapProviderUrl);
	}
	
	private void initialise(String ldapProviderUrl) throws CertificateLoaderException {		
		try {
			Hashtable<String, String> environment = new Hashtable<String, String>();
			environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");			
			environment.put(Context.PROVIDER_URL, ldapProviderUrl);

			ldapContext = new InitialDirContext(environment);

			controls = new SearchControls();
			controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new CertificateLoaderException("error instantiating certificate factory", e);
		} catch (NamingException e) {
			throw new CertificateLoaderException("error establishing directory context", e);
		}		
	}
	
	public byte[] loadCertificateData(String name, String filter) throws CertificateLoaderException {	
		Properties properties = new Properties();
		properties.setProperty("name", name);
		properties.setProperty("filter", filter);
		return loadCertificateData(properties );
	}

	
	//Override
	public byte[] loadCertificateData(Properties properties) throws CertificateLoaderException {
		byte [] data = null;
		
		String name = properties.getProperty("name");
		String filter = properties.getProperty("filter");
		
		boolean found = false;

		try {
			NamingEnumeration<SearchResult> results = ldapContext.search(name, filter, controls);
						
			while (results.hasMore() && !found) {
				SearchResult searchResult = (SearchResult) results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attribute = attributes.get("userCertificate;binary");
	
				
				if (attribute != null) {					
					NamingEnumeration<?> values = attribute.getAll();
					while (values.hasMoreElements()) {
						data = (byte[]) values.nextElement();
						//System.out.println("certificate: " + data.length);
						X509Certificate x509certificate = (X509Certificate) certificateFactory
								.generateCertificate(new ByteArrayInputStream(data));
						if(Certificates.isSignatureX509Certificate(x509certificate)) {
							//System.out.println("certificate found");							
							found = true;
							break;
						} else {		
							x509certificate = null;
						}
					}
				}
			}			
		} catch (NamingException e) {
			throw new CertificateLoaderException("ldap search error" , e);
		} catch (CertificateException e) {
			throw new CertificateLoaderException("error parsing certificate" , e);
		}
		
		return data;
	}	
	
	public Certificate loadCertificate(String name, String filter) throws CertificateLoaderException {	
		Properties properties = new Properties();
		properties.setProperty("name", name);
		properties.setProperty("filter", filter);
		return loadCertificate(properties);
	}
	
	//Override
	public Certificate loadCertificate(Properties props) throws CertificateLoaderException {
		
		X509Certificate x509certificate = null;
		
		byte [] data = loadCertificateData(props);
		if (data!=null){
			try {
				x509certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(data));
			} catch (CertificateException e) {
				throw new CertificateLoaderException("error parsing certificate" , e);
			}
		}
				
		return x509certificate;
	}	
}
