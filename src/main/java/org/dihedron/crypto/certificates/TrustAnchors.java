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
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.dihedron.core.url.URLFactory;
import org.dihedron.core.variables.SystemPropertyValueProvider;
import org.dihedron.core.variables.Variables;
import org.dihedron.core.xml.DOM;
import org.dihedron.crypto.certificates.impl.Base64CertificateLoader;
import org.dihedron.crypto.exceptions.CertificateLoaderException;
import org.dihedron.crypto.exceptions.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * @author Andrea Funto'
 */
public final class TrustAnchors {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(TrustAnchors.class);
	
	/**
	 * The path to the CA root certificates.
	 */
	private static final String CACERTS_PATH = "${java.home}/lib/security/cacerts";
	
	/**
	 * The default password of the CA root certificates key store.
	 */
	private static final String CACERTS_PASSWORD = "changeit";

	/**
	 * Attempts to load the certificates of the most trusted CAs ("root CAs") as 
	 * known to the Java Virtual Machine.
	 * 
	 * @return
	 *   a List of certificates of the "root CAs".   
	 * @throws CryptoException
	 */
	public static List<X509Certificate> fromJavaRootCAs() throws CryptoException {
		List<X509Certificate> trustAnchors = new ArrayList<>();
		try {
	        // load the JDK's cacerts keystore file
			String filename = Variables.replaceVariables(CACERTS_PATH, new SystemPropertyValueProvider());
	        FileInputStream is = new FileInputStream(filename);
	        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	        keystore.load(is, CACERTS_PASSWORD.toCharArray());
	
	        // this class retrieves the most-trusted CAs from the keystore
	        PKIXParameters parameters = new PKIXParameters(keystore);
	
	        // get the set of trust anchors, which contain the most-trusted CA certificates
	        Iterator<TrustAnchor> iterator = parameters.getTrustAnchors().iterator();
	        while( iterator.hasNext() ) {
	            TrustAnchor trustAnchor = (TrustAnchor)iterator.next();
	            // get certificate
	            X509Certificate certificate = trustAnchor.getTrustedCert();
//	            logger.trace("adding certificate '{}' to root CAs", certificate.getSubjectDN());
	            trustAnchors.add(certificate);
	        }
	        logger.trace("returning {} certificates as trust anchors", trustAnchors.size());
	        return trustAnchors;
	    } catch (CertificateException e) {
	    	logger.error("certificate exception", e);
	    	throw new CryptoException("certificate exception", e);
	    } catch (KeyStoreException e) {
	    	logger.error("error acquiring or loading the key store", e);
	    	throw new CryptoException("error acquiring or loading the key store", e);
	    } catch (NoSuchAlgorithmException e) {
	    	logger.error("key store loading requires unsupported algorithm", e);
	    	throw new CryptoException("key store loading requires unsupported algorithm", e);	    	
	    } catch (InvalidAlgorithmParameterException e) {
	    	logger.error("PKIXParameters class does not support the key store algorithm", e);
	    	throw new CryptoException("PKIXParameters class does not support the key store algorithm", e);	    	
	    } catch (IOException e) {
	    	logger.error("error reading the key store from disk", e);
	    	throw new CryptoException("error reading the key store from disk", e);	    	
	    }
	}
	
	public static List<X509Certificate> fromTSL(String tslURL) throws MalformedURLException {
		List<X509Certificate> trustAnchors = new ArrayList<>();
		
		logger.trace("acquiring root CAs from TSL '{}'", tslURL);
		
		URL url = URLFactory.makeURL(tslURL);
		try (InputStream stream = url.openStream()){
			logger.trace("stream opened");
			DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			logger.trace("XML document builder ready, reading");
			Document document = builder.parse(stream);
			logger.trace("XML read and parsed");
			List<Element> nodes = DOM.getDescendantsByTagName(document, "X509Certificate");
			logger.trace("{} nodes found", nodes.size());
			Base64CertificateLoader loader = new Base64CertificateLoader();			
			for(Element node : nodes) {
				String data = node.getTextContent();
				try {
					X509Certificate certificate = (X509Certificate)loader.loadCertificate(data);				
//					logger.trace("adding certificate '{}' to root CAs", certificate.getSubjectDN());
					trustAnchors.add(certificate);
				} catch(Exception e) {
					logger.warn("discarding invalid (unparseable) certificate data '{}'", data);
				}
				
			}
		} catch (ParserConfigurationException | SAXException | IOException e) {
			logger.error("error acquiring TSL from '" + tslURL + "'", e);
		} catch (CertificateLoaderException e) {
			logger.error("error initialising certificate loader", e);
		}
		
		return trustAnchors;
	}
		
	/**
	 * Private constructor, to prevent instantiation.
	 */
	private TrustAnchors() {		
	}
}
