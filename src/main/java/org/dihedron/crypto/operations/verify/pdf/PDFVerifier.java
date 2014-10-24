/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.verify.pdf;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.Provider;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;

import org.dihedron.core.License;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.operations.verify.Verifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.PdfReader;

/**
 * @author Andrea Funto'
 */
@License
public class PDFVerifier extends Verifier {
	
	/**
	 * The logger. 
	 */
	private static Logger logger = LoggerFactory.getLogger(PDFVerifier.class);
	
	private KeyRing keyring;
	
	private Key key = null;
	
	private Certificate[] chain = null; 
	
	/**
	 * Constructor.
	 * @throws CryptoException 
	 */
	public PDFVerifier(String alias, KeyRing keyring, Provider provider) throws CryptoException {
		this.keyring = keyring;
		
		// retrieve key and certificate
		key = keyring.getPrivateKey(alias);
		//certificate = accessor.getCertificate(alias);		
		chain = keyring.getCertificateChainAsArray(alias);
		
		logger.trace("PdfSigner initialised");
	} 

	@Override
	public boolean verify(byte[] signed) throws CryptoException {
		return verify(signed, null);
	}

	@Override
	public boolean verify(byte[] signed, byte [] data) throws CryptoException {
		boolean verified = false;
		try {			
			PdfReader reader = new PdfReader(signed);
			AcroFields af = reader.getAcroFields();
			ArrayList<String> names = af.getSignatureNames();
			for (String name : names) {
				logger.debug("signature name: {}", name);
				logger.debug("signature covers whole document: {}", af.signatureCoversWholeDocument(name));
				logger.debug("document revision: {} of {}", af.getRevision(name), af.getTotalRevisions());
				PdfPKCS7 pk = af.verifySignature(name);
				Calendar cal = pk.getSignDate();
				Certificate[] pkc = pk.getCertificates();
				logger.debug("subject: {}", PdfPKCS7.getSubjectFields(pk.getSigningCertificate()));
				logger.debug("revision modified: {}", !pk.verify());
				Object fails[] = PdfPKCS7.verifyCertificates(pkc, keyring.getKeyStore(), null, cal);
				if (fails == null) {
					logger.debug("certificates verified against the KeyStoreHelper");
					verified = true;
				} else {
					logger.warn("certificate failed: {}", fails[1]);
					verified = false;
				}
			}
		} catch(IOException e) {
			throw new CryptoException("I/O exception while verifying the signature", e); 
		} catch (SignatureException e) {
			throw new CryptoException("Signature exception while verifying the signature", e);
		}
		return verified;
	}

	@Override
	public boolean verify(InputStream signed) throws CryptoException {
		// TODO Auto-generated method stub
		return false;
	}
}
