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
package org.dihedron.crypto.operations.sign.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;

import org.dihedron.core.library.Traits;
import org.dihedron.core.streams.Streams;
import org.dihedron.crypto.CryptoLibrary;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.operations.sign.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;

/**
 * @author Andrea Funto'
 */
public class PdfSigner extends Signer {
	
	public enum Mode {
		/**
		 * There can only be one signature of this kind per document.
		 */
		EXCLUSIVE,
		
		/**
		 * There can be multiple signatures of this kind per document.
		 */
		CONCURRENT;
	}
	
	/**
	 * The logger. 
	 */
	private static Logger logger = LoggerFactory.getLogger(PdfSigner.class);
	
	private Key key = null;
	
	private Certificate[] chain = null; 
	
	private Mode mode = null;
	
	public PdfSigner(String alias, KeyRing keyring, Provider provider) throws CryptoException {
		this(alias, keyring, provider, Mode.CONCURRENT);
	}
	
	/**
	 * Constructor.
	 * @throws CryptoException 
	 */
	public PdfSigner(String alias, KeyRing keyring, Provider provider, Mode mode) throws CryptoException {
		super(alias, keyring, provider);
		this.mode = mode;

		// retrieve key and certificate
		key = keyring.getPrivateKey(alias);
		//certificate = accessor.getCertificate(alias);		
		chain = keyring.getCertificateChainAsArray(alias);
		
		logger.trace("PdfSigner initialised");
	} 

	public byte[] sign(byte[] data) throws CryptoException {
		ByteArrayInputStream input = null;
		ByteArrayOutputStream output = null;
		try {
			input = new ByteArrayInputStream(data);
			output = new ByteArrayOutputStream();
			sign(input, output);
			return output.toByteArray();
		} finally {
			Streams.safelyClose(input);
			Streams.safelyClose(output);
		}
		
//		ByteArrayOutputStream baos = new ByteArrayOutputStream();  
//		
//		try {
//			PdfReader reader = new PdfReader(data);
//			PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
//			PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
//			//appearance.setVisibleSignature("mySig");
//			appearance.setReason("Signed with Dihedron WebSign - Digital Signature for the Web ver. " + CryptoLibrary.valueOf(Traits.VERSION));
//			appearance.setLocation("Hidden Signature");
//			 
//			appearance.setCrypto((PrivateKey)key, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
//			if(mode == Mode.EXCLUSIVE) {
//				appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
//			}
//			// TODO: no graphic signature mode enabled yet
//	//		if (graphic) {
//	//			appearance.setAcro6Layers(true);
//	//			appearance.setSignatureGraphic(Image.getInstance(RESOURCE));
//	//			appearance.setRenderingMode(
//	//			PdfSignatureAppearance.RenderingMode.GRAPHIC);
//	//		}
//		
//			stamper.close();
//		} catch(IOException e) {
//			throw new CryptoException("I/O exception writing the PDF", e);
//		} catch (DocumentException e) {
//			throw new CryptoException("document exception writing the PDF", e);
//		}
//		return baos.toByteArray();
	}
	
	public void sign(InputStream input, OutputStream output) throws CryptoException {
		try {
			PdfReader reader = new PdfReader(input);
			PdfStamper stamper = PdfStamper.createSignature(reader, output, '\0');
			PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
			//appearance.setVisibleSignature("mySig");
			appearance.setReason("Signed with Dihedron WebSign - Digital Signature for the Web ver. " + CryptoLibrary.valueOf(Traits.VERSION));
			appearance.setLocation("Hidden Signature");
			 
			appearance.setCrypto((PrivateKey)key, chain, null, PdfSignatureAppearance.WINCER_SIGNED);
			if(mode == Mode.EXCLUSIVE) {
				appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
			}
			// TODO: no graphic signature mode enabled yet
	//		if (graphic) {
	//			appearance.setAcro6Layers(true);
	//			appearance.setSignatureGraphic(Image.getInstance(RESOURCE));
	//			appearance.setRenderingMode(
	//			PdfSignatureAppearance.RenderingMode.GRAPHIC);
	//		}		
			stamper.close();
		} catch (IOException e) {
			logger.error("I/O exception writing the PDF", e);
			throw new CryptoException("I/O exception writing the PDF", e);
		} catch (DocumentException e) {
			logger.error("invalid document: exception writing the PDF", e);
			throw new CryptoException("document exception writing the PDF", e);
		}
	}
	
	public boolean verify(byte[] signed) throws CryptoException {
		return verify(signed, null);
	}

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
