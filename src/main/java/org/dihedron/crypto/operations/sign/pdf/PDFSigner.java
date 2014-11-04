/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
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
import java.security.cert.Certificate;

import org.dihedron.core.License;
import org.dihedron.core.library.Traits;
import org.dihedron.core.streams.Streams;
import org.dihedron.crypto.Crypto;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;
import org.dihedron.crypto.operations.sign.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;

/**
 * @author Andrea Funto'
 */
@License
public class PDFSigner extends Signer {
	
	@License
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
	private static Logger logger = LoggerFactory.getLogger(PDFSigner.class);
	
	private Key key = null;
	
	private Certificate[] chain = null; 
	
	private Mode mode = null;
	
	public PDFSigner(String alias, KeyRing keyring, Provider provider) throws CryptoException {
		this(alias, keyring, provider, Mode.CONCURRENT);
	}
	
	/**
	 * Constructor.
	 * @throws CryptoException 
	 */
	public PDFSigner(String alias, KeyRing keyring, Provider provider, Mode mode) throws CryptoException {
		super(alias, keyring, provider);
		this.mode = mode;

		// retrieve key and certificate
		key = keyring.getPrivateKey(alias);
		//certificate = accessor.getCertificate(alias);		
		chain = keyring.getCertificateChainAsArray(alias);
		
		logger.trace("PdfSigner initialised");
	} 

	@Override
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
	
	@Override
	public void sign(InputStream input, OutputStream output) throws CryptoException {
		try {
			PdfReader reader = new PdfReader(input);
			PdfStamper stamper = PdfStamper.createSignature(reader, output, '\0');
			PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
			//appearance.setVisibleSignature("mySig");
			appearance.setReason("Signed with Dihedron WebSign - Digital Signature for the Web ver. " + Crypto.valueOf(Traits.VERSION));
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
}
