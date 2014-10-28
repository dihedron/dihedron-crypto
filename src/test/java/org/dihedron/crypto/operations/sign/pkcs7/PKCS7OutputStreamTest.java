/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */
package org.dihedron.crypto.operations.sign.pkcs7;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.dihedron.core.License;
import org.dihedron.core.os.OperatingSystem;
import org.dihedron.core.os.Platform;
import org.dihedron.core.os.files.FileFinder;
import org.dihedron.core.os.modules.ImageFile;
import org.dihedron.core.os.modules.ImageFileParser;
import org.dihedron.core.os.modules.ImageParseException;
import org.dihedron.core.os.modules.ImageFile.Format;
import org.dihedron.core.streams.Streams;
import org.dihedron.core.url.URLFactory;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.certificates.TrustAnchors;
import org.dihedron.crypto.constants.SignatureAlgorithm;
import org.dihedron.crypto.exceptions.CertificateVerificationException;
import org.dihedron.crypto.exceptions.ProviderException;
import org.dihedron.crypto.exceptions.UnavailableDriverException;
import org.dihedron.crypto.operations.sign.SigningStream;
import org.dihedron.crypto.operations.sign.SigningStreamConfigurator;
import org.dihedron.crypto.providers.AutoCloseableProvider;
import org.dihedron.crypto.providers.smartcard.SmartCardKeyRing;
import org.dihedron.crypto.providers.smartcard.SmartCardProviderFactory;
import org.dihedron.crypto.providers.smartcard.SmartCardTraits;
import org.dihedron.crypto.providers.smartcard.discovery.DataBase;
import org.dihedron.crypto.providers.smartcard.discovery.DataBaseLoader;
import org.dihedron.crypto.providers.smartcard.discovery.Reader;
import org.dihedron.crypto.providers.smartcard.discovery.Readers;
import org.dihedron.crypto.providers.smartcard.discovery.SmartCard;
import org.dihedron.crypto.ui.PINDialog;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@License
public class PKCS7OutputStreamTest {
	
	private static final Logger logger = LoggerFactory.getLogger(PKCS7OutputStreamTest.class);

	private static Map<Platform, String[]> paths = new HashMap<>();
	static {
		paths.put(Platform.LINUX_32, new String[]{ "/lib/i386-linux-gnu/", "/usr/local/lib/" });
		paths.put(Platform.LINUX_64, new String[]{ "/lib/x86_64-linux-gnu/", "/usr/local/lib/" });
	}
	
	@Before
	public void setUp() throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		
		// if on Linux (what about MacOS-X?) I need to load the libpcsclite library 
		// otherwise the PKCS#11 support will throw an exception as soon as loaded
		ImageFileParser parser = null;
		
		// ... if only I had lambdas!
		Platform platform = Platform.getCurrent();
		switch(platform.getOperatingSystem()) {
		case LINUX:
			parser = ImageFileParser.makeParser(Format.ELF);
			for(File file : FileFinder.findFile("libpcsclite.*", true, paths.get(platform))) {
				try {
					ImageFile module = parser.parse(file);
					logger.trace("module: {}", module.toJSON());
					if(module.getAddressing() == platform.getAddressing() && (module.getOperatingSystem() == OperatingSystem.LINUX || module.getOperatingSystem() == OperatingSystem.SYSTEM_V)) {
						// make the library accessible to the JVM
						logger.info("making libpcsclite accessible from file at {}", file.getCanonicalPath());
						System.setProperty("sun.security.smartcardio.library", file.getCanonicalPath());
						break;
					}
				} catch(IOException | ImageParseException e) {
					logger.error("error parsing image at " + file.getCanonicalPath(), e);
				}
			}
			
			break;
		case MACOSX:
			// TODO: implement once support is ready
			logger.warn("unsupported platform");
			break;
		default:
			logger.trace("no need to lookup libpcsclite");			
			break;
		}
	}
	
	@Test
	public void testWrite() throws Exception {
		String password = new PINDialog("Please enter PIN", "SmartCard model unknown").getPIN();
		
		//
		// DETECT THE SMART CARD, INSTANTIATE ITS PROVIDER AND GRAB THE KEYRING
		//
		try (AutoCloseableProvider provider = new SmartCardProviderFactory().getProvider(getSmartCardTraits()); KeyRing keyring = new SmartCardKeyRing(provider, password)) {
			if(provider == null) {
				logger.warn("no smart card available, aborting test");
				return;
			}
			
			//
			// PREPARE THE TRUST ANCHORS
			//
			Collection<X509Certificate> trustAnchors = TrustAnchors.fromJavaRootCAs();			
			trustAnchors.addAll(TrustAnchors.fromTSL("classpath:org/dihedron/crypto/certificates/tsl/DIGITPA-20141015.xml"));
//			trustAnchors.addAll(TrustAnchors.fromTSL("https://applicazioni.cnipa.gov.it/TSL/IT_TSL_signed.xml"));			
						
			for(String alias : keyring.getSignatureKeyAliases()) {
				logger.info("signature alias: '{}'", alias);
				
				SigningStreamConfigurator configurator = new SigningStreamConfigurator();
				configurator					
					.setAlias(alias)
					.setAlgorithm(SignatureAlgorithm.SHA256_WITH_RSA)
					.setKeyRing(keyring)
					.setProvider(provider)
					.setEncapsulateData(true)
					.setVerifyCertificate(true)
					.addTrustAnchors(trustAnchors);
								
				try (	InputStream input = URLFactory.makeURL("classpath:org/dihedron/crypto/data/tutorial.pdf").openStream(); 
						ByteArrayOutputStream output = new ByteArrayOutputStream(); 
						SigningStream signer = new PKCS7SigningStream(output, configurator)) {
					
					Streams.copy(input, signer);
					signer.flush();
					// VERY IMPORTANT NOTE: signed attributes table is not appended to 
					// the encapsulated data until you actually close the CMS signed
					// data generator stream (wrapped by the PKCSOutputStream): that 
					// is the point when the generator understands that it can seal
					// the stream with signature data: never forget to close()!!!!
					signer.close();
					
					logger.trace("written {} bytes to (signed output) output buffer", output.size());
					
					byte[] data = Arrays.clone(output.toByteArray());
					logger.trace("cloned byte array has a size of {} bytes", data.length);
					try(InputStream signed = new ByteArrayInputStream(data); OutputStream fos = new FileOutputStream("tutorial_streaming.pdf.p7e")) {
						Streams.copy(signed, fos);
						
					}
					
//					try(InputStream signed = new ByteArrayInputStream(data)) {
//						if(signer.verify(signed)) {
//							logger.info("data verified");
//						} else {
//							logger.error("error verifying data");
//						}
//					}
					
				}
				
			}
		} catch(CertificateVerificationException e) {
			logger.warn("the certificate has expired or is not valid (CRL)");
		} catch(UnavailableDriverException e) {
			logger.warn("there is no valid driver for the current platform/smartcard combination: maybe you're running on a 64-bits JVM on Windows?");
		} catch(IllegalArgumentException e) {
			if(e.getMessage().equalsIgnoreCase("missing provider")) {
				logger.warn("there is no valid smartcard in any slot");
			} else {
				throw e;
			}
		}
		
	}	
	
	private SmartCardTraits getSmartCardTraits() throws IOException, ProviderException {
		DataBase database = DataBaseLoader.load();			
		
		List<Reader> readers = new ArrayList<Reader>();
		while(true) {
			readers.clear();
			for(Reader reader : Readers.enumerate()) {
				logger.trace("reader:\n{}", reader);
				if(reader.hasSmartCard()) {
					readers.add(reader);
				}
			}
			if(readers.size() == 1) {
				SmartCard smartcard = database.get(readers.get(0).getATR());
				logger.trace("selected smartcard:\n{}", smartcard);				
				return new SmartCardTraits(readers.get(0), smartcard);
			} else {
				logger.warn("no readers have a smart card available");
				break;
			}
		}
		return null;
	}
}
