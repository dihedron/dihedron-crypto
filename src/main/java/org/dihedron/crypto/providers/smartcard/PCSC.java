/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.dihedron.core.License;
import org.dihedron.core.os.Addressing;
import org.dihedron.core.os.OperatingSystem;
import org.dihedron.core.os.Platform;
import org.dihedron.core.os.files.FileFinder;
import org.dihedron.core.os.modules.ImageFile;
import org.dihedron.core.os.modules.ImageFile.Format;
import org.dihedron.core.os.modules.ImageFileParser;
import org.dihedron.core.os.modules.ImageParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class providing support for PC/SC initialisation; this is particularly important 
 * on UNIX/Linux systems, where PC/SC is emulated via a library that is not part
 * of the ordinary set of system libraries and must therefore be found and loaded
 * into the JVM; this is what this utility class does.
 *  
 * @author Andrea Funto'
 */
@License
public final class PCSC {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(PCSC.class);

	/**
	 * The potential location of the libpcsclite library on the variouos platforms.
	 */
	private static Map<Platform, String[]> paths = new HashMap<>();
	static {
		paths.put(Platform.LINUX_32, new String[] {
				"/lib/i386-linux-gnu/",
				"/usr/local/lib/"
			}); 
		paths.put(Platform.LINUX_64, new String[] {
				"/lib/x86_64-linux-gnu/",
				"/usr/local/lib/"
			}); 
	}
	
	/**
	 * Loads the PC/SC library on systems where it is not available by default:
	 * on linux (and probably MacOS X) we need to discover and load into the JVM
	 * an implementation of the PC/SC protocol, which is not part of the base 
	 * operating system set of functionalities and libraries and is therefore not 
	 * available to the JVM under the ordinary LD_LIBRARY_PATH.
	 */
	public static void load() {
		
		// if on Linux (what about MacOS-X?) I need to load the libpcsclite library 
		// otherwise the PKCS#11 support will throw an exception as soon as loaded
		
		Platform platform = Platform.getCurrent();
		switch(platform.getOperatingSystem()) {
		case WINDOWS:
			logger.trace("no need to initialise the PC/SC subsystem on Windows");
			if(platform.getAddressing() == Addressing.SIZE_64) {
				logger.warn("64-bits Windows is not a supported platform");
			}
			break;
		case LINUX:
			ImageFileParser parser = ImageFileParser.makeParser(Format.ELF);
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
					logger.error("error parsing image at " + file.getAbsolutePath(), e);
				}
			}			
			break;
		case MACOSX:
			// TODO: implement once support is ready
			// NOTE: voluntary fall-through until mac is supported
		default:
			logger.trace("unsupported platform");			
			break;
		}
	}
	
	/**
	 * Private constructor, to prevent library instantiation.
	 */
	private PCSC() {
	}
}
