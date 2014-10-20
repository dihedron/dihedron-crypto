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
package org.dihedron.crypto.providers.smartcard.discovery;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.dihedron.core.os.HardDrives;
import org.dihedron.core.os.Platform;
import org.dihedron.core.variables.EnvironmentValueProvider;
import org.dihedron.core.variables.SystemPropertyValueProvider;
import org.dihedron.core.variables.Variables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class representing a shared object or dynamic link library supporting a
 * smart card driver on a given platform.
 * 
 * @author Andrea Funto'
 */
public class Driver {
	/**
	 * The logger
	 */
	private static final Logger logger = LoggerFactory.getLogger(Driver.class);
	
	/**
	 * A variable representing all mounted file system roots (all drives on Windows).
	 */
	private static final String ALL_DRIVES = "@{ALL_DRIVES}";

	/**
	 * The platform on which this driver is supported.
	 */
	private Platform platform;
	
	/**
	 * The list of paths under which the driver can be located, including the name 
	 * of the PKCS#11 library.
	 */
	private List<String> paths;

	
	/**
	 * Constructor.
	 * 
	 * @param platform
	 *   the platform supported by this driver, as a string.
	 */
	Driver(String platform) {
		this(Platform.fromString(platform));
	}
	
	/**
	 * Constructor.
	 * 
	 * @param platform
	 *   the platform supported by this driver.
	 */
	Driver(Platform platform) {
		logger.trace("instantiating driver for platform '{}'", platform);
		this.platform = platform;
		this.paths = new ArrayList<String>();
	}
	
	/**
	 * Returns the platform on which this driver is supported.
	 * 
	 * @return
	 *   the platform on which this driver is supported.
	 */
	public Platform getPlatform() {
		return platform;
	}
	
	/**
	 * Adds a path on the file system to the set of paths under which the driver 
	 * can be located.
	 * 
	 * @param path
	 *   the path to the driver's supporting library.
	 */
	void addPath(String path) {
		if(path != null && path.trim().length() > 0) {
			logger.trace("supporting library: '{}'", path);
			paths.add(path);
		}
	}

	/**
	 * Locates the driver on disk and returns the fully qualified path to the
	 * supporting library.
	 *  
	 * @return
	 *   the File object representing the supporting driver library, or null if
	 *   not found on disk.
	 */
	File find() {
		List<String> pathsToTest = new ArrayList<String>();
		for(String path : paths) {			
			logger.trace("analysing path '{}'", path);
			if(path.startsWith(ALL_DRIVES)) {
				List<File> roots = HardDrives.listAll();
				String temp = path.replace(ALL_DRIVES, "");
				for(File root : roots) {
					String newPath = root.getAbsolutePath() + temp;
					logger.trace("adding new generated path '{}'", newPath);
					pathsToTest.add(newPath);
				}
			} else {
				pathsToTest.add(path);
			}
		}
		
		for(String path : pathsToTest) {
			path = Variables.replaceVariables(path, new SystemPropertyValueProvider(), new EnvironmentValueProvider());
			logger.trace("trying to locate driver library '{}'...", path);
			File file = new File(path);
			if(file.exists() && file.isFile()) {
				logger.info("library '{}' found", path);
				return file;
			}
		}
		logger.info("no supporting library found");
		return null;
	}
	
	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer
			.append("driver: { platform: '")
			.append(platform)
			.append("', paths: [");
		boolean first = true;
		for(String path: paths) {
			buffer.append(first ? "'" : ", '").append(path).append("'");
			first = false;
		}
		buffer.append("] },");
		return buffer.toString();		
	}
}
