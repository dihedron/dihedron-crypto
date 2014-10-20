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
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.dihedron.core.os.Platform;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents the smart card information needed to use a given smart 
 * card on a set of supported platforms; the smart card can be identified by 
 * means of its SMARTCARD_ATR (answer to reset) code and is accompanied by a description,
 * and the name of the manufacturer; each supporting driver (one per platform) 
 * has the name of the PKCS#11 driver library ( a .dll on Windows, a .so on 
 * Linux...) and a series of paths where it should be located.
 * 
 * @author Andrea Funto'
 */
public class SmartCard {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(SmartCard.class);
	
	/**
	 * The smart card Answer To Reset code.
	 */
	private ATR atr;
	
	/**
	 * The smart card description.
	 */
	private String description;
	
	/**
	 * The smart card manufacturer.
	 */
	private String manufacturer;
	
	/**
	 * The smart card drivers, one for each supported platform.
	 */
	private Map<Platform, Driver> drivers = new HashMap<Platform, Driver>();
	
	/**
	 * Constructor.
	 * 
	 * @param atr
	 *   the ATR object representing the unique Answer To Reset byte sequence.
	 */
	SmartCard(ATR atr) {
		logger.trace("creating a new smartcard for ATR '{}'", atr);
		this.atr = atr;
	}
	
	/**
	 * Retrieves the smart card SMARTCARD_ATR.
	 * 
	 * @return
	 *   the smart card Answer To Reset code.
	 */
	public ATR getATR() {
		return atr;
	}

	/**
	 * Returns the smart card description.
	 * 
	 * @return
	 *   the smart card description.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Sets the smart card description.
	 * 
	 * @param description
	 *   the smart card description.
	 */
	void setDescription(String description) {
		logger.trace("setting description to '{}'", description);
		this.description = description;
	}

	/**
	 * Returns the smart card manufacturer.
	 * 
	 * @return
	 *   the smart card manufacturer.
	 */
	public String getManufacturer() {
		return manufacturer;
	}

	/**
	 * Sets the smart card manufacturer.
	 * 
	 * @param manufacturer
	 *   the smart card manufacturer.
	 */
	void setManufacturer(String manufacturer) {
		this.manufacturer = manufacturer;
	}
	
	/**
	 * Adds a new driver to the list of supporting libraries for the given 
	 * smart card.
	 * 
	 * @param driver
	 *   the driver to be added.
	 */
	void addDriver(Driver driver) {
		if(driver != null) {
			logger.info("adding new driver for platform '{}' to smartcard '{}'", driver.getPlatform(), atr);
			drivers.put(driver.getPlatform(), driver);
		}
	}
	
	/**
	 * Attempts to find the supporting PKCS#11 driver on disk.
	 * 
	 * @param platform
	 *   the current platform.
	 * @return
	 *   the File object representing the PKCS#11 driver, or null.
	 */
	public File getDriver(Platform platform) {
		Driver driver = drivers.get(platform);
		if(driver != null) {
			return driver.find();
		}
		logger.error("no supporting driver found for smartcard '{}' (SMARTCARD_ATR: {}) on platform '{}'", description, atr, platform);
		return null;
	}
	
	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer.append("smartcard: {\n");
		buffer.append("\tatr          : '").append(atr).append("',\n");
		buffer.append("\tdescription  : '").append(description).append("',\n");
		buffer.append("\tmanufacturer : '").append(manufacturer).append("',\n");
		buffer.append("\tdrivers      : [\n");
		for(Entry<Platform, Driver> driver : drivers.entrySet()) {
			buffer.append("\t\t").append(driver.getValue().toString()).append("\n");
		}
		buffer.append("\t]\n");
		buffer.append("}");
		return buffer.toString();
	}
}
