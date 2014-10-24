/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard.discovery;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import org.dihedron.core.License;
import org.dihedron.core.filters.Filter;
import org.dihedron.crypto.exceptions.SmartCardException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funtò
 */
@License
public final class Readers {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(Readers.class);
	
	/**
	 * Enumerates all available readers and returns basic information about 
	 * each of them: their assigned slot, the description and, if a smart card 
	 * is present, its ATR.
	 * 
	 * @return
	 *   a collection of smart card readers information objects ({@code Reader}s).
	 * @throws SmartCardException
	 *   if an unrecoverable error occurs while loading the PC/SC layer or 
	 *   accessing the smart card reader (terminal) factory object.
	 */
	public static Collection<Reader> enumerate() throws SmartCardException {
		List<Reader> readers = new ArrayList<Reader>();
		try {
			int slot = 0;
			for (CardTerminal terminal : TerminalFactory.getInstance("PC/SC", null).terminals().list()) {
				ATR atr = null;
				String name = terminal.getName();
				try {					
					logger.trace("connecting to smart card reader '{}' at slot {}...", name, slot);
					if(terminal.isCardPresent()) {
						logger.trace("... smart card available in reader");
						atr = new ATR(terminal.connect("*").getATR().getBytes());
						logger.trace("... smart card in reader has ATR '{}'", atr);
					}			
					readers.add(new Reader(slot, name, atr));
				} catch(CardException e) {
					logger.warn("error accessing reader '" + name + "', it will be ignored", e);
				}
				slot++;
			}
		} catch(CardException e) {
			logger.error("error accessing the smart card reader (terminal) factory", e);
			throw new SmartCardException("error accessing the smart card reader (terminal) factory", e);
		} catch (NoSuchAlgorithmException e) {
			logger.error("error opening PC/SC provider: it may not be available", e);
			throw new SmartCardException("error opening PC/SC provider: it may not be available", e);
		}
		return readers;
	}
	
	/**
	 * Enumerates the available readers, applying a filter to it.
	 * 
	 * @param filter
	 *   the filter to be applied.
	 * @return
	 *   a collection of readers filtered according to the given criteria.
	 * @throws SmartCardException
	 */
	public static Collection<Reader> enumerate(Filter<Reader> filter) throws SmartCardException {
		Collection<Reader> readers = enumerate();
		return Filter.apply(filter, readers);
	}
	
	/**
	 * Private constructor, to prevent instantiation of library.
	 */ 
	private Readers() {
	}
}
