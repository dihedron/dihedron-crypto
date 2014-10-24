/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.providers.smartcard.discovery;

import org.dihedron.core.License;


/**
 * @author Andrea Funto'
 */
@License
public class Reader {
	/**
	 * The slot assigned to this smart card reader.
	 */
	private int slot;
	
	/**
	 * A string describing model and make of the smart card reader.
	 */
	private String description;
	
	/**
	 * Possibly the ATR of the smart card inserted into the reader.
	 */
	private ATR atr;
	
	/**
	 * Constructor; it is supposed to be called only by the Readers factory class.
	 * 
	 * @param slot
	 *   the slot assigned to this smart card reader.
	 * @param description
	 *   the description of the model and make of this reader.
	 */
	Reader(int slot, String description) {
		this(slot, description, null);
	}

	/**
	 * Constructor; it is supposed to be called only by the Readers factory class.
	 * 
	 * @param slot
	 *   the slot assigned to this smart card reader.
	 * @param description
	 *   the description of the model and make of this reader.
	 * @param atr
	 *   if a smart card is present, the ATR of the smart card.
	 */
	Reader(int slot, String description, ATR atr) {
		this.slot = slot;
		this.description = description;
		this.atr = atr;
	}

	/**
	 * Returns the slot index assigned to this reader.
	 * 
	 * @return
	 *   the slot index assigned to this reader.
	 */
	public int getSlot() {
		return slot;
	}
	
	/**
	 * Sets a new value for the reader's slot; it is supposed to be
	 * called exclusively by the {@code Readers} factory class.
	 * 
	 * @param slot
	 *   the new value for the slot index.
	 */
	void setSlot(int slot) {
		this.slot = slot;
	}
	
	/**
	 * Returns a string describing model and make of the smart card reader.
	 * 
	 * @return
	 *   a string describing model and make of the smart card reader.
	 */
	public String getDescription() {
		return description;
	}
	
	/**
	 * Sets a new value for the reader's description; it is supposed to be
	 * called exclusively by the {@code Readers} factory class.
	 * 
	 * @param description
	 *   the new value for the reader's description.
	 */
	void setDescription(String description) {
		this.description = description;
	}
	
	/**
	 * If a smart card is inserted into the reader, returns its ATR (answer-to-reset)
	 * code.
	 * 
	 * @return
	 *   the ATR code of the smart card, if one is available in the reader.
	 */
	public ATR getATR() {
		return atr;
	}
	
	/**
	 * Sets a new value for the smart card ATR; it is supposed to be
	 * called exclusively by the {@code Readers} factory class.
	 * 
	 * @param atr
	 *   the new value for the smart card ATR, if present.
	 */
	void setATR(ATR atr) {
		this.atr = atr;
	}
	
	/**
	 * Returns whether this smart card reader had a smart card present 
	 * when this object was created; this information may not be actual 
	 * and may not reflect the real status of the physical reader if the 
	 * user inserted or removed the smart card after the creation of
	 * this object.
	 * 
	 * @return
	 *   whether the smart card reader had a smart card available when this
	 *   object was created.
	 */
	public boolean hasSmartCard() {
		return atr != null;
	}

	/**
	 * Returns a JSON-like representation of the reader's internal status.
	 */
	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder("reader: {\n");
		buffer.append("\t").append("slot          : ").append(slot).append(",\n");
		buffer.append("\t").append("description   : '").append(description).append("'");
		if(atr != null) {
			buffer.append(",\n");
			buffer.append("\t").append("smartcard ATR : '").append(atr.toString()).append("'\n");
		}
		buffer.append("}");
		return buffer.toString();		
	}
}
