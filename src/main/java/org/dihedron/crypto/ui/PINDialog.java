/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved.
 * 
 * This file is part of the Dihedron Crypto Utilities library ("Crypto").
 *
 * "Crypto" is free software: you can redistribute it and/or modify it under 
 * the terms of the GNU Lesser General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option) 
 * any later version.
 *
 * "Crypto" is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR 
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License 
 * along with "Crypto". If not, see <http://www.gnu.org/licenses/>.
 */
package org.dihedron.crypto.ui;

import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public class PINDialog extends JDialog implements ActionListener {

	/**
	 * Whether by default the dialog should be modal.
	 */
	public static final boolean DEFAULT_MODALITY = true;
			
    /**
	 * Serial version id.
	 */
	private static final long serialVersionUID = -4012173637510636595L;
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(PINDialog.class);

	/**
	 * The PIN characters (only populated upon exit).
	 */
	private char[] pin = null;
	
	/**
	 * The caption label, above the input password field.
	 */
	private JLabel caption;
    
    /**
     * The label for the password field.
     */
    private JLabel label;
    
    /**
     * The OK button.
     */
    private JButton ok;
    
	/**
	 * The cancel button.
	 */
    private JButton cancel;
    
    /**
     * The password input field.
     */
    private JPasswordField password;
                       
	/**
	 * Default constructor, creates a modal dialog with no owner. 
	 */
	public PINDialog() {
		this(null, DEFAULT_MODALITY, null, null);
	}
	
	/**
	 * Constructor, creates a modal dialog with the given owner.
	 * 
	 * @param parent
	 *   the dialog owner.
	 */
	public PINDialog(Frame parent) {
		this(parent, DEFAULT_MODALITY, null, null);
	}
	
	/**
	 * Constructor, creates a dialog with no owner.
	 * 
	 * @param modal
	 *   whether the dialog is modal.
	 */
	public PINDialog(boolean modal) {
		this(null, modal);
	}		
	
	/**
     * Constructor.
     * 
     * @param frame
     *   the owning frame (window, dialog...).
     * @param modal
     *   whether the dialog is modal.
     */
    public PINDialog(Frame parent, boolean modal) {
    	this(parent, modal, null, null);
    }
    
	/**
     * Constructor.
     * 
     * @param title
     *   the title dialog.
     * @param caption
     *   the caption to be shown right above the password input field, e.g to provide
     *   some information about the specific smart card for which the password is
     *   being requested.
     */
    public PINDialog(String title, String caption) {
    	this(null, DEFAULT_MODALITY, title, caption);    
    }

	/**
     * Constructor.
     * 
     * @param frame
     *   the owning frame (window, dialog...).
     * @param modal
     *   whether the dialog is modal.
     * @param title
     *   the title dialog.
     */
    public PINDialog(Frame parent, boolean modal, String title) {
        this(parent, modal, title, null);
    }   
    
	/**
     * Constructor.
     * 
     * @param frame
     *   the owning frame (window, dialog...).
     * @param modal
     *   whether the dialog is modal.
     * @param title
     *   the title dialog.
     * @param caption
     *   the caption to be shown right above the password input field, e.g to provide
     *   some information about the specific smart card for which the password is
     *   being requested.
     */
    public PINDialog(Frame parent, boolean modal, String title, String caption) {    	
        super(parent, title, modal);
        
        setLocationRelativeTo(parent);
        
        // set system look'n'feel
        try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException e) {
			logger.error("error installing system look'n'feel", e);
		} 
        
        initComponents(caption);
    }  
    
    public PINDialog setDialogTitle(String title) {
    	this.setTitle(title);
    	return this;
    }
        
    /**
     * Shows the dialog and returns the actual PIN.
     * 
     * @return
     *   the PIN, or null if the user cancelled the operation.
     */
    public String getPIN() {
		this.setVisible(true);
		if(pin != null) {
			return new String(pin);
		}
		return null;
    }    

    /**
     * This method is called from within the constructor to initialize the form.
     * 
     * @param caption
     *   the caption to be shown right above the password input field, e.g to provide
     *   some information about the specific smart card for which the password is
     *   being requested.
     */
    private void initComponents(String caption) {
        this.caption = caption == null ? new JLabel("Insert PIN for smartcard") : new JLabel(caption);
        this.label = new JLabel();
        this.password = new JPasswordField();
        this.ok = new JButton();
        this.cancel = new JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);        

        this.label.setText("PIN:");

        this.ok.setText("OK");
        this.getRootPane().setDefaultButton(ok);
        this.ok.addActionListener(this);

        this.cancel.setText("Cancel");
        this.cancel.addActionListener(this);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(this.caption, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(this.label)
                        .addGap(18, 18, 18)
                        .addComponent(this.password))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 221, Short.MAX_VALUE)
                        .addComponent(this.ok, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(this.cancel, javax.swing.GroupLayout.PREFERRED_SIZE, 76, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(this.caption, javax.swing.GroupLayout.PREFERRED_SIZE, 38, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(this.password, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(this.label))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                    .addComponent(this.ok)
                    .addComponent(this.cancel))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }
    
	/**
	 * Reacts to user clicks and events.
	 */
	@Override
	public void actionPerformed(ActionEvent e) {
		switch(e.getActionCommand()) {
		case "OK":
			logger.trace("OK pressed");
			this.pin = password.getPassword();
			this.dispose();			
			break;
		case "Cancel":
			logger.trace("Cancel pressed");
			this.pin = null;
			this.dispose();			
			break;
		}		
	}    
}
