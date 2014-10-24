/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.crypto.operations.sign;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;

import org.dihedron.core.License;
import org.dihedron.crypto.KeyRing;
import org.dihedron.crypto.exceptions.CryptoException;

/**
 * @author Andrea Funto'
 */
@License
public abstract class BulkSigner extends Signer {

	/**
	 * @param alias
	 * @param keyring
	 * @param provider
	 * @throws CryptoException
	 */
	public BulkSigner(String alias, KeyRing keyring, Provider provider) throws CryptoException {
		super(alias, keyring, provider);
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see org.dihedron.crypto.operations.sign.Signer#sign(byte[])
	 */
	@Override
	public byte[] sign(byte[] data) throws CryptoException {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see org.dihedron.crypto.operations.sign.Signer#sign(java.io.InputStream, java.io.OutputStream)
	 */
	@Override
	public void sign(InputStream input, OutputStream output) throws CryptoException {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.dihedron.crypto.operations.sign.Signer#verify(byte[])
	 */
	@Override
	public boolean verify(byte[] signed) throws CryptoException {
		// TODO Auto-generated method stub
		return false;
	}

	/* (non-Javadoc)
	 * @see org.dihedron.crypto.operations.sign.Signer#verify(java.io.InputStream)
	 */
	@Override
	public boolean verify(InputStream signed) throws CryptoException {
		// TODO Auto-generated method stub
		return false;
	}

	/* (non-Javadoc)
	 * @see org.dihedron.crypto.operations.sign.Signer#verify(byte[], byte[])
	 */
	@Override
	public boolean verify(byte[] data, byte[] signature) throws CryptoException {
		// TODO Auto-generated method stub
		return false;
	}

}
