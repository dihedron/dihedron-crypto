package org.dihedron.crypto.exceptions;


/**
 * This class wraps an exception that could be thrown during the certificate
 * verification process.
 * 
 * @author Andrea Funto'
 * @author Svetlin Nakov
 */
public class CertificateVerificationException extends CertificateException {

	/**
	 * Serial version id.
	 */
	private static final long serialVersionUID = -1184561130864502980L;

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 */
	public CertificateVerificationException(String message) {
		super(message);
	}

	/**
	 * Constructor.
	 * 
	 * @param message
	 *   the exception message.
	 * @param cause
	 *   the root cause of the exception.
	 */
	public CertificateVerificationException(String message, Throwable cause) {
		super(message, cause);
	}
}