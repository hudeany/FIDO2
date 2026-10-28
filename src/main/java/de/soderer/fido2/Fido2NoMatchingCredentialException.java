package de.soderer.fido2;

/**
 * Thrown when none of the given credentials belongs to the connected token
 * (e.g. a file was encrypted with a different token).
 */
public class Fido2NoMatchingCredentialException extends Fido2Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Creates a new exception.
	 *
	 * @param message description of the mismatch, suitable for display to
	 *        the user
	 */
	public Fido2NoMatchingCredentialException(final String message) {
		super(message);
	}
}
