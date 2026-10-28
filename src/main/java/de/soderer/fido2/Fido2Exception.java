package de.soderer.fido2;

/**
 * Runtime error for FIDO2 token operations (device access, credential
 * creation, or assertion creation).
 */
public class Fido2Exception extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public Fido2Exception(final String message) {
		super(message);
	}

	public Fido2Exception(final String message, final Throwable cause) {
		super(message, cause);
	}
}
