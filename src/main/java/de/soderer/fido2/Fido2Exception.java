package de.soderer.fido2;

/**
 * Runtime error for FIDO2 token operations (device access, credential
 * creation, or assertion creation).
 *
 * More specific situations are reported by the subclasses
 * {@link Fido2PinRequiredException} and
 * {@link Fido2NoMatchingCredentialException}.
 */
public class Fido2Exception extends RuntimeException {
	private static final long serialVersionUID = 1L;

	/**
	 * Creates a new exception.
	 *
	 * @param message description of the error
	 */
	public Fido2Exception(final String message) {
		super(message);
	}

	/**
	 * Creates a new exception with an underlying cause.
	 *
	 * @param message description of the error
	 * @param cause the underlying error (e.g. a {@link LinkageError} from
	 *        loading the native library), may be null
	 */
	public Fido2Exception(final String message, final Throwable cause) {
		super(message, cause);
	}
}
