package de.soderer.fido2;

/**
 * Thrown when a FIDO2 token operation (credential creation or assertion)
 * failed because the token requires its PIN to be supplied, but either no
 * PIN was given at all, or the PIN that was given was rejected by the
 * token.
 *
 * This is a distinct subclass of {@link Fido2Exception} (rather than just a
 * string comparison on the generic error message) so that callers can
 * specifically react to it, e.g. by showing a PIN entry dialog and retrying
 * the operation once with the entered PIN.
 */
public class Fido2PinRequiredException extends Fido2Exception {
	private static final long serialVersionUID = 1L;

	/** True if a PIN was already supplied for the failed attempt (i.e. the supplied PIN was wrong), false if none was supplied at all. */
	private final boolean pinWasAlreadyAttempted;

	/**
	 * Creates a new exception.
	 *
	 * @param message description of the error
	 * @param pinWasAlreadyAttempted true if a PIN was supplied and rejected
	 *        by the token, false if no PIN was supplied at all
	 */
	public Fido2PinRequiredException(final String message, final boolean pinWasAlreadyAttempted) {
		super(message);
		this.pinWasAlreadyAttempted = pinWasAlreadyAttempted;
	}

	/**
	 * Tells whether the failed attempt already used a PIN. Callers can use
	 * this to distinguish "please enter the PIN" from "the PIN was wrong".
	 *
	 * @return true if a PIN was supplied and rejected by the token, false if
	 *         no PIN was supplied at all
	 */
	public boolean isPinWasAlreadyAttempted() {
		return pinWasAlreadyAttempted;
	}
}
