package de.soderer.fido2;

/**
 * Thrown if a FIDO2 operation cannot be performed in the requested
 * {@link Fido2VerificationMode}, or if the token did not perform the
 * operation in that mode.
 *
 * Examples:
 * <ul>
 * <li>{@link Fido2VerificationMode#USER_PRESENCE} was requested via the
 * Windows WebAuthn API, which always enforces user verification for the
 * hmac-secret extension</li>
 * <li>{@link Fido2VerificationMode#USER_PRESENCE} was requested, but the
 * token enforces user verification (e.g. "alwaysUv" or a fingerprint
 * token)</li>
 * <li>the user verification flag reported by the token does not match the
 * requested mode</li>
 * </ul>
 *
 * Since the token derives a different hmac-secret with and without user
 * verification, a secret obtained in the wrong mode would not match the
 * mode stored by the caller. This exception prevents that.
 *
 * Unlike other {@link Fido2Exception}s it does not mean that a credential
 * does not belong to the token, so trying further candidate credentials is
 * pointless.
 */
public class Fido2VerificationModeException extends Fido2Exception {
	private static final long serialVersionUID = 6283094561377290213L;

	/**
	 * Creates a new exception.
	 *
	 * @param message the detail message
	 */
	public Fido2VerificationModeException(final String message) {
		super(message);
	}
}
