package de.soderer.fido2;

/**
 * Kind of user check the token performs for a FIDO2 operation.
 *
 * IMPORTANT for hmac-secret: the token derives a different secret for the
 * same credential and salt depending on whether user verification took
 * place (CTAP2 "CredRandomWithUV" / "CredRandomWithoutUV"). Data encrypted
 * in one mode can only be decrypted in the same mode, so callers must
 * store the mode together with the credential.
 */
public enum Fido2VerificationMode {
	/**
	 * User presence only (UP): touching the token is sufficient, no PIN is
	 * sent. If the token itself enforces user verification (e.g. "alwaysUv"
	 * or CTAP 2.0 credential creation with a PIN set), the PIN is requested
	 * as a fallback.
	 */
	USER_PRESENCE,

	/**
	 * User verification (UV): the token's PIN is always required (on Windows
	 * the WebAuthn dialog asks for it). Fails if the token has no PIN set.
	 */
	USER_VERIFICATION
}
