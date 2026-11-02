package de.soderer.fido2;

/**
 * Kind of user check the token performs for a FIDO2 operation.
 *
 * IMPORTANT for hmac-secret: the token derives a different secret for the
 * same credential and salt depending on whether user verification took
 * place (CTAP2 "CredRandomWithUV" / "CredRandomWithoutUV"). Data encrypted
 * in one mode can only be decrypted in the same mode, so callers must
 * store the mode together with the credential. The library checks the user
 * verification flag reported by the token after every assertion and throws
 * a {@link Fido2VerificationModeException} if it does not match the
 * requested mode, so a secret is never returned for the wrong mode.
 */
public enum Fido2VerificationMode {
	/**
	 * User presence only (UP): touching the token is sufficient, no PIN is
	 * sent. Not possible for the hmac-secret via the Windows WebAuthn API
	 * (Windows without administrator rights), since Windows always enforces
	 * user verification there, and not with tokens enforcing user
	 * verification themselves (e.g. "alwaysUv", fingerprint tokens). See
	 * {@link Fido2Utilities#isUserPresenceOnlySupported(Fido2Token)}.
	 * Creating a credential may still require the PIN, if the token has one
	 * set (CTAP 2.0 tokens demand it).
	 */
	USER_PRESENCE,

	/**
	 * User verification (UV): the token's PIN is always required (on Windows
	 * without administrator rights the Windows dialog asks for it). Fails if
	 * the token has no PIN set (with direct access; Windows asks to create
	 * one).
	 */
	USER_VERIFICATION
}
