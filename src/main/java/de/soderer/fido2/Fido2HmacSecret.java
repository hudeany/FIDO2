package de.soderer.fido2;

/**
 * Result of
 * {@link Fido2Utilities#getHmacSecret(Fido2Token, String, java.util.List, Fido2Interaction)}:
 * the hmac-secret and which of the candidate credentials produced it.
 */
public final class Fido2HmacSecret {
	private final int credentialIndex;
	private final byte[] secret;

	/**
	 * Creates a new result. The secret array is stored without copying.
	 *
	 * @param credentialIndex 0-based index of the matching credential in the
	 *        candidate list
	 * @param secret the hmac-secret returned by the token
	 */
	Fido2HmacSecret(final int credentialIndex, final byte[] secret) {
		this.credentialIndex = credentialIndex;
		this.secret = secret;
	}

	/**
	 * Returns which of the candidate credentials belongs to the token.
	 *
	 * @return 0-based index of the matching credential in the candidate list
	 */
	public int getCredentialIndex() {
		return credentialIndex;
	}

	/**
	 * Returns the hmac-secret. The array is not copied, so the caller may
	 * wipe it (e.g. with {@link java.util.Arrays#fill(byte[], byte)}) after
	 * use.
	 *
	 * @return the 32 byte hmac-secret
	 */
	public byte[] getSecret() {
		return secret;
	}
}
