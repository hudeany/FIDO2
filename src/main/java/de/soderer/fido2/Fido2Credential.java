package de.soderer.fido2;

/**
 * A stored FIDO2 credential with the salt for its hmac-secret, as candidate
 * for
 * {@link Fido2Utilities#getHmacSecret(Fido2Token, String, java.util.List, Fido2Interaction)}.
 *
 * Instances are immutable: the byte arrays are copied on construction and
 * on every getter call.
 */
public final class Fido2Credential {
	private final byte[] credentialId;
	private final byte[] salt;
	private final String tokenName;

	/**
	 * Creates a new candidate credential.
	 *
	 * @param credentialId credential id, as returned by
	 *        {@link Fido2Utilities#createCredential(Fido2Token, String, String, Fido2Interaction)}
	 * @param salt {@link Fido2Utilities#HMAC_SALT_LENGTH} byte salt for the
	 *        hmac-secret extension
	 * @param tokenName optional name of the token the credential was created
	 *        on, only used for more helpful error messages; may be null
	 * @throws IllegalArgumentException if the credential id is null or
	 *         empty, or the salt is null or does not have exactly
	 *         {@link Fido2Utilities#HMAC_SALT_LENGTH} bytes
	 */
	public Fido2Credential(final byte[] credentialId, final byte[] salt, final String tokenName) {
		if (credentialId == null || credentialId.length == 0) {
			throw new IllegalArgumentException("Credential id is missing");
		}
		if (salt == null || salt.length != Fido2Utilities.HMAC_SALT_LENGTH) {
			throw new IllegalArgumentException("Salt must be exactly " + Fido2Utilities.HMAC_SALT_LENGTH + " bytes long");
		}
		this.credentialId = credentialId.clone();
		this.salt = salt.clone();
		this.tokenName = tokenName;
	}

	/**
	 * Returns the credential id.
	 *
	 * @return a copy of the credential id
	 */
	public byte[] getCredentialId() {
		return credentialId.clone();
	}

	/**
	 * Returns the salt for the hmac-secret extension.
	 *
	 * @return a copy of the {@link Fido2Utilities#HMAC_SALT_LENGTH} byte salt
	 */
	public byte[] getSalt() {
		return salt.clone();
	}

	/**
	 * Returns the name of the token the credential was created on.
	 *
	 * @return the token name, or null if unknown
	 */
	public String getTokenName() {
		return tokenName;
	}
}
