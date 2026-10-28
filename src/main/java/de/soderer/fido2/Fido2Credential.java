package de.soderer.fido2;

/**
 * A stored FIDO2 credential with the salt for its hmac-secret, as candidate
 * for Fido2Utilities.getHmacSecret(Fido2Token, String, List, Fido2Interaction).
 */
public final class Fido2Credential {
	private final byte[] credentialId;
	private final byte[] salt;
	private final String tokenName;

	/**
	 * @param credentialId credential id, as returned by Fido2Utilities.createCredential()
	 * @param salt 32 byte salt for the hmac-secret extension
	 * @param tokenName optional name of the token the credential was created
	 *        on, only used for more helpful error messages; may be null
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

	public byte[] getCredentialId() {
		return credentialId.clone();
	}

	public byte[] getSalt() {
		return salt.clone();
	}

	public String getTokenName() {
		return tokenName;
	}
}
