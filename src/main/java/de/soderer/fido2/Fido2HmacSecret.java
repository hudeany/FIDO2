package de.soderer.fido2;

/**
 * Result of Fido2Utilities.getHmacSecret(Fido2Token, String, List, Fido2Interaction):
 * the hmac-secret and which of the candidate credentials produced it.
 */
public final class Fido2HmacSecret {
	private final int credentialIndex;
	private final byte[] secret;

	Fido2HmacSecret(final int credentialIndex, final byte[] secret) {
		this.credentialIndex = credentialIndex;
		this.secret = secret;
	}

	/** 0-based index of the matching credential in the candidate list */
	public int getCredentialIndex() {
		return credentialIndex;
	}

	/** The 32 byte hmac-secret (not copied, caller may wipe it after use) */
	public byte[] getSecret() {
		return secret;
	}
}
