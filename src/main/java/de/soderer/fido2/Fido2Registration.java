package de.soderer.fido2;

/**
 * Result of {@link Fido2Utilities#register(Fido2Token, String, String, Fido2Interaction, Fido2VerificationMode)}:
 * a new signature credential on a FIDO2 token.
 *
 * The caller stores both values (neither is secret): the credential id to
 * address the credential in later
 * {@link Fido2Utilities#authenticate(Fido2Token, String, java.util.List, byte[], Fido2Interaction, Fido2VerificationMode) authenticate()}
 * calls, the public key to check the signatures with
 * {@link Fido2Utilities#verifyAssertion(Fido2Assertion, byte[], String, byte[], Fido2VerificationMode) verifyAssertion()}.
 */
public final class Fido2Registration {
	private final byte[] credentialId;
	private final byte[] publicKey;

	/**
	 * Creates a new registration result.
	 *
	 * @param credentialId the credential id
	 * @param publicKey the public key, X.509 SubjectPublicKeyInfo (DER)
	 */
	Fido2Registration(final byte[] credentialId, final byte[] publicKey) {
		this.credentialId = credentialId.clone();
		this.publicKey = publicKey.clone();
	}

	/**
	 * Returns the id of the created credential.
	 *
	 * @return a copy of the credential id
	 */
	public byte[] getCredentialId() {
		return credentialId.clone();
	}

	/**
	 * Returns the public key of the created credential (ECDSA P-256, COSE
	 * algorithm ES256), encoded as X.509 SubjectPublicKeyInfo (DER). This is
	 * the standard Java encoding: {@code KeyFactory.getInstance("EC")
	 * .generatePublic(new X509EncodedKeySpec(publicKey))} restores it, and
	 * Base64 of it between "-----BEGIN PUBLIC KEY-----" lines is a PEM file.
	 *
	 * @return a copy of the encoded public key
	 */
	public byte[] getPublicKey() {
		return publicKey.clone();
	}
}
