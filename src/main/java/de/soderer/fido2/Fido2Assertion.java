package de.soderer.fido2;

/**
 * A signature of a FIDO2 token over a challenge, as returned by
 * {@link Fido2Utilities#authenticate(Fido2Token, String, java.util.List, byte[], Fido2Interaction, Fido2VerificationMode) authenticate()}
 * and checked by
 * {@link Fido2Utilities#verifyAssertion(Fido2Assertion, byte[], String, byte[], Fido2VerificationMode) verifyAssertion()}.
 *
 * The token signs the authenticator data followed by the SHA-256 hash of
 * the client data (a WebAuthn JSON structure containing the challenge).
 * All four byte arrays are needed for the verification; they can be
 * transferred to another system (e.g. a server) and turned into an
 * assertion there again with the public constructor.
 */
public final class Fido2Assertion {
	/** Minimum length of authenticator data: rpIdHash (32), flags (1), signature counter (4) */
	static final int MIN_AUTHENTICATOR_DATA_LENGTH = 37;

	private static final int FLAGS_OFFSET = 32;
	private static final int SIGNATURE_COUNTER_OFFSET = 33;

	private final int credentialIndex;
	private final byte[] credentialId;
	private final byte[] clientData;
	private final byte[] authenticatorData;
	private final byte[] signature;

	/**
	 * Creates an assertion from transferred data, e.g. on a server checking
	 * a signature created on another system. The credential index is not
	 * known then ({@link #getCredentialIndex()} returns -1).
	 *
	 * @param credentialId id of the credential that created the signature
	 * @param clientData the client data JSON (UTF-8)
	 * @param authenticatorData the raw authenticator data
	 * @param signature the DER encoded ECDSA signature
	 * @throws IllegalArgumentException if a value is null or empty, or the
	 *         authenticator data is shorter than 37 bytes
	 */
	public Fido2Assertion(final byte[] credentialId, final byte[] clientData, final byte[] authenticatorData, final byte[] signature) {
		this(-1, credentialId, clientData, authenticatorData, signature);
	}

	/**
	 * Creates an assertion with the index of the used credential.
	 *
	 * @param credentialIndex index of the used credential in the list given
	 *        to authenticate(), -1 if unknown
	 * @param credentialId id of the credential that created the signature
	 * @param clientData the client data JSON (UTF-8)
	 * @param authenticatorData the raw authenticator data
	 * @param signature the DER encoded ECDSA signature
	 * @throws IllegalArgumentException if a value is null or empty, or the
	 *         authenticator data is shorter than 37 bytes
	 */
	Fido2Assertion(final int credentialIndex, final byte[] credentialId, final byte[] clientData, final byte[] authenticatorData, final byte[] signature) {
		if (credentialId == null || credentialId.length == 0) {
			throw new IllegalArgumentException("Credential id is missing");
		}
		if (clientData == null || clientData.length == 0) {
			throw new IllegalArgumentException("Client data is missing");
		}
		if (authenticatorData == null || authenticatorData.length < MIN_AUTHENTICATOR_DATA_LENGTH) {
			throw new IllegalArgumentException("Authenticator data must be at least " + MIN_AUTHENTICATOR_DATA_LENGTH + " bytes long");
		}
		if (signature == null || signature.length == 0) {
			throw new IllegalArgumentException("Signature is missing");
		}
		this.credentialIndex = credentialIndex;
		this.credentialId = credentialId.clone();
		this.clientData = clientData.clone();
		this.authenticatorData = authenticatorData.clone();
		this.signature = signature.clone();
	}

	/**
	 * Returns the index of the used credential in the list given to
	 * authenticate(), so the caller knows which stored public key to use.
	 *
	 * @return the 0-based index, or -1 if unknown (assertion created from
	 *         transferred data)
	 */
	public int getCredentialIndex() {
		return credentialIndex;
	}

	/**
	 * Returns the id of the credential that created the signature.
	 *
	 * @return a copy of the credential id
	 */
	public byte[] getCredentialId() {
		return credentialId.clone();
	}

	/**
	 * Returns the client data JSON (UTF-8) whose SHA-256 hash was signed. It
	 * contains the challenge (base64url) and the relying party id as origin.
	 *
	 * @return a copy of the client data
	 */
	public byte[] getClientData() {
		return clientData.clone();
	}

	/**
	 * Returns the raw authenticator data: SHA-256 hash of the relying party
	 * id (32 bytes), flags (1 byte), signature counter (4 bytes, big-endian),
	 * possibly followed by extension data.
	 *
	 * @return a copy of the authenticator data
	 */
	public byte[] getAuthenticatorData() {
		return authenticatorData.clone();
	}

	/**
	 * Returns the signature (ECDSA P-256 with SHA-256, ASN.1 DER encoded)
	 * over the authenticator data followed by the SHA-256 hash of the client
	 * data.
	 *
	 * @return a copy of the signature
	 */
	public byte[] getSignature() {
		return signature.clone();
	}

	/**
	 * Returns the "user present" flag of the authenticator data: the user
	 * touched the token.
	 *
	 * @return true if the user was present
	 */
	public boolean isUserPresent() {
		return (authenticatorData[FLAGS_OFFSET] & LibFido2.AUTHDATA_FLAG_USER_PRESENT) != 0;
	}

	/**
	 * Returns the "user verified" flag of the authenticator data: the token
	 * verified the user (PIN or fingerprint).
	 *
	 * @return true if the user was verified
	 */
	public boolean isUserVerified() {
		return (authenticatorData[FLAGS_OFFSET] & LibFido2.AUTHDATA_FLAG_USER_VERIFIED) != 0;
	}

	/**
	 * Returns the signature counter of the authenticator data. Tokens
	 * increase it with every signature (some always report 0). A caller can
	 * detect a cloned token if the counter does not increase compared to
	 * the last stored value; this check is not done by verifyAssertion().
	 *
	 * @return the signature counter (unsigned 32 bit)
	 */
	public long getSignatureCounter() {
		long counter = 0;
		for (int i = 0; i < 4; i++) {
			counter = (counter << 8) | (authenticatorData[SIGNATURE_COUNTER_OFFSET + i] & 0xFF);
		}
		return counter;
	}
}
