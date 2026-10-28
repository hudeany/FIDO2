package de.soderer.fido2;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Operating system independent access to FIDO2 hardware tokens with the
 * hmac-secret extension (based on the native libfido2 library).
 *
 * Callers do not need to care about operating system specifics. These are
 * handled here internally, e.g.:
 * <ul>
 * <li>Windows: bundled DLLs are extracted and loaded; without administrator
 * rights the tokens are used via the Windows WebAuthn API (Windows shows its
 * own dialogs for selecting the key, touch and PIN), with administrator rights
 * they are accessed directly.</li>
 * <li>Windows WebAuthn API: no own touch prompts and PIN requests (the
 * Fido2Interaction callbacks are not called), no discoverable credentials, no
 * user verification (so the hmac-secret is the same as with direct access),
 * the matching credential of several candidates is determined in a single
 * step (otherwise Windows would show an error dialog per non-matching one).</li>
 * <li>Linux/macOS: direct HID access via the system libfido2.</li>
 * </ul>
 *
 * All token operations are serialized (libfido2 device handles are not
 * thread-safe), so they may be called from any thread. Token operations block
 * until the user has touched the token, so do not call them on a GUI thread.
 *
 * Typical usage:
 * <pre>
 * final Fido2Availability availability = Fido2Utilities.checkAvailability();
 * if (!availability.isReady()) { ... }
 *
 * final Fido2Token token = Fido2Utilities.findToken();
 * final byte[] credentialId = Fido2Utilities.createCredential(token, "MyApp", "user", interaction);
 * final byte[] salt = Fido2Utilities.generateSalt();
 * final byte[] secret = Fido2Utilities.getHmacSecret(token, "MyApp", credentialId, salt, interaction);
 * </pre>
 */
public final class Fido2Utilities {
	/** Length of the salt for the hmac-secret extension */
	public static final int HMAC_SALT_LENGTH = 32;

	/** Maximum number of devices to probe */
	private static final int MAX_DEVICES = 16;

	private static final ReentrantLock LOCK = new ReentrantLock(true);

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	/**
	 * Cached failure of loading the native library: after a failed static
	 * initialization of Fido2Native, the JVM only reports a
	 * NoClassDefFoundError without the original cause.
	 */
	private static Fido2Availability libraryLoadFailure = null;

	private Fido2Utilities() {
		// Utility class
	}

	/**
	 * Loads the native library (if not done yet) and checks whether FIDO2
	 * tokens can be used at all. Never throws an exception, so it is suitable
	 * for a startup check.
	 */
	public static Fido2Availability checkAvailability() {
		LOCK.lock();
		try {
			if (libraryLoadFailure != null) {
				return libraryLoadFailure;
			}

			try {
				LibFido2.ensureInitialized();
			} catch (final LinkageError e) {
				libraryLoadFailure = createLibraryLoadFailure(e);
				return libraryLoadFailure;
			}

			if (Fido2WindowsSupport.isWindows() && !Fido2WindowsSupport.isRunningAsAdministrator() && !LibFido2.isWindowsWebAuthnAvailable()) {
				// Windows before 10 1903: no WebAuthn API, direct HID access needs administrator rights
				return new Fido2Availability(Fido2Availability.State.NO_TOKEN_ACCESS, "Direct access to FIDO2 tokens requires administrator rights on this Windows version");
			}

			return new Fido2Availability(Fido2Availability.State.READY, null);
		} finally {
			LOCK.unlock();
		}
	}

	private static Fido2Availability createLibraryLoadFailure(final LinkageError error) {
		// Native.load() in the static field initializer of Fido2Native is wrapped in an ExceptionInInitializerError
		Throwable cause = error;
		while (cause instanceof ExceptionInInitializerError && cause.getCause() != null) {
			cause = cause.getCause();
		}
		final String detail = cause.getMessage() != null ? cause.getMessage() : cause.toString();
		if (cause instanceof UnsatisfiedLinkError) {
			return new Fido2Availability(Fido2Availability.State.LIBRARY_NOT_FOUND, detail);
		} else {
			return new Fido2Availability(Fido2Availability.State.LIBRARY_LOAD_ERROR, detail);
		}
	}

	/**
	 * Lists the usable FIDO2 tokens.
	 *
	 * On Windows without administrator rights this is a single entry for the
	 * Windows WebAuthn API, where the user selects the key in the Windows
	 * dialog (with includeDetails, its details list the keys detected by
	 * Windows).
	 *
	 * @param includeDetails also collect additional display information
	 *        (Fido2Token.getDetails()), which may take about a second
	 * @throws Fido2Exception if the native library is not available or the
	 *         device enumeration failed
	 */
	public static List<Fido2Token> listTokens(final boolean includeDetails) {
		LOCK.lock();
		try {
			ensureLibraryAvailable();

			final List<Fido2Token> directTokens = new ArrayList<>();
			boolean windowsWebAuthnAvailable = false;
			for (final LibFido2.DeviceEntry device : LibFido2.listDevices(MAX_DEVICES)) {
				if (LibFido2.WINDOWS_WEBAUTHN_PATH.equals(device.path)) {
					windowsWebAuthnAvailable = true;
				} else {
					directTokens.add(new Fido2Token(device.path, device.getDisplayName(), null, false));
				}
			}

			if (windowsWebAuthnAvailable && (directTokens.isEmpty() || !Fido2WindowsSupport.isRunningAsAdministrator())) {
				// Without administrator rights Windows denies opening the tokens directly, so they are
				// only usable via the Windows WebAuthn API (like in browsers)
				final List<Fido2Token> result = new ArrayList<>();
				result.add(new Fido2Token(LibFido2.WINDOWS_WEBAUTHN_PATH, "Windows WebAuthn (security key selected in Windows dialog)",
						includeDetails ? Fido2WindowsSupport.listSecurityKeyDescriptions() : null, true));
				return result;
			} else {
				return directTokens;
			}
		} finally {
			LOCK.unlock();
		}
	}

	/**
	 * Returns the first usable FIDO2 token.
	 *
	 * @throws Fido2Exception if no token was found (with an operating system
	 *         specific hint in its message)
	 */
	public static Fido2Token findToken() {
		final List<Fido2Token> tokens = listTokens(false);
		if (tokens.isEmpty()) {
			throw new Fido2Exception(buildNoTokenFoundMessage());
		}
		return tokens.get(0);
	}

	private static String buildNoTokenFoundMessage() {
		final String baseMessage = "No FIDO2 USB token found. Please make sure the token is plugged in.";
		if (!Fido2WindowsSupport.isWindows()) {
			return baseMessage;
		} else if (!Fido2WindowsSupport.isRunningAsAdministrator()) {
			// The Windows WebAuthn API would have been listed, if available (Windows 10 1903 or newer)
			return baseMessage + " On this Windows version the Windows WebAuthn API is not available, so direct USB/HID access "
					+ "to a FIDO2 token requires this application to run with administrator rights. Please update Windows "
					+ "or restart this application as Administrator and try again.";
		} else {
			return baseMessage + " This application is already running with administrator rights, so this is likely not "
					+ "a rights issue. Try a different USB port, check Device Manager for driver issues with the token, "
					+ "and make sure no other application (e.g. a browser) is currently accessing the token.";
		}
	}

	/**
	 * Creates a new credential with the hmac-secret extension on the token.
	 * Needs one touch (and the PIN, if the token has one set).
	 *
	 * @param relyingPartyId application identifier, the same value must be
	 *        used for getHmacSecret()
	 * @param userName user name stored with the credential
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @return the credential id, to be stored by the caller
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2Exception on any other error
	 */
	public static byte[] createCredential(final Fido2Token token, final String relyingPartyId, final String userName, final Fido2Interaction interaction) {
		Objects.requireNonNull(token, "token");
		Objects.requireNonNull(relyingPartyId, "relyingPartyId");
		Objects.requireNonNull(userName, "userName");

		LOCK.lock();
		try {
			ensureLibraryAvailable();
			return LibFido2.makeCredential(token.getId(), relyingPartyId, userName, nonNull(interaction));
		} finally {
			LOCK.unlock();
		}
	}

	/**
	 * Retrieves the hmac-secret of a credential for the given salt. The same
	 * token, credential and salt always give the same secret. Needs one touch.
	 *
	 * @param salt HMAC_SALT_LENGTH bytes, see generateSalt()
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @return the 32 byte hmac-secret
	 * @throws Fido2NoMatchingCredentialException if the credential does not belong to the token
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2Exception on any other error
	 */
	public static byte[] getHmacSecret(final Fido2Token token, final String relyingPartyId, final byte[] credentialId, final byte[] salt, final Fido2Interaction interaction) {
		final List<Fido2Credential> candidates = new ArrayList<>();
		candidates.add(new Fido2Credential(credentialId, salt, null));
		return getHmacSecret(token, relyingPartyId, candidates, interaction).getSecret();
	}

	/**
	 * Retrieves the hmac-secret for whichever of the candidate credentials
	 * belongs to the token (e.g. a file encrypted for several tokens).
	 *
	 * The strategy depends on the operating system access path: directly
	 * accessed tokens are tried credential by credential, with the Windows
	 * WebAuthn API the matching credential is determined first (one
	 * additional touch), since every non-matching attempt would show a
	 * Windows error dialog. Fido2Interaction.onCredentialAttempt() is called
	 * before each attempt.
	 *
	 * @throws Fido2NoMatchingCredentialException if no candidate belongs to the token
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2Exception on any other error
	 */
	public static Fido2HmacSecret getHmacSecret(final Fido2Token token, final String relyingPartyId, final List<Fido2Credential> candidates, final Fido2Interaction interaction) {
		Objects.requireNonNull(token, "token");
		Objects.requireNonNull(relyingPartyId, "relyingPartyId");
		if (candidates == null || candidates.isEmpty()) {
			throw new IllegalArgumentException("No candidate credentials given");
		}
		final Fido2Interaction checkedInteraction = nonNull(interaction);

		LOCK.lock();
		try {
			ensureLibraryAvailable();

			if (token.isSystemApi() && candidates.size() > 1) {
				final List<byte[]> credentialIds = new ArrayList<>();
				for (final Fido2Credential candidate : candidates) {
					credentialIds.add(candidate.getCredentialId());
				}
				final int matchingIndex = LibFido2.findMatchingCredentialIndex(token.getId(), relyingPartyId, credentialIds, checkedInteraction);
				final Fido2Credential candidate = candidates.get(matchingIndex);
				checkedInteraction.onCredentialAttempt(matchingIndex + 1, candidates.size());
				return new Fido2HmacSecret(matchingIndex, LibFido2.getHmacSecret(token.getId(), relyingPartyId, candidate.getCredentialId(), candidate.getSalt(), checkedInteraction, candidate.getTokenName()));
			}

			Fido2Exception lastError = null;
			for (int i = 0; i < candidates.size(); i++) {
				final Fido2Credential candidate = candidates.get(i);
				checkedInteraction.onCredentialAttempt(i + 1, candidates.size());
				try {
					return new Fido2HmacSecret(i, LibFido2.getHmacSecret(token.getId(), relyingPartyId, candidate.getCredentialId(), candidate.getSalt(), checkedInteraction, candidate.getTokenName()));
				} catch (final Fido2PinRequiredException e) {
					// Missing or wrong PIN is not a non-matching credential, trying further candidates would only ask again
					throw e;
				} catch (final Fido2Exception e) {
					// This credential does not belong to the token, try the next one
					lastError = e;
				}
			}
			if (lastError == null) {
				// Unreachable: candidates is not empty, so every loop pass either returned, threw or set lastError
				throw new Fido2NoMatchingCredentialException("Internal error: none of the " + candidates.size() + " candidate credentials could be checked against the connected token.");
			} else if (candidates.size() == 1) {
				throw lastError;
			} else {
				throw new Fido2NoMatchingCredentialException("The connected token does not match any of the " + candidates.size() + " authorized tokens: " + lastError.getMessage());
			}
		} finally {
			LOCK.unlock();
		}
	}

	/** Creates a random salt for the hmac-secret extension */
	public static byte[] generateSalt() {
		final byte[] salt = new byte[HMAC_SALT_LENGTH];
		SECURE_RANDOM.nextBytes(salt);
		return salt;
	}

	private static void ensureLibraryAvailable() {
		if (libraryLoadFailure != null) {
			throw new Fido2Exception("The native libfido2 library is not available: " + libraryLoadFailure.getDetail());
		}
		try {
			LibFido2.ensureInitialized();
		} catch (final LinkageError e) {
			libraryLoadFailure = createLibraryLoadFailure(e);
			throw new Fido2Exception("The native libfido2 library is not available: " + libraryLoadFailure.getDetail(), e);
		}
	}

	private static Fido2Interaction nonNull(final Fido2Interaction interaction) {
		return interaction != null ? interaction : Fido2Interaction.NONE;
	}
}
