package de.soderer.fido2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * Fido2Interaction callbacks are not called), no discoverable credentials,
 * the matching credential of several candidates is determined in a single
 * step (otherwise Windows would show an error dialog per non-matching one).
 * Windows always enforces user verification for the hmac-secret extension,
 * so only {@link Fido2VerificationMode#USER_VERIFICATION} is supported there
 * (see {@link #isUserPresenceOnlySupported(Fido2Token)}).</li>
 * <li>Linux/macOS: direct HID access via the system libfido2.</li>
 * </ul>
 *
 * Verification mode: with {@link Fido2VerificationMode#USER_PRESENCE}
 * (default) touching the token is sufficient for retrieving the hmac-secret,
 * with {@link Fido2VerificationMode#USER_VERIFICATION} the token's PIN is
 * always required. The token derives different hmac-secrets in both modes, so
 * the caller must store the mode with the credential and use the same mode
 * for every later call. After every assertion the user verification flag
 * reported by the token is checked against the requested mode, so a secret
 * is never returned for a different mode than requested
 * ({@link Fido2VerificationModeException} otherwise).
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
 *
 * Besides the hmac-secret (a stable secret key), tokens can be used for
 * signatures like a WebAuthn login: {@link #register(Fido2Token, String, String, Fido2Interaction, Fido2VerificationMode) register()}
 * creates a credential and returns its public key,
 * {@link #authenticate(Fido2Token, String, List, byte[], Fido2Interaction, Fido2VerificationMode) authenticate()}
 * lets the token sign a challenge, and
 * {@link #verifyAssertion(Fido2Assertion, byte[], String, byte[], Fido2VerificationMode) verifyAssertion()}
 * checks the signature in pure Java (no token or native library needed).
 * Unlike the hmac-secret, signatures with user presence only also work via
 * the Windows WebAuthn API. A credential for both purposes (hmac-secret and
 * signatures) is created by
 * {@link #createCredentialWithPublicKey(Fido2Token, String, String, Fido2Interaction, Fido2VerificationMode) createCredentialWithPublicKey()}.
 */
public final class Fido2Utilities {
	/** Length of the salt for the hmac-secret extension */
	public static final int HMAC_SALT_LENGTH = 32;

	/** Length of the challenges created by {@link #generateChallenge()} */
	public static final int CHALLENGE_LENGTH = 32;

	/** Minimum length of a challenge for {@link #authenticate(Fido2Token, String, List, byte[], Fido2Interaction, Fido2VerificationMode)} */
	public static final int MIN_CHALLENGE_LENGTH = 16;

	/**
	 * DER prefix of an X.509 SubjectPublicKeyInfo for an uncompressed P-256
	 * point: SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 },
	 * BIT STRING { 0x04 || x || y } }. Followed by the 64 bytes x || y.
	 */
	private static final byte[] ES256_SUBJECT_PUBLIC_KEY_INFO_PREFIX = {
			0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01,
			0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07,
			0x03, 0x42, 0x00, 0x04 };

	/** The client data type of an assertion (WebAuthn) */
	private static final String CLIENT_DATA_TYPE_GET = "webauthn.get";

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
	 *
	 * A failure to load the native library is cached, so later calls return
	 * the same result without retrying.
	 *
	 * @return the availability, never null
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

	/**
	 * Maps an error of loading the native library to an availability result:
	 * an UnsatisfiedLinkError (library not found) becomes
	 * {@link Fido2Availability.State#LIBRARY_NOT_FOUND}, everything else
	 * {@link Fido2Availability.State#LIBRARY_LOAD_ERROR}.
	 */
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
	 *        ({@link Fido2Token#getDetails()}), which may take about a second
	 * @return the usable tokens, empty if none was found
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
	 * @return the first entry of {@link #listTokens(boolean)}
	 * @throws Fido2Exception if no token was found (with an operating system
	 *         specific hint in its message), or if the native library is not
	 *         available
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
	 * @param token the token to create the credential on
	 * @param relyingPartyId application identifier, the same value must be
	 *        used for getHmacSecret()
	 * @param userName user name stored with the credential
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @return the credential id, to be stored by the caller
	 * @throws NullPointerException if token, relyingPartyId or userName is
	 *         null
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2Exception on any other error
	 */
	public static byte[] createCredential(final Fido2Token token, final String relyingPartyId, final String userName, final Fido2Interaction interaction) {
		return createCredential(token, relyingPartyId, userName, interaction, Fido2VerificationMode.USER_PRESENCE);
	}

	/**
	 * Creates a new credential with the hmac-secret extension on the token.
	 * Needs one touch, and the PIN if the token has one set or user
	 * verification is requested.
	 *
	 * The verification mode only decides whether the PIN is required for
	 * the creation itself. The credential supports both modes for
	 * {@link #getHmacSecret(Fido2Token, String, byte[], byte[], Fido2Interaction, Fido2VerificationMode)}.
	 *
	 * @param token the token to create the credential on
	 * @param relyingPartyId application identifier, the same value must be
	 *        used for getHmacSecret()
	 * @param userName user name stored with the credential
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @param verificationMode USER_PRESENCE or USER_VERIFICATION
	 * @return the credential id, to be stored by the caller
	 * @throws NullPointerException if token, relyingPartyId, userName or
	 *         verificationMode is null
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2Exception on any other error, e.g. user verification
	 *         requested for a token without PIN
	 */
	public static byte[] createCredential(final Fido2Token token, final String relyingPartyId, final String userName, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode) {
		Objects.requireNonNull(token, "token");
		Objects.requireNonNull(relyingPartyId, "relyingPartyId");
		Objects.requireNonNull(userName, "userName");
		Objects.requireNonNull(verificationMode, "verificationMode");

		LOCK.lock();
		try {
			ensureLibraryAvailable();
			return LibFido2.makeCredential(token.getId(), relyingPartyId, userName, nonNull(interaction), verificationMode);
		} finally {
			LOCK.unlock();
		}
	}

	/**
	 * Creates a new credential with the hmac-secret extension on the token,
	 * like {@link #createCredential(Fido2Token, String, String, Fido2Interaction, Fido2VerificationMode)},
	 * but additionally returns its public key (ECDSA P-256). Needs one touch,
	 * and the PIN if the token has one set or user verification is requested.
	 *
	 * The public key is only available at creation time. With it, the same
	 * credential can be used for both the hmac-secret and signatures:
	 * {@link #authenticate(Fido2Token, String, List, byte[], Fido2Interaction, Fido2VerificationMode)}
	 * and {@link #verifyAssertion(Fido2Assertion, byte[], String, byte[], Fido2VerificationMode)}
	 * accept its credential id and public key like those of
	 * {@link #register(Fido2Token, String, String, Fido2Interaction, Fido2VerificationMode)}.
	 *
	 * @param token the token to create the credential on
	 * @param relyingPartyId application identifier, the same value must be
	 *        used for getHmacSecret(), authenticate() and verifyAssertion()
	 * @param userName user name stored with the credential
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @param verificationMode USER_PRESENCE or USER_VERIFICATION; only
	 *        decides whether the PIN is required for the creation itself
	 * @return the credential id and public key (X.509 SubjectPublicKeyInfo,
	 *         DER), to be stored by the caller
	 * @throws NullPointerException if token, relyingPartyId, userName or
	 *         verificationMode is null
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2VerificationModeException if user verification is
	 *         requested for a token without PIN
	 * @throws Fido2Exception on any other error
	 */
	public static Fido2Registration createCredentialWithPublicKey(final Fido2Token token, final String relyingPartyId, final String userName, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode) {
		Objects.requireNonNull(token, "token");
		Objects.requireNonNull(relyingPartyId, "relyingPartyId");
		Objects.requireNonNull(userName, "userName");
		Objects.requireNonNull(verificationMode, "verificationMode");

		LOCK.lock();
		try {
			ensureLibraryAvailable();
			// Last parameter: create the credential with the hmac-secret extension
			final LibFido2.CreatedCredential createdCredential = LibFido2.createCredential(token.getId(), relyingPartyId, userName, nonNull(interaction), verificationMode, true);
			return new Fido2Registration(createdCredential.credentialId(), encodeEs256PublicKey(createdCredential.rawPublicKey()));
		} finally {
			LOCK.unlock();
		}
	}

	/**
	 * Retrieves the hmac-secret of a credential for the given salt. The same
	 * token, credential and salt always give the same secret. Needs one touch.
	 *
	 * @param token the token the credential was created on
	 * @param relyingPartyId application identifier, the same value as used
	 *        for {@link #createCredential(Fido2Token, String, String, Fido2Interaction)}
	 * @param credentialId credential id, as returned by
	 *        {@link #createCredential(Fido2Token, String, String, Fido2Interaction)}
	 * @param salt {@link #HMAC_SALT_LENGTH} bytes, see {@link #generateSalt()}
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @return the 32 byte hmac-secret
	 * @throws NullPointerException if token or relyingPartyId is null
	 * @throws IllegalArgumentException if the credential id is null or empty,
	 *         or the salt does not have {@link #HMAC_SALT_LENGTH} bytes
	 * @throws Fido2NoMatchingCredentialException if the credential does not belong to the token
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2Exception on any other error
	 */
	public static byte[] getHmacSecret(final Fido2Token token, final String relyingPartyId, final byte[] credentialId, final byte[] salt, final Fido2Interaction interaction) {
		return getHmacSecret(token, relyingPartyId, credentialId, salt, interaction, Fido2VerificationMode.USER_PRESENCE);
	}

	/**
	 * Retrieves the hmac-secret of a credential for the given salt. The same
	 * token, credential, salt and verification mode always give the same
	 * secret. Needs one touch, with user verification also the PIN.
	 *
	 * @param token the token the credential was created on
	 * @param relyingPartyId application identifier, the same value as used
	 *        for {@link #createCredential(Fido2Token, String, String, Fido2Interaction, Fido2VerificationMode)}
	 * @param credentialId credential id, as returned by
	 *        {@link #createCredential(Fido2Token, String, String, Fido2Interaction, Fido2VerificationMode)}
	 * @param salt {@link #HMAC_SALT_LENGTH} bytes, see {@link #generateSalt()}
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @param verificationMode USER_PRESENCE or USER_VERIFICATION, must be
	 *        the same as used for retrieving the secret the first time
	 * @return the 32 byte hmac-secret
	 * @throws NullPointerException if token, relyingPartyId or
	 *         verificationMode is null
	 * @throws IllegalArgumentException if the credential id is null or empty,
	 *         or the salt does not have {@link #HMAC_SALT_LENGTH} bytes
	 * @throws Fido2NoMatchingCredentialException if the credential does not belong to the token
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2VerificationModeException if the secret cannot be
	 *         retrieved in the requested mode with this token, see
	 *         {@link #isUserPresenceOnlySupported(Fido2Token)}
	 * @throws Fido2Exception on any other error
	 */
	public static byte[] getHmacSecret(final Fido2Token token, final String relyingPartyId, final byte[] credentialId, final byte[] salt, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode) {
		final List<Fido2Credential> candidates = new ArrayList<>();
		candidates.add(new Fido2Credential(credentialId, salt, null));
		return getHmacSecret(token, relyingPartyId, candidates, interaction, verificationMode).getSecret();
	}

	/**
	 * Retrieves the hmac-secret for whichever of the candidate credentials
	 * belongs to the token (e.g. a file encrypted for several tokens).
	 *
	 * The strategy depends on the operating system access path: directly
	 * accessed tokens are tried credential by credential, with the Windows
	 * WebAuthn API the matching credential is determined first (one
	 * additional touch), since every non-matching attempt would show a
	 * Windows error dialog. {@link Fido2Interaction#onCredentialAttempt(int, int)}
	 * is called before each attempt.
	 *
	 * @param token the connected token
	 * @param relyingPartyId application identifier, the same value as used
	 *        for {@link #createCredential(Fido2Token, String, String, Fido2Interaction)}
	 * @param candidates the candidate credentials (with their salts), at
	 *        least one
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @return the hmac-secret and the index of the matching candidate
	 * @throws NullPointerException if token or relyingPartyId is null
	 * @throws IllegalArgumentException if candidates is null or empty
	 * @throws Fido2NoMatchingCredentialException if no candidate belongs to the token
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2Exception on any other error
	 */
	public static Fido2HmacSecret getHmacSecret(final Fido2Token token, final String relyingPartyId, final List<Fido2Credential> candidates, final Fido2Interaction interaction) {
		return getHmacSecret(token, relyingPartyId, candidates, interaction, Fido2VerificationMode.USER_PRESENCE);
	}

	/**
	 * Retrieves the hmac-secret for whichever of the candidate credentials
	 * belongs to the token (e.g. a file encrypted for several tokens).
	 *
	 * The strategy depends on the operating system access path and the
	 * verification mode: with the Windows WebAuthn API or with user
	 * verification, the matching credential is determined first (one
	 * additional touch, no PIN), since every non-matching attempt would show
	 * a Windows error dialog or ask for the PIN again. Otherwise the
	 * credentials are tried one by one.
	 * {@link Fido2Interaction#onCredentialAttempt(int, int)} is called before
	 * each attempt.
	 *
	 * @param token the connected token
	 * @param relyingPartyId application identifier, the same value as used
	 *        for {@link #createCredential(Fido2Token, String, String, Fido2Interaction, Fido2VerificationMode)}
	 * @param candidates the candidate credentials (with their salts), at
	 *        least one
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @param verificationMode USER_PRESENCE or USER_VERIFICATION, used for
	 *        all candidates; must be the same as used for retrieving the
	 *        secret the first time
	 * @return the hmac-secret and the index of the matching candidate
	 * @throws NullPointerException if token, relyingPartyId or
	 *         verificationMode is null
	 * @throws IllegalArgumentException if candidates is null or empty
	 * @throws Fido2NoMatchingCredentialException if no candidate belongs to the token
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2VerificationModeException if the secret cannot be
	 *         retrieved in the requested mode with this token, see
	 *         {@link #isUserPresenceOnlySupported(Fido2Token)}
	 * @throws Fido2Exception on any other error
	 */
	public static Fido2HmacSecret getHmacSecret(final Fido2Token token, final String relyingPartyId, final List<Fido2Credential> candidates, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode) {
		Objects.requireNonNull(token, "token");
		Objects.requireNonNull(relyingPartyId, "relyingPartyId");
		Objects.requireNonNull(verificationMode, "verificationMode");
		if (candidates == null || candidates.isEmpty()) {
			throw new IllegalArgumentException("No candidate credentials given");
		}
		final Fido2Interaction checkedInteraction = nonNull(interaction);
		if (verificationMode == Fido2VerificationMode.USER_PRESENCE && !isUserPresenceOnlySupported(token)) {
			// Checked before any token access, Windows would otherwise force the user to create or enter a PIN first
			throw new Fido2VerificationModeException("Retrieving the HMAC secret with user presence only (touch, no PIN) is not possible via the Windows WebAuthn API, "
					+ "since Windows always enforces user verification (PIN) for it. Run the application with administrator rights for direct token access, "
					+ "or use user verification.");
		}

		LOCK.lock();
		try {
			ensureLibraryAvailable();

			// Windows WebAuthn: every non-matching attempt would show a Windows error dialog.
			// User verification: every attempt would ask for the PIN again.
			// So determine the matching credential first (user presence only, no PIN).
			if (candidates.size() > 1 && (token.isSystemApi() || verificationMode == Fido2VerificationMode.USER_VERIFICATION)) {
				final List<byte[]> credentialIds = new ArrayList<>();
				for (final Fido2Credential candidate : candidates) {
					credentialIds.add(candidate.getCredentialId());
				}
				final int matchingIndex = LibFido2.findMatchingCredentialIndex(token.getId(), relyingPartyId, credentialIds, checkedInteraction);
				final Fido2Credential candidate = candidates.get(matchingIndex);
				checkedInteraction.onCredentialAttempt(matchingIndex + 1, candidates.size());
				return new Fido2HmacSecret(matchingIndex, LibFido2.getHmacSecret(token.getId(), relyingPartyId, candidate.getCredentialId(), candidate.getSalt(), checkedInteraction, candidate.getTokenName(), verificationMode));
			}

			Fido2Exception lastError = null;
			for (int i = 0; i < candidates.size(); i++) {
				final Fido2Credential candidate = candidates.get(i);
				checkedInteraction.onCredentialAttempt(i + 1, candidates.size());
				try {
					return new Fido2HmacSecret(i, LibFido2.getHmacSecret(token.getId(), relyingPartyId, candidate.getCredentialId(), candidate.getSalt(), checkedInteraction, candidate.getTokenName(), verificationMode));
				} catch (final Fido2PinRequiredException e) {
					// Missing or wrong PIN is not a non-matching credential, trying further candidates would only ask again
					throw e;
				} catch (final Fido2VerificationModeException e) {
					// The requested mode is not possible with this token, the same applies to all further candidates
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

	/**
	 * Checks whether the hmac-secret can be retrieved with
	 * {@link Fido2VerificationMode#USER_PRESENCE} (touch only, no PIN) from
	 * the given token. Not possible via the Windows WebAuthn API
	 * ({@link Fido2Token#isSystemApi()}), since Windows always enforces user
	 * verification for the hmac-secret extension. Requires no user
	 * interaction.
	 *
	 * @param token the token to check
	 * @return true if user presence only is possible, false if only user
	 *         verification is possible
	 * @throws NullPointerException if token is null
	 */
	public static boolean isUserPresenceOnlySupported(final Fido2Token token) {
		Objects.requireNonNull(token, "token");
		return !token.isSystemApi();
	}

	/**
	 * Checks whether the hmac-secret can be retrieved with
	 * {@link Fido2VerificationMode#USER_PRESENCE} (touch only, no PIN) on this
	 * system, without enumerating any token. Intended for presetting user
	 * interfaces: false on Windows without administrator rights, where tokens
	 * are only accessible via the Windows WebAuthn API. The definite check
	 * for a concrete token is {@link #isUserPresenceOnlySupported(Fido2Token)}.
	 *
	 * @return false if user presence only is not possible on this system
	 */
	public static boolean isUserPresenceOnlyAvailable() {
		return !(Fido2WindowsSupport.isWindows() && !Fido2WindowsSupport.isRunningAsAdministrator());
	}

	/**
	 * Creates a random salt for the hmac-secret extension, using a
	 * {@link SecureRandom}.
	 *
	 * @return a new array of {@link #HMAC_SALT_LENGTH} random bytes
	 */
	public static byte[] generateSalt() {
		final byte[] salt = new byte[HMAC_SALT_LENGTH];
		SECURE_RANDOM.nextBytes(salt);
		return salt;
	}

	/**
	 * Creates a random challenge for
	 * {@link #authenticate(Fido2Token, String, List, byte[], Fido2Interaction, Fido2VerificationMode)},
	 * using a {@link SecureRandom}. A challenge must be used only once.
	 *
	 * @return a new array of {@link #CHALLENGE_LENGTH} random bytes
	 */
	public static byte[] generateChallenge() {
		final byte[] challenge = new byte[CHALLENGE_LENGTH];
		SECURE_RANDOM.nextBytes(challenge);
		return challenge;
	}

	/**
	 * Creates a new signature credential (ECDSA P-256, without hmac-secret)
	 * on the token, like a WebAuthn registration. Needs one touch (and the
	 * PIN, if the token has one set or user verification is requested).
	 *
	 * Works via the Windows WebAuthn API with both verification modes.
	 *
	 * @param token the token to create the credential on
	 * @param relyingPartyId application identifier, the same value must be
	 *        used for authenticate() and verifyAssertion()
	 * @param userName user name stored with the credential
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @param verificationMode USER_PRESENCE or USER_VERIFICATION; only
	 *        decides whether the PIN is required for the creation itself
	 * @return the credential id and public key, to be stored by the caller
	 * @throws NullPointerException if token, relyingPartyId, userName or
	 *         verificationMode is null
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2VerificationModeException if user verification is
	 *         requested for a token without PIN
	 * @throws Fido2Exception on any other error
	 */
	public static Fido2Registration register(final Fido2Token token, final String relyingPartyId, final String userName, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode) {
		Objects.requireNonNull(token, "token");
		Objects.requireNonNull(relyingPartyId, "relyingPartyId");
		Objects.requireNonNull(userName, "userName");
		Objects.requireNonNull(verificationMode, "verificationMode");

		LOCK.lock();
		try {
			ensureLibraryAvailable();
			final LibFido2.CreatedCredential createdCredential = LibFido2.createCredential(token.getId(), relyingPartyId, userName, nonNull(interaction), verificationMode, false);
			return new Fido2Registration(createdCredential.credentialId(), encodeEs256PublicKey(createdCredential.rawPublicKey()));
		} finally {
			LOCK.unlock();
		}
	}

	/**
	 * Lets the token sign a challenge with one of the given credentials (no
	 * hmac-secret), like a WebAuthn login. Needs one touch, with user
	 * verification also the PIN. Unlike the hmac-secret, user presence only
	 * also works via the Windows WebAuthn API.
	 *
	 * The result is not verified here, use
	 * {@link #verifyAssertion(Fido2Assertion, byte[], String, byte[], Fido2VerificationMode)}
	 * with the stored public key of the credential at
	 * {@link Fido2Assertion#getCredentialIndex()}.
	 *
	 * @param token the connected token
	 * @param relyingPartyId application identifier, the same value as used
	 *        for register()
	 * @param credentialIds the credential ids registered for the user, at
	 *        least one; the token uses the one that belongs to it
	 * @param challenge the challenge to be signed, at least
	 *        {@link #MIN_CHALLENGE_LENGTH} bytes, see {@link #generateChallenge()}
	 * @param interaction callbacks for PIN and touch prompts, may be null
	 * @param verificationMode USER_PRESENCE (touch only) or
	 *        USER_VERIFICATION (touch and PIN)
	 * @return the assertion with the signature
	 * @throws NullPointerException if token, relyingPartyId, challenge or
	 *         verificationMode is null
	 * @throws IllegalArgumentException if credentialIds is null, empty or
	 *         contains a null or empty id, or the challenge is too short
	 * @throws Fido2NoMatchingCredentialException if no credential belongs to the token
	 * @throws Fido2PinRequiredException if the PIN is needed but was not
	 *         given, or was rejected
	 * @throws Fido2VerificationModeException if the requested mode is not
	 *         possible with this token (user verification without PIN set, a
	 *         token enforcing user verification), or the token did not report
	 *         the requested user check
	 * @throws Fido2Exception on any other error
	 */
	public static Fido2Assertion authenticate(final Fido2Token token, final String relyingPartyId, final List<byte[]> credentialIds, final byte[] challenge, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode) {
		Objects.requireNonNull(token, "token");
		Objects.requireNonNull(relyingPartyId, "relyingPartyId");
		Objects.requireNonNull(challenge, "challenge");
		Objects.requireNonNull(verificationMode, "verificationMode");
		if (credentialIds == null || credentialIds.isEmpty()) {
			throw new IllegalArgumentException("No credential ids given");
		}
		final List<byte[]> checkedCredentialIds = new ArrayList<>(credentialIds.size());
		for (final byte[] credentialId : credentialIds) {
			if (credentialId == null || credentialId.length == 0) {
				throw new IllegalArgumentException("Credential id is missing");
			}
			checkedCredentialIds.add(credentialId.clone());
		}
		if (challenge.length < MIN_CHALLENGE_LENGTH) {
			throw new IllegalArgumentException("Challenge must be at least " + MIN_CHALLENGE_LENGTH + " bytes long");
		}

		LOCK.lock();
		try {
			ensureLibraryAvailable();
			final LibFido2.SignedAssertion signedAssertion = LibFido2.getSignatureAssertion(token.getId(), relyingPartyId, checkedCredentialIds, challenge.clone(), nonNull(interaction), verificationMode);
			return new Fido2Assertion(signedAssertion.credentialIndex(), signedAssertion.credentialId(), signedAssertion.clientData(), signedAssertion.authenticatorData(), signedAssertion.signature());
		} finally {
			LOCK.unlock();
		}
	}

	/**
	 * Verifies an assertion created by
	 * {@link #authenticate(Fido2Token, String, List, byte[], Fido2Interaction, Fido2VerificationMode)}.
	 * Pure Java (JDK), needs neither a token nor the native library, so it
	 * also works on a server.
	 *
	 * Checks:
	 * <ul>
	 * <li>the relying party id hash in the authenticator data</li>
	 * <li>the "user present" flag, and for USER_VERIFICATION also the "user
	 * verified" flag</li>
	 * <li>type "webauthn.get" and the expected challenge in the client data</li>
	 * <li>the ECDSA P-256 signature over the authenticator data followed by
	 * the SHA-256 hash of the client data</li>
	 * </ul>
	 * Not checked: the origin in the client data, and whether the signature
	 * counter increased ({@link Fido2Assertion#getSignatureCounter()}, the
	 * caller has to compare it with the last stored value if needed).
	 *
	 * @param assertion the assertion to verify
	 * @param publicKey the stored public key of the used credential, as
	 *        returned by {@link Fido2Registration#getPublicKey()}
	 * @param relyingPartyId the relying party id used for registration
	 * @param expectedChallenge the challenge given to authenticate()
	 * @param requiredMode USER_PRESENCE (touch is sufficient, additional
	 *        verification is accepted) or USER_VERIFICATION (verification
	 *        required)
	 * @return true if the assertion is valid, false otherwise (also for a
	 *         malformed public key or client data)
	 * @throws NullPointerException if a parameter is null
	 */
	public static boolean verifyAssertion(final Fido2Assertion assertion, final byte[] publicKey, final String relyingPartyId, final byte[] expectedChallenge, final Fido2VerificationMode requiredMode) {
		Objects.requireNonNull(assertion, "assertion");
		Objects.requireNonNull(publicKey, "publicKey");
		Objects.requireNonNull(relyingPartyId, "relyingPartyId");
		Objects.requireNonNull(expectedChallenge, "expectedChallenge");
		Objects.requireNonNull(requiredMode, "requiredMode");

		try {
			final byte[] authenticatorData = assertion.getAuthenticatorData();
			final byte[] clientData = assertion.getClientData();

			final byte[] relyingPartyIdHash = MessageDigest.getInstance("SHA-256").digest(relyingPartyId.getBytes(StandardCharsets.UTF_8));
			if (!MessageDigest.isEqual(relyingPartyIdHash, Arrays.copyOf(authenticatorData, relyingPartyIdHash.length))) {
				return false;
			}

			if (!assertion.isUserPresent()) {
				return false;
			}
			if (requiredMode == Fido2VerificationMode.USER_VERIFICATION && !assertion.isUserVerified()) {
				return false;
			}

			final String clientDataJson = new String(clientData, StandardCharsets.UTF_8);
			if (!CLIENT_DATA_TYPE_GET.equals(getJsonStringValue(clientDataJson, "type"))) {
				return false;
			}
			final String expectedChallengeText = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedChallenge);
			final String challengeText = getJsonStringValue(clientDataJson, "challenge");
			if (challengeText == null || !MessageDigest.isEqual(expectedChallengeText.getBytes(StandardCharsets.US_ASCII), challengeText.getBytes(StandardCharsets.US_ASCII))) {
				return false;
			}

			final PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKey));
			if (!(key instanceof final ECPublicKey ecPublicKey) || ecPublicKey.getParams().getCurve().getField().getFieldSize() != 256) {
				return false;
			}
			final Signature verifier = Signature.getInstance("SHA256withECDSA");
			verifier.initVerify(key);
			verifier.update(authenticatorData);
			verifier.update(MessageDigest.getInstance("SHA-256").digest(clientData));
			return verifier.verify(assertion.getSignature());
		} catch (@SuppressWarnings("unused") final GeneralSecurityException | IllegalArgumentException e) {
			// Malformed key or signature: not valid
			return false;
		}
	}

	/**
	 * Encodes a raw ES256 public key (x || y, 32 bytes each) as X.509
	 * SubjectPublicKeyInfo (DER).
	 *
	 * @param rawPublicKey the 64 byte raw public key
	 * @return the encoded public key
	 * @throws Fido2Exception if the raw key does not have 64 bytes
	 */
	static byte[] encodeEs256PublicKey(final byte[] rawPublicKey) {
		if (rawPublicKey == null || rawPublicKey.length != LibFido2.RAW_ES256_PUBLIC_KEY_LENGTH) {
			throw new Fido2Exception("Invalid raw ES256 public key length: " + (rawPublicKey == null ? "null" : rawPublicKey.length));
		}
		final byte[] encoded = Arrays.copyOf(ES256_SUBJECT_PUBLIC_KEY_INFO_PREFIX, ES256_SUBJECT_PUBLIC_KEY_INFO_PREFIX.length + rawPublicKey.length);
		System.arraycopy(rawPublicKey, 0, encoded, ES256_SUBJECT_PUBLIC_KEY_INFO_PREFIX.length, rawPublicKey.length);
		return encoded;
	}

	/**
	 * Returns the value of a top-level string member of a flat JSON object,
	 * without unescaping (sufficient for the base64url challenge and the
	 * type of WebAuthn client data, which contain no escape sequences).
	 *
	 * @param json the JSON text
	 * @param name the member name
	 * @return the raw string value, or null if the member is missing or not a string
	 */
	static String getJsonStringValue(final String json, final String name) {
		final Matcher matcher = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
		return matcher.find() ? matcher.group(1) : null;
	}

	/**
	 * Loads the native library if not done yet.
	 *
	 * @throws Fido2Exception if the native library is not available
	 */
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
