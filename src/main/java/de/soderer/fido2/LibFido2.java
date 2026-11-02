package de.soderer.fido2;

import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

/**
 * Low-level FIDO2 operations on device paths, based on the native libfido2
 * library via JNA. Mirrors the steps of the reference shell script
 * "fido2_hmac-secret.sh" (credential creation, hmac-secret assertion).
 *
 * INTERNAL: Only used by Fido2Utilities, which decides which device path and
 * which strategy to use on the current operating system. Not thread-safe,
 * Fido2Utilities serializes all calls.
 */
final class LibFido2 {
	/**
	 * Device path of libfido2's Windows WebAuthn API backend (webauthn.dll).
	 * Not a token itself: Windows shows its own dialog, lets the user select
	 * and touch a security key and asks for its PIN. Works without
	 * administrator rights, like in browsers.
	 */
	static final String WINDOWS_WEBAUTHN_PATH = "windows://hello";

	/**
	 * Name of the environment variable or system property, which enables the
	 * debug log of libfido2. Its value is the path of the log file, or "1"
	 * for the file "Fido2Crypt-debug.log" in the user's home directory.
	 */
	static final String DEBUG_LOG_SETTING = "FIDO2CRYPT_DEBUG";

	private static boolean initialized = false;

	/** Strong reference, the native library must never call a garbage collected callback. */
	private static Fido2Native.LogHandler debugLogHandler = null;

	/** Discards the libfido2 debug output, a static field keeps the callback from being garbage collected. */
	private static final Fido2Native.LogHandler DISCARDING_LOG_HANDLER = message -> {
		// Debug output not wanted
	};

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	/** "UP" bit of the authenticator data flags: the user was present (touched the token) */
	static final int AUTHDATA_FLAG_USER_PRESENT = 0x01;

	/** "UV" bit of the authenticator data flags: the token performed user verification */
	static final int AUTHDATA_FLAG_USER_VERIFIED = 0x04;

	/** Length of a raw ES256 public key as returned by libfido2: coordinates x and y, 32 bytes each */
	static final int RAW_ES256_PUBLIC_KEY_LENGTH = 64;

	static {
		// libfido2 expects UTF-8 strings.
		// Native.setProtected(true) must NOT be used: on Linux/macOS JNA then temporarily installs its own
		// SIGSEGV/SIGBUS handlers during every native call. The JVM itself uses SIGSEGV internally (implicit
		// null checks and safepoint polls in JIT-compiled code), so such a signal raised by any other Java
		// thread meanwhile is caught by JNA instead of the JVM, which crashes the JVM.
		System.setProperty("jna.encoding", "UTF-8");
	}

	/** A device as reported by fido_dev_info_manifest() */
	static final class DeviceEntry {
		/** Device path for fido_dev_open() */
		final String path;
		/** Manufacturer, may be null or empty */
		final String manufacturer;
		/** Product name, may be null or empty */
		final String product;

		/**
		 * Creates a new device entry.
		 *
		 * @param path device path for fido_dev_open()
		 * @param manufacturer manufacturer, may be null or empty
		 * @param product product name, may be null or empty
		 */
		DeviceEntry(final String path, final String manufacturer, final String product) {
			this.path = path;
			this.manufacturer = manufacturer;
			this.product = product;
		}

		/**
		 * Builds a human readable name: "manufacturer product", only the
		 * product if there is no manufacturer, or the path if there is no
		 * product.
		 *
		 * @return the display name
		 */
		String getDisplayName() {
			if (product != null && !product.isBlank()) {
				return manufacturer != null && !manufacturer.isBlank() ? manufacturer + " " + product : product;
			} else {
				return path;
			}
		}
	}

	private LibFido2() {
		// Utility class
	}

	/**
	 * Loads the native library and initializes libfido2 (including the debug
	 * output setting).
	 *
	 * @throws LinkageError (UnsatisfiedLinkError) if libfido2 cannot be loaded
	 */
	static synchronized void ensureInitialized() {
		if (initialized) {
			return;
		}

		String debugLogSetting = System.getProperty(DEBUG_LOG_SETTING);
		if (debugLogSetting == null || debugLogSetting.isBlank()) {
			debugLogSetting = System.getenv(DEBUG_LOG_SETTING);
		}
		if (debugLogSetting != null && !debugLogSetting.isBlank()) {
			final File debugLogFile = "1".equals(debugLogSetting.trim())
					? new File(System.getProperty("user.home"), "Fido2Crypt-debug.log")
					: new File(debugLogSetting.trim());
			debugLogHandler = message -> writeDebugLog(debugLogFile, message);
			Fido2Native.INSTANCE.fido_init(Fido2Native.FIDO_DEBUG);
			Fido2Native.INSTANCE.fido_set_log_handler(debugLogHandler);
			writeDebugLog(debugLogFile, "FIDO2 debug log started, os: " + System.getProperty("os.name") + ", administrator: " + Fido2WindowsSupport.isRunningAsAdministrator());
		} else {
			Fido2Native.INSTANCE.fido_init(0);
			// libfido2 also writes debug output to stderr, if the environment variable FIDO_DEBUG is set
			debugLogHandler = null;
			Fido2Native.INSTANCE.fido_set_log_handler(DISCARDING_LOG_HANDLER);
		}
		initialized = true;
	}

	private static synchronized void writeDebugLog(final File debugLogFile, final String message) {
		try (Writer writer = new OutputStreamWriter(Files.newOutputStream(debugLogFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.APPEND), StandardCharsets.UTF_8)) {
			writer.write(LocalDateTime.now() + " " + (message == null ? "" : message.stripTrailing()) + System.lineSeparator());
		} catch (@SuppressWarnings("unused") final IOException e) {
			// Debug logging must never break the actual operation
		}
	}

	private static void debugLog(final String message) {
		final Fido2Native.LogHandler handler = debugLogHandler;
		if (handler != null) {
			handler.invoke("FIDO2: " + message);
		}
	}

	/**
	 * Lists the devices reported by libfido2, including the Windows WebAuthn
	 * pseudo-device (WINDOWS_WEBAUTHN_PATH) on Windows.
	 *
	 * @param maxDevices maximum number of devices to report
	 * @return the devices, empty if none is connected
	 * @throws Fido2Exception if the enumeration failed
	 */
	static List<DeviceEntry> listDevices(final int maxDevices) {
		ensureInitialized();

		final Fido2Native fido = Fido2Native.INSTANCE;
		final List<DeviceEntry> result = new ArrayList<>();

		final Pointer devList = fido.fido_dev_info_new(new SizeT(maxDevices));
		if (devList == null) {
			throw new Fido2Exception("fido_dev_info_new() failed (memory error).");
		}

		try {
			final SizeT.ByRef devCountOut = new SizeT.ByRef();
			final int returnCode = fido.fido_dev_info_manifest(devList, new SizeT(maxDevices), devCountOut);
			if (returnCode != Fido2Native.FIDO_OK) {
				throw new Fido2Exception("fido_dev_info_manifest() failed: " + fido.fido_strerr(returnCode));
			}

			final long deviceCount = Math.min(devCountOut.getValue(), maxDevices);
			for (long i = 0; i < deviceCount; i++) {
				final Pointer devInfoEntry = fido.fido_dev_info_ptr(devList, new SizeT(i));
				if (devInfoEntry != null) {
					// Strings are copied by JNA immediately, before the list is freed
					result.add(new DeviceEntry(
							fido.fido_dev_info_path(devInfoEntry),
							fido.fido_dev_info_manufacturer_string(devInfoEntry),
							fido.fido_dev_info_product_string(devInfoEntry)));
				}
			}
		} finally {
			fido.fido_dev_info_free(new PointerByReference(devList), new SizeT(maxDevices));
		}

		return result;
	}

	/**
	 * Checks whether the Windows WebAuthn API can be opened. Requires no user
	 * interaction, fido_dev_is_winhello() only reads a flag set by
	 * fido_dev_open(). Always false on other systems.
	 *
	 * @return true if the Windows WebAuthn API is usable
	 */
	static boolean isWindowsWebAuthnAvailable() {
		if (!Fido2WindowsSupport.isWindows()) {
			return false;
		}
		ensureInitialized();

		final Fido2Native fido = Fido2Native.INSTANCE;
		final Pointer dev = fido.fido_dev_new();
		if (dev == null) {
			return false;
		}
		boolean opened = false;
		try {
			opened = fido.fido_dev_open(dev, WINDOWS_WEBAUTHN_PATH) == Fido2Native.FIDO_OK;
			return opened && fido.fido_dev_is_winhello(dev) != 0;
		} finally {
			closeAndFree(fido, dev, opened);
		}
	}

	/**
	 * Creates a new credential with the hmac-secret extension enabled
	 * ("fido2-cred -M / -V" in the shell script).
	 *
	 * @param path device path
	 * @param relyingPartyId relying party id
	 * @param userName user name stored with the credential
	 * @param interaction callbacks for PIN and touch prompts, not null
	 * @return credential id
	 * @throws Fido2PinRequiredException if a PIN is needed but none was
	 *         given by the interaction, or the given PIN was rejected
	 */
	static byte[] makeCredential(final String path, final String relyingPartyId, final String userName, final Fido2Interaction interaction) {
		return makeCredential(path, relyingPartyId, userName, interaction, Fido2VerificationMode.USER_PRESENCE);
	}

	/**
	 * Creates a new credential with the hmac-secret extension enabled
	 * ("fido2-cred -M / -V" in the shell script).
	 *
	 * The verification mode only decides whether a PIN is asked for during
	 * the creation. The credential itself supports both modes for later
	 * hmac-secret assertions.
	 *
	 * @param path device path
	 * @param relyingPartyId relying party id
	 * @param userName user name stored with the credential
	 * @param interaction callbacks for PIN and touch prompts, not null
	 * @param verificationMode USER_PRESENCE or USER_VERIFICATION, not null
	 * @return credential id
	 * @throws Fido2PinRequiredException if a PIN is needed but none was
	 *         given by the interaction, or the given PIN was rejected
	 * @throws Fido2VerificationModeException if user verification is
	 *         requested, but the token has no PIN set
	 */
	static byte[] makeCredential(final String path, final String relyingPartyId, final String userName, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode) {
		return createCredential(path, relyingPartyId, userName, interaction, verificationMode, true).credentialId();
	}

	/**
	 * Result of a credential creation: the credential id and the public key
	 * (raw ES256 coordinates x and y, 64 bytes; may be null for hmac-secret
	 * credentials, never null for signature credentials).
	 *
	 * @param credentialId the credential id
	 * @param rawPublicKey the raw public key
	 */
	record CreatedCredential(byte[] credentialId, byte[] rawPublicKey) {
		// Data holder only
	}

	/**
	 * Creates a new ES256 credential, optionally with the hmac-secret
	 * extension enabled.
	 *
	 * The verification mode only decides whether a PIN is asked for during
	 * the creation.
	 *
	 * @param path device path
	 * @param relyingPartyId relying party id
	 * @param userName user name stored with the credential
	 * @param interaction callbacks for PIN and touch prompts, not null
	 * @param verificationMode USER_PRESENCE or USER_VERIFICATION, not null
	 * @param hmacSecret true to enable the hmac-secret extension, false for
	 *        a plain credential for signatures only (like WebAuthn logins)
	 * @return credential id and public key
	 * @throws Fido2PinRequiredException if a PIN is needed but none was
	 *         given by the interaction, or the given PIN was rejected
	 * @throws Fido2VerificationModeException if user verification is
	 *         requested, but the token has no PIN set
	 */
	static CreatedCredential createCredential(final String path, final String relyingPartyId, final String userName, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode, final boolean hmacSecret) {
		ensureInitialized();

		final boolean userVerification = isUserVerification(verificationMode);

		final Fido2Native fido = Fido2Native.INSTANCE;
		final Pointer dev = fido.fido_dev_new();
		if (dev == null) {
			throw new Fido2Exception("fido_dev_new() failed (memory error).");
		}

		boolean opened = false;
		Pointer cred = null;
		try {
			int returnCode = fido.fido_dev_open(dev, path);
			if (returnCode != Fido2Native.FIDO_OK) {
				throw new Fido2Exception("Could not open token (" + path + "): " + fido.fido_strerr(returnCode));
			}
			opened = true;

			final boolean windowsWebAuthn = fido.fido_dev_is_winhello(dev) != 0;

			cred = fido.fido_cred_new();
			if (cred == null) {
				throw new Fido2Exception("fido_cred_new() failed (memory error).");
			}

			final byte[] clientData = createClientData("webauthn.create", relyingPartyId);
			final byte[] userId = randomBytes(32);

			checkResult(fido.fido_cred_set_type(cred, Fido2Native.COSE_ES256), "fido_cred_set_type");
			checkResult(fido.fido_cred_set_clientdata(cred, clientData, new SizeT(clientData.length)), "fido_cred_set_clientdata");
			checkResult(fido.fido_cred_set_rp(cred, relyingPartyId, relyingPartyId), "fido_cred_set_rp");
			checkResult(fido.fido_cred_set_user(cred, userId, new SizeT(userId.length), userName, userName, null), "fido_cred_set_user");
			if (hmacSecret) {
				checkResult(fido.fido_cred_set_extensions(cred, Fido2Native.FIDO_EXT_HMAC_SECRET), "fido_cred_set_extensions");
			}
			// Windows WebAuthn: explicitly no discoverable credential, Windows would otherwise prefer
			// to store it on the token, which needs one of its few storage slots for every credential
			checkResult(fido.fido_cred_set_rk(cred, windowsWebAuthn ? Fido2Native.FIDO_OPT_FALSE : Fido2Native.FIDO_OPT_OMIT), "fido_cred_set_rk");
			// Windows WebAuthn: explicit user verification setting, otherwise Windows uses "preferred" and
			// forces the user to set a PIN on tokens without one. Direct access: UV is done via the PIN.
			checkResult(fido.fido_cred_set_uv(cred, getUvOption(windowsWebAuthn, userVerification)), "fido_cred_set_uv");

			// Local capability check (no touch needed): with a PIN set, ask for it right away instead
			// of a doomed first attempt without PIN. The Windows WebAuthn API asks for the PIN itself.
			final boolean hasPin = !windowsWebAuthn && fido.fido_dev_has_pin(dev) != 0;
			if (userVerification && !windowsWebAuthn && !hasPin) {
				throw new Fido2VerificationModeException("User verification was requested, but the token has no PIN set. Please set a PIN on the token first.");
			}

			String pin = null;
			if (hasPin) {
				pin = requirePin(interaction, "Credential creation requires the token's PIN.");
			}
			returnCode = attemptMakeCredential(fido, dev, cred, pin, interaction, windowsWebAuthn);

			if (returnCode == Fido2Native.FIDO_ERR_PIN_REQUIRED && pin == null) {
				// Token demands a PIN despite reporting none set at open time
				pin = requirePin(interaction, "Credential creation requires the token's PIN.");
				returnCode = attemptMakeCredential(fido, dev, cred, pin, interaction, windowsWebAuthn);
			}
			if (returnCode == Fido2Native.FIDO_ERR_PIN_REQUIRED || isPinInvalid(fido, returnCode)) {
				throw new Fido2PinRequiredException("Credential creation failed: the given PIN was rejected by the token.", true);
			}
			if (returnCode != Fido2Native.FIDO_OK) {
				throw new Fido2Exception("Credential creation failed (activate token / check PIN): " + fido.fido_strerr(returnCode));
			}

			// Windows may return an attestation without signature (attestation conveyance "none"),
			// which cannot be verified. Only the credential id is used here anyway.
			if (!windowsWebAuthn) {
				returnCode = fido.fido_cred_verify(cred);
				if (returnCode != Fido2Native.FIDO_OK) {
					throw new Fido2Exception("Verification of the created credential failed: " + fido.fido_strerr(returnCode));
				}
			}

			final Pointer credIdPtr = fido.fido_cred_id_ptr(cred);
			final int credIdLen = fido.fido_cred_id_len(cred).intValue();
			if (credIdPtr == null || credIdLen <= 0) {
				throw new Fido2Exception("Could not read a credential id from the token.");
			}
			// Copied before fido_cred_free()
			final byte[] credentialId = credIdPtr.getByteArray(0, credIdLen);
			final Pointer pubKeyPtr = fido.fido_cred_pubkey_ptr(cred);
			final int pubKeyLen = fido.fido_cred_pubkey_len(cred).intValue();
			final byte[] rawPublicKey;
			if (pubKeyPtr != null && pubKeyLen == RAW_ES256_PUBLIC_KEY_LENGTH) {
				rawPublicKey = pubKeyPtr.getByteArray(0, pubKeyLen);
			} else if (hmacSecret) {
				// hmac-secret credentials do not need their public key
				rawPublicKey = null;
			} else {
				// Signature credentials are useless without their public key
				throw new Fido2Exception("Could not read the ES256 public key of the created credential (length " + pubKeyLen + ").");
			}
			return new CreatedCredential(credentialId, rawPublicKey);
		} finally {
			if (cred != null) {
				fido.fido_cred_free(new PointerByReference(cred));
			}
			closeAndFree(fido, dev, opened);
		}
	}

	/**
	 * Retrieves the hmac-secret of an existing credential for the given salt
	 * ("fido2-assert -G" in the shell script).
	 *
	 * @param path device path
	 * @param relyingPartyId relying party id used for the credential creation
	 * @param credentialId credential id
	 * @param salt salt for the hmac-secret extension
	 * @param interaction callbacks for PIN and touch prompts, not null
	 * @param expectedTokenName optional name of the token the credential was
	 *        created on, only for the error message; may be null
	 * @return the 32 byte hmac-secret
	 * @throws Fido2NoMatchingCredentialException if the credential does not belong to the token
	 * @throws Fido2PinRequiredException if a PIN is needed but none was
	 *         given by the interaction, or the given PIN was rejected
	 */
	static byte[] getHmacSecret(final String path, final String relyingPartyId, final byte[] credentialId, final byte[] salt, final Fido2Interaction interaction, final String expectedTokenName) {
		return getHmacSecret(path, relyingPartyId, credentialId, salt, interaction, expectedTokenName, Fido2VerificationMode.USER_PRESENCE);
	}

	/**
	 * Retrieves the hmac-secret of an existing credential for the given salt
	 * ("fido2-assert -G" in the shell script).
	 *
	 * The token derives different secrets with and without user
	 * verification, so the same verification mode as for the original
	 * encryption must be used.
	 *
	 * @param path device path
	 * @param relyingPartyId relying party id used for the credential creation
	 * @param credentialId credential id
	 * @param salt salt for the hmac-secret extension
	 * @param interaction callbacks for PIN and touch prompts, not null
	 * @param expectedTokenName optional name of the token the credential was
	 *        created on, only for the error message; may be null
	 * @param verificationMode USER_PRESENCE (touch only, never a PIN) or
	 *        USER_VERIFICATION (PIN always), not null
	 * @return the 32 byte hmac-secret
	 * @throws Fido2NoMatchingCredentialException if the credential does not belong to the token
	 * @throws Fido2PinRequiredException if a PIN is needed but none was
	 *         given by the interaction, or the given PIN was rejected
	 * @throws Fido2VerificationModeException if the secret cannot be
	 *         retrieved in the requested mode (user presence via the Windows
	 *         WebAuthn API, user verification on a token without PIN, a token
	 *         enforcing user verification), or the token reported a different
	 *         user verification state than requested
	 */
	static byte[] getHmacSecret(final String path, final String relyingPartyId, final byte[] credentialId, final byte[] salt, final Fido2Interaction interaction, final String expectedTokenName, final Fido2VerificationMode verificationMode) {
		ensureInitialized();

		final boolean userVerification = isUserVerification(verificationMode);

		final Fido2Native fido = Fido2Native.INSTANCE;
		final Pointer dev = fido.fido_dev_new();
		if (dev == null) {
			throw new Fido2Exception("fido_dev_new() failed (memory error).");
		}

		boolean opened = false;
		Pointer assertPtr = null;
		try {
			int returnCode = fido.fido_dev_open(dev, path);
			if (returnCode != Fido2Native.FIDO_OK) {
				throw new Fido2Exception("Could not open token (" + path + "): " + fido.fido_strerr(returnCode));
			}
			opened = true;

			final boolean windowsWebAuthn = fido.fido_dev_is_winhello(dev) != 0;

			assertPtr = fido.fido_assert_new();
			if (assertPtr == null) {
				throw new Fido2Exception("fido_assert_new() failed (memory error).");
			}

			final byte[] clientData = createClientData("webauthn.get", relyingPartyId);

			checkResult(fido.fido_assert_set_rp(assertPtr, relyingPartyId), "fido_assert_set_rp");
			checkResult(fido.fido_assert_set_clientdata(assertPtr, clientData, new SizeT(clientData.length)), "fido_assert_set_clientdata");
			checkResult(fido.fido_assert_allow_cred(assertPtr, credentialId, new SizeT(credentialId.length)), "fido_assert_allow_cred");
			checkResult(fido.fido_assert_set_extensions(assertPtr, Fido2Native.FIDO_EXT_HMAC_SECRET), "fido_assert_set_extensions");
			checkResult(fido.fido_assert_set_hmac_salt(assertPtr, salt, new SizeT(salt.length)), "fido_assert_set_hmac_salt");
			checkResult(fido.fido_assert_set_up(assertPtr, Fido2Native.FIDO_OPT_OMIT), "fido_assert_set_up");
			// Windows WebAuthn: "required" for user verification (user presence only is rejected below).
			// Direct access: UV is done via the PIN (pinUvAuthParam), the "uv" option itself is omitted.
			checkResult(fido.fido_assert_set_uv(assertPtr, getUvOption(windowsWebAuthn, userVerification)), "fido_assert_set_uv");

			if (windowsWebAuthn && !userVerification) {
				// The Windows WebAuthn API enforces user verification for the hmac-secret extension, even with
				// "discouraged" (it even forces creating a PIN on tokens without one). The token would then derive
				// the secret of the user verification mode, which does not match the requested mode.
				throw new Fido2VerificationModeException("Retrieving the HMAC secret with user presence only (touch, no PIN) is not possible via the Windows WebAuthn API, "
						+ "since Windows always enforces user verification (PIN) for it. Run the application with administrator rights for direct token access, "
						+ "or use user verification.");
			}

			if (userVerification && !windowsWebAuthn) {
				// User verification: the PIN is always needed, no attempt without it
				if (fido.fido_dev_has_pin(dev) == 0) {
					throw new Fido2VerificationModeException("User verification was requested, but the token has no PIN set. Please set a PIN on the token first.");
				}
				final String pin = requirePin(interaction, "Retrieving the HMAC secret with user verification requires the token's PIN.");
				returnCode = attemptGetAssert(fido, dev, assertPtr, pin, interaction, windowsWebAuthn);
				if (returnCode == Fido2Native.FIDO_ERR_PIN_REQUIRED || isPinInvalid(fido, returnCode)) {
					throw new Fido2PinRequiredException("Retrieving the HMAC secret failed: the given PIN was rejected by the token.", true);
				}
			} else {
				// User presence via direct access: no PIN. User verification via Windows WebAuthn: Windows asks for the PIN itself.
				returnCode = attemptGetAssert(fido, dev, assertPtr, null, interaction, windowsWebAuthn);
				if (returnCode == Fido2Native.FIDO_ERR_PIN_REQUIRED && !windowsWebAuthn) {
					// Token enforces user verification (e.g. "alwaysUv"). Retrying with the PIN would derive the
					// secret of the user verification mode, which does not match the requested mode.
					throw new Fido2VerificationModeException("The token requires user verification (PIN) for retrieving the HMAC secret (e.g. 'alwaysUv' is enabled), "
							+ "so user presence only (touch, no PIN) is not possible with this token. Please use user verification.");
				}
			}

			if (returnCode != Fido2Native.FIDO_OK) {
				if ("FIDO_ERR_NO_CREDENTIALS".equals(fido.fido_strerr(returnCode))) {
					if (expectedTokenName != null && !expectedTokenName.isBlank()) {
						throw new Fido2NoMatchingCredentialException("The given credential id does not match the connected token. Please plug in the correct token (token used for encryption: '" + expectedTokenName + "').");
					} else {
						throw new Fido2NoMatchingCredentialException("The given credential id does not match the connected token. Please plug in the correct token.");
					}
				} else {
					throw new Fido2Exception("Assertion failed: " + fido.fido_strerr(returnCode));
				}
			}

			if (fido.fido_assert_count(assertPtr).longValue() <= 0) {
				throw new Fido2Exception("Token did not return any assertion statements.");
			}

			// The hmac-secret depends on whether the token actually performed user verification, so it must
			// match the requested mode. Otherwise the caller would store a mode that does not fit the secret.
			final boolean userVerified = (fido.fido_assert_flags(assertPtr, new SizeT(0)) & AUTHDATA_FLAG_USER_VERIFIED) != 0;
			debugLog("assertion flags: user verified = " + userVerified + ", requested mode = " + verificationMode);
			if (userVerified != userVerification) {
				if (userVerified) {
					throw new Fido2VerificationModeException("The token performed user verification although user presence only (touch, no PIN) was requested "
							+ "(e.g. a token with fingerprint sensor, or the operating system enforced it). The HMAC secret would not match the requested mode.");
				} else {
					throw new Fido2VerificationModeException("The token did not perform user verification although it was requested. "
							+ "The HMAC secret would not match the requested mode.");
				}
			}

			final Pointer hmacSecretPtr = fido.fido_assert_hmac_secret_ptr(assertPtr, new SizeT(0));
			final int hmacSecretLen = fido.fido_assert_hmac_secret_len(assertPtr, new SizeT(0)).intValue();
			if (hmacSecretPtr == null || hmacSecretLen <= 0) {
				throw new Fido2Exception("Token did not return an HMAC secret. Does the token support the hmac-secret extension?");
			}
			// Copied before fido_assert_free()
			return hmacSecretPtr.getByteArray(0, hmacSecretLen);
		} finally {
			if (assertPtr != null) {
				fido.fido_assert_free(new PointerByReference(assertPtr));
			}
			closeAndFree(fido, dev, opened);
		}
	}

	/**
	 * Finds out which of the given credentials belongs to the connected
	 * token, with a single assertion allowing all of them (the token picks
	 * its own credential).
	 *
	 * @param path device path
	 * @param relyingPartyId relying party id used for the credential creation
	 * @param credentialIds candidate credential ids
	 * @param interaction callbacks for touch prompts, not null
	 * @return index of the matching credential in credentialIds
	 * @throws Fido2NoMatchingCredentialException if no credential matches the token
	 */
	static int findMatchingCredentialIndex(final String path, final String relyingPartyId, final List<byte[]> credentialIds, final Fido2Interaction interaction) {
		ensureInitialized();

		final Fido2Native fido = Fido2Native.INSTANCE;
		final Pointer dev = fido.fido_dev_new();
		if (dev == null) {
			throw new Fido2Exception("fido_dev_new() failed (memory error).");
		}

		boolean opened = false;
		Pointer assertPtr = null;
		try {
			final int openReturnCode = fido.fido_dev_open(dev, path);
			if (openReturnCode != Fido2Native.FIDO_OK) {
				throw new Fido2Exception("Could not open token (" + path + "): " + fido.fido_strerr(openReturnCode));
			}
			opened = true;

			final boolean windowsWebAuthn = fido.fido_dev_is_winhello(dev) != 0;

			assertPtr = fido.fido_assert_new();
			if (assertPtr == null) {
				throw new Fido2Exception("fido_assert_new() failed (memory error).");
			}

			final byte[] clientData = createClientData("webauthn.get", relyingPartyId);
			checkResult(fido.fido_assert_set_rp(assertPtr, relyingPartyId), "fido_assert_set_rp");
			checkResult(fido.fido_assert_set_clientdata(assertPtr, clientData, new SizeT(clientData.length)), "fido_assert_set_clientdata");
			for (final byte[] credentialId : credentialIds) {
				checkResult(fido.fido_assert_allow_cred(assertPtr, credentialId, new SizeT(credentialId.length)), "fido_assert_allow_cred");
			}
			checkResult(fido.fido_assert_set_up(assertPtr, Fido2Native.FIDO_OPT_OMIT), "fido_assert_set_up");
			checkResult(fido.fido_assert_set_uv(assertPtr, windowsWebAuthn ? Fido2Native.FIDO_OPT_FALSE : Fido2Native.FIDO_OPT_OMIT), "fido_assert_set_uv");

			final int returnCode = attemptGetAssert(fido, dev, assertPtr, null, interaction, windowsWebAuthn);
			if (returnCode != Fido2Native.FIDO_OK) {
				throw new Fido2NoMatchingCredentialException("The connected token does not match any token authorized for this file: " + fido.fido_strerr(returnCode));
			}

			if (fido.fido_assert_count(assertPtr).longValue() > 0) {
				final Pointer idPtr = fido.fido_assert_id_ptr(assertPtr, new SizeT(0));
				final int idLen = fido.fido_assert_id_len(assertPtr, new SizeT(0)).intValue();
				if (idPtr != null && idLen > 0) {
					final byte[] usedCredentialId = idPtr.getByteArray(0, idLen);
					for (int i = 0; i < credentialIds.size(); i++) {
						if (Arrays.equals(credentialIds.get(i), usedCredentialId)) {
							return i;
						}
					}
				}
			}
			throw new Fido2NoMatchingCredentialException("The connected token does not match any token authorized for this file.");
		} finally {
			if (assertPtr != null) {
				fido.fido_assert_free(new PointerByReference(assertPtr));
			}
			closeAndFree(fido, dev, opened);
		}
	}

	/**
	 * Result of a signature assertion (without hmac-secret).
	 *
	 * @param credentialIndex index of the used credential in the given list
	 * @param credentialId the used credential id
	 * @param clientData the client data JSON whose hash was signed
	 * @param authenticatorData the raw authenticator data
	 * @param signature the DER encoded ECDSA signature over
	 *        authenticatorData || SHA-256(clientData)
	 */
	record SignedAssertion(int credentialIndex, byte[] credentialId, byte[] clientData, byte[] authenticatorData, byte[] signature) {
		// Data holder only
	}

	/**
	 * Obtains an assertion without hmac-secret: the token only signs the
	 * given challenge, like a WebAuthn login. Unlike the hmac-secret, this
	 * works with user presence only via the Windows WebAuthn API too
	 * (Windows honors "discouraged" here).
	 *
	 * @param path device path
	 * @param relyingPartyId relying party id used for the credential creation
	 * @param credentialIds allowed credential ids, the token uses its own one
	 * @param challenge challenge to be signed (embedded into the client data)
	 * @param interaction callbacks for PIN and touch prompts, not null
	 * @param verificationMode USER_PRESENCE (touch only) or
	 *        USER_VERIFICATION (PIN always), not null
	 * @return the assertion data needed for verification
	 * @throws Fido2NoMatchingCredentialException if no credential belongs to the token
	 * @throws Fido2PinRequiredException if a PIN is needed but none was
	 *         given by the interaction, or the given PIN was rejected
	 * @throws Fido2VerificationModeException if user verification is
	 *         requested for a token without PIN, a token enforces user
	 *         verification although user presence was requested, or the
	 *         token did not report the requested user check
	 */
	static SignedAssertion getSignatureAssertion(final String path, final String relyingPartyId, final List<byte[]> credentialIds, final byte[] challenge, final Fido2Interaction interaction, final Fido2VerificationMode verificationMode) {
		ensureInitialized();

		final boolean userVerification = isUserVerification(verificationMode);

		final Fido2Native fido = Fido2Native.INSTANCE;
		final Pointer dev = fido.fido_dev_new();
		if (dev == null) {
			throw new Fido2Exception("fido_dev_new() failed (memory error).");
		}

		boolean opened = false;
		Pointer assertPtr = null;
		try {
			int returnCode = fido.fido_dev_open(dev, path);
			if (returnCode != Fido2Native.FIDO_OK) {
				throw new Fido2Exception("Could not open token (" + path + "): " + fido.fido_strerr(returnCode));
			}
			opened = true;

			final boolean windowsWebAuthn = fido.fido_dev_is_winhello(dev) != 0;

			assertPtr = fido.fido_assert_new();
			if (assertPtr == null) {
				throw new Fido2Exception("fido_assert_new() failed (memory error).");
			}

			final byte[] clientData = createClientData("webauthn.get", relyingPartyId, challenge);
			checkResult(fido.fido_assert_set_rp(assertPtr, relyingPartyId), "fido_assert_set_rp");
			checkResult(fido.fido_assert_set_clientdata(assertPtr, clientData, new SizeT(clientData.length)), "fido_assert_set_clientdata");
			for (final byte[] credentialId : credentialIds) {
				checkResult(fido.fido_assert_allow_cred(assertPtr, credentialId, new SizeT(credentialId.length)), "fido_assert_allow_cred");
			}
			checkResult(fido.fido_assert_set_up(assertPtr, Fido2Native.FIDO_OPT_OMIT), "fido_assert_set_up");
			// Windows WebAuthn: "discouraged" or "required" (without hmac-secret Windows honors "discouraged").
			// Direct access: UV is done via the PIN (pinUvAuthParam), the "uv" option itself is omitted.
			checkResult(fido.fido_assert_set_uv(assertPtr, getUvOption(windowsWebAuthn, userVerification)), "fido_assert_set_uv");

			if (userVerification && !windowsWebAuthn) {
				if (fido.fido_dev_has_pin(dev) == 0) {
					throw new Fido2VerificationModeException("User verification was requested, but the token has no PIN set. Please set a PIN on the token first.");
				}
				final String pin = requirePin(interaction, "Signing with user verification requires the token's PIN.");
				returnCode = attemptGetAssert(fido, dev, assertPtr, pin, interaction, windowsWebAuthn);
				if (returnCode == Fido2Native.FIDO_ERR_PIN_REQUIRED || isPinInvalid(fido, returnCode)) {
					throw new Fido2PinRequiredException("Signing failed: the given PIN was rejected by the token.", true);
				}
			} else {
				// User presence via direct access: no PIN. Windows WebAuthn: Windows asks for the PIN itself if needed.
				returnCode = attemptGetAssert(fido, dev, assertPtr, null, interaction, windowsWebAuthn);
				if (returnCode == Fido2Native.FIDO_ERR_PIN_REQUIRED && !windowsWebAuthn) {
					throw new Fido2VerificationModeException("The token requires user verification (PIN) for signing (e.g. 'alwaysUv' is enabled), "
							+ "so user presence only (touch, no PIN) is not possible with this token. Please use user verification.");
				}
			}

			if (returnCode != Fido2Native.FIDO_OK) {
				if ("FIDO_ERR_NO_CREDENTIALS".equals(fido.fido_strerr(returnCode))) {
					throw new Fido2NoMatchingCredentialException("None of the given credential ids belongs to the connected token.");
				} else {
					throw new Fido2Exception("Assertion failed: " + fido.fido_strerr(returnCode));
				}
			}

			if (fido.fido_assert_count(assertPtr).longValue() <= 0) {
				throw new Fido2Exception("Token did not return any assertion statements.");
			}

			final int credentialIndex = findUsedCredentialIndex(fido, assertPtr, credentialIds);

			final int flags = fido.fido_assert_flags(assertPtr, new SizeT(0)) & 0xFF;
			final boolean userPresent = (flags & AUTHDATA_FLAG_USER_PRESENT) != 0;
			final boolean userVerified = (flags & AUTHDATA_FLAG_USER_VERIFIED) != 0;
			debugLog("assertion flags: user present = " + userPresent + ", user verified = " + userVerified + ", requested mode = " + verificationMode);
			if (!userPresent) {
				throw new Fido2VerificationModeException("The token did not confirm user presence (touch) for the signature.");
			}
			// Additional user verification in user presence mode (e.g. fingerprint tokens) does not weaken a signature, so it is accepted
			if (userVerification && !userVerified) {
				throw new Fido2VerificationModeException("The token did not perform user verification although it was requested.");
			}

			final Pointer authDataPtr = fido.fido_assert_authdata_ptr(assertPtr, new SizeT(0));
			final int authDataLen = fido.fido_assert_authdata_len(assertPtr, new SizeT(0)).intValue();
			final Pointer sigPtr = fido.fido_assert_sig_ptr(assertPtr, new SizeT(0));
			final int sigLen = fido.fido_assert_sig_len(assertPtr, new SizeT(0)).intValue();
			if (authDataPtr == null || authDataLen <= 0 || sigPtr == null || sigLen <= 0) {
				throw new Fido2Exception("Token did not return authenticator data and signature.");
			}

			// Copied before fido_assert_free()
			final byte[] authenticatorData = unwrapCborByteString(authDataPtr.getByteArray(0, authDataLen));
			final byte[] signature = sigPtr.getByteArray(0, sigLen);
			return new SignedAssertion(credentialIndex, credentialIds.get(credentialIndex).clone(), clientData, authenticatorData, signature);
		} finally {
			if (assertPtr != null) {
				fido.fido_assert_free(new PointerByReference(assertPtr));
			}
			closeAndFree(fido, dev, opened);
		}
	}

	/**
	 * Determines which of the allowed credentials the token used. The
	 * token may omit the credential id in its response if exactly one
	 * credential was allowed (CTAP2), then that one was used.
	 */
	private static int findUsedCredentialIndex(final Fido2Native fido, final Pointer assertPtr, final List<byte[]> credentialIds) {
		final Pointer idPtr = fido.fido_assert_id_ptr(assertPtr, new SizeT(0));
		final int idLen = fido.fido_assert_id_len(assertPtr, new SizeT(0)).intValue();
		if (idPtr != null && idLen > 0) {
			final byte[] usedCredentialId = idPtr.getByteArray(0, idLen);
			for (int i = 0; i < credentialIds.size(); i++) {
				if (Arrays.equals(credentialIds.get(i), usedCredentialId)) {
					return i;
				}
			}
			throw new Fido2Exception("The token used a credential that was not allowed.");
		} else if (credentialIds.size() == 1) {
			return 0;
		} else {
			throw new Fido2Exception("The token did not report which credential it used.");
		}
	}

	/**
	 * Extracts the content of a CBOR byte string (major type 2, definite
	 * length). libfido2 returns the authenticator data of an assertion in
	 * this encoding, the signature covers only its content. Newer libfido2
	 * versions offer fido_assert_authdata_raw_ptr() for this, decoding it
	 * here keeps older libfido2 versions supported.
	 *
	 * @param cborByteString the CBOR-encoded byte string
	 * @return the content of the byte string
	 * @throws Fido2Exception if the data is not exactly one CBOR byte string
	 */
	static byte[] unwrapCborByteString(final byte[] cborByteString) {
		if (cborByteString == null || cborByteString.length == 0) {
			throw new Fido2Exception("Empty CBOR data.");
		}
		final int initialByte = cborByteString[0] & 0xFF;
		final int majorType = initialByte >>> 5;
		final int additionalInfo = initialByte & 0x1F;
		if (majorType != 2) {
			throw new Fido2Exception("CBOR data is not a byte string (major type " + majorType + ").");
		}

		final int headerLength;
		final long contentLength;
		if (additionalInfo < 24) {
			headerLength = 1;
			contentLength = additionalInfo;
		} else if (additionalInfo == 24) {
			headerLength = 2;
			contentLength = readUnsignedBigEndian(cborByteString, 1, 1);
		} else if (additionalInfo == 25) {
			headerLength = 3;
			contentLength = readUnsignedBigEndian(cborByteString, 1, 2);
		} else if (additionalInfo == 26) {
			headerLength = 5;
			contentLength = readUnsignedBigEndian(cborByteString, 1, 4);
		} else {
			throw new Fido2Exception("Unsupported CBOR byte string length encoding: " + additionalInfo);
		}

		if (headerLength + contentLength != cborByteString.length) {
			throw new Fido2Exception("CBOR byte string length mismatch: header says " + contentLength + " bytes, but " + (cborByteString.length - headerLength) + " bytes follow.");
		}
		return Arrays.copyOfRange(cborByteString, headerLength, cborByteString.length);
	}

	private static long readUnsignedBigEndian(final byte[] data, final int offset, final int length) {
		if (offset + length > data.length) {
			throw new Fido2Exception("Truncated CBOR data.");
		}
		long value = 0;
		for (int i = 0; i < length; i++) {
			value = (value << 8) | (data[offset + i] & 0xFF);
		}
		return value;
	}

	private static int attemptMakeCredential(final Fido2Native fido, final Pointer dev, final Pointer cred, final String pin, final Fido2Interaction interaction, final boolean windowsWebAuthn) {
		// The Windows WebAuthn API shows its own dialog for touch and PIN, an additional prompt would only confuse
		if (!windowsWebAuthn) {
			interaction.onTouchRequired();
		}
		try {
			debugLog("fido_dev_make_cred started");
			final int returnCode = fido.fido_dev_make_cred(dev, cred, pin);
			debugLog("fido_dev_make_cred returned " + returnCode + " (" + fido.fido_strerr(returnCode) + ")");
			return returnCode;
		} finally {
			if (!windowsWebAuthn) {
				interaction.onTouchCompleted();
			}
		}
	}

	private static int attemptGetAssert(final Fido2Native fido, final Pointer dev, final Pointer assertPtr, final String pin, final Fido2Interaction interaction, final boolean windowsWebAuthn) {
		// The Windows WebAuthn API shows its own dialog for touch and PIN, an additional prompt would only confuse
		if (!windowsWebAuthn) {
			interaction.onTouchRequired();
		}
		try {
			debugLog("fido_dev_get_assert started");
			final int returnCode = fido.fido_dev_get_assert(dev, assertPtr, pin);
			debugLog("fido_dev_get_assert returned " + returnCode + " (" + fido.fido_strerr(returnCode) + ")");
			return returnCode;
		} finally {
			if (!windowsWebAuthn) {
				interaction.onTouchCompleted();
			}
		}
	}

	private static boolean isUserVerification(final Fido2VerificationMode verificationMode) {
		if (verificationMode == null) {
			throw new IllegalArgumentException("Verification mode must not be null");
		}
		return verificationMode == Fido2VerificationMode.USER_VERIFICATION;
	}

	/**
	 * Value for fido_cred_set_uv() / fido_assert_set_uv(). The Windows WebAuthn
	 * API needs an explicit setting ("required" or "discouraged"); "discouraged"
	 * is only honored without the hmac-secret extension (credential creation,
	 * finding the matching credential), see getHmacSecret(). With direct
	 * access the "uv" option is omitted: user verification is done via the PIN
	 * (pinUvAuthParam), and tokens without built-in UV (fingerprint) reject an
	 * explicit "uv" option.
	 */
	private static int getUvOption(final boolean windowsWebAuthn, final boolean userVerification) {
		if (windowsWebAuthn) {
			return userVerification ? Fido2Native.FIDO_OPT_TRUE : Fido2Native.FIDO_OPT_FALSE;
		} else {
			return Fido2Native.FIDO_OPT_OMIT;
		}
	}

	private static String requirePin(final Fido2Interaction interaction, final String message) {
		final String pin = interaction.requestPin();
		if (pin == null) {
			throw new Fido2PinRequiredException(message, false);
		}
		return pin;
	}

	/** A wrong PIN is reported as FIDO_ERR_PIN_INVALID (or blocked variants), not as FIDO_ERR_PIN_REQUIRED */
	private static boolean isPinInvalid(final Fido2Native fido, final int returnCode) {
		final String errorName = fido.fido_strerr(returnCode);
		return "FIDO_ERR_PIN_INVALID".equals(errorName) || "FIDO_ERR_PIN_AUTH_INVALID".equals(errorName);
	}

	/** fido_dev_close() only for an opened device, fido_dev_free() always */
	private static void closeAndFree(final Fido2Native fido, final Pointer dev, final boolean opened) {
		if (opened) {
			fido.fido_dev_close(dev);
		}
		fido.fido_dev_free(new PointerByReference(dev));
	}

	private static void checkResult(final int returnCode, final String operationName) {
		if (returnCode != Fido2Native.FIDO_OK) {
			throw new Fido2Exception(operationName + " failed: " + Fido2Native.INSTANCE.fido_strerr(returnCode));
		}
	}

	private static byte[] randomBytes(final int length) {
		final byte[] bytes = new byte[length];
		SECURE_RANDOM.nextBytes(bytes);
		return bytes;
	}

	/**
	 * Creates client data in the JSON structure of WebAuthn with a random
	 * challenge. Its content is not checked by anybody (there is no server),
	 * but the Windows WebAuthn API needs real client data instead of only
	 * its hash. It does not influence the hmac-secret.
	 *
	 * @param type "webauthn.create" or "webauthn.get"
	 * @param origin origin (the relying party id), JSON-escaped here
	 * @return the UTF-8 encoded client data JSON
	 */
	private static byte[] createClientData(final String type, final String origin) {
		return createClientData(type, origin, randomBytes(32));
	}

	/**
	 * Creates client data in the JSON structure of WebAuthn with the given
	 * challenge.
	 *
	 * @param type "webauthn.create" or "webauthn.get"
	 * @param origin origin (the relying party id), JSON-escaped here
	 * @param challengeBytes the challenge, base64url-encoded into the JSON
	 * @return the UTF-8 encoded client data JSON
	 */
	static byte[] createClientData(final String type, final String origin, final byte[] challengeBytes) {
		final String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);
		final String escapedOrigin = origin.replace("\\", "\\\\").replace("\"", "\\\"");
		final String clientDataJson = "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + escapedOrigin + "\",\"crossOrigin\":false}";
		return clientDataJson.getBytes(StandardCharsets.UTF_8);
	}
}
