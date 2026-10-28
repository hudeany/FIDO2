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
		ensureInitialized();

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
			checkResult(fido.fido_cred_set_extensions(cred, Fido2Native.FIDO_EXT_HMAC_SECRET), "fido_cred_set_extensions");
			// Windows WebAuthn: explicitly no discoverable credential, Windows would otherwise prefer
			// to store it on the token, which needs one of its few storage slots for every encryption
			checkResult(fido.fido_cred_set_rk(cred, windowsWebAuthn ? Fido2Native.FIDO_OPT_FALSE : Fido2Native.FIDO_OPT_OMIT), "fido_cred_set_rk");
			// Windows WebAuthn: explicitly no user verification, otherwise Windows uses "preferred" and
			// forces the user to set a PIN on tokens without one
			checkResult(fido.fido_cred_set_uv(cred, windowsWebAuthn ? Fido2Native.FIDO_OPT_FALSE : Fido2Native.FIDO_OPT_OMIT), "fido_cred_set_uv");

			// Local capability check (no touch needed): with a PIN set, ask for it right away instead
			// of a doomed first attempt without PIN. The Windows WebAuthn API asks for the PIN itself.
			final boolean hasPin = !windowsWebAuthn && fido.fido_dev_has_pin(dev) != 0;

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
			return credIdPtr.getByteArray(0, credIdLen);
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
		ensureInitialized();

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
			// Windows WebAuthn: explicitly no user verification, otherwise Windows asks for the PIN ("preferred"), and the
			// token then derives a different hmac-secret than with direct access without PIN (files would not be compatible)
			checkResult(fido.fido_assert_set_uv(assertPtr, windowsWebAuthn ? Fido2Native.FIDO_OPT_FALSE : Fido2Native.FIDO_OPT_OMIT), "fido_assert_set_uv");

			// Most tokens hand out the hmac-secret on touch only, so try without PIN first
			returnCode = attemptGetAssert(fido, dev, assertPtr, null, interaction, windowsWebAuthn);
			if (returnCode == Fido2Native.FIDO_ERR_PIN_REQUIRED) {
				final String pin = requirePin(interaction, "Retrieving the HMAC secret requires the token's PIN.");
				returnCode = attemptGetAssert(fido, dev, assertPtr, pin, interaction, windowsWebAuthn);
				if (returnCode == Fido2Native.FIDO_ERR_PIN_REQUIRED || isPinInvalid(fido, returnCode)) {
					throw new Fido2PinRequiredException("Retrieving the HMAC secret failed: the given PIN was rejected by the token.", true);
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
		final String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(32));
		final String escapedOrigin = origin.replace("\\", "\\\\").replace("\"", "\\\"");
		final String clientDataJson = "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge + "\",\"origin\":\"" + escapedOrigin + "\",\"crossOrigin\":false}";
		return clientDataJson.getBytes(StandardCharsets.UTF_8);
	}
}
