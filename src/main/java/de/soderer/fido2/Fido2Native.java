package de.soderer.fido2;

import com.sun.jna.Callback;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

/**
 * Low-level JNA binding for the native libfido2 library.
 *
 * This interface only declares the functions of the libfido2 C API that are
 * needed for this project. All fido_*_t types (fido_dev_t, fido_cred_t,
 * fido_assert_t, fido_dev_info_t) are opaque structures in libfido2 that are
 * only ever accessed via pointers and their associated functions. From a JNA
 * perspective, the generic Pointer type is sufficient for this.
 *
 * INTERNAL: Only to be used by the classes of this package. Applications use
 * {@link Fido2Utilities} instead. This interface (like {@link SizeT}) is only
 * public because JNA needs reflective access to it and its callback type.
 *
 * All C "size_t" parameters and return values are mapped to {@link SizeT}
 * (8 bytes on 64-bit systems), never to int.
 *
 * Unless stated otherwise, functions returning "int" return {@link #FIDO_OK}
 * on success or a FIDO_ERR_* error code, which can be translated with
 * {@link #fido_strerr(int)}.
 */
public interface Fido2Native extends Library {

	/**
	 * On Windows, the bundled native DLLs are extracted first (see
	 * Fido2WindowsSupport.extractBundledLibrariesIfNeeded()). A method call
	 * is used because interfaces cannot have static initializer blocks.
	 */
	private static Fido2Native loadInstance() {
		Fido2WindowsSupport.extractBundledLibrariesIfNeeded();
		return Native.load("fido2", Fido2Native.class);
	}

	/**
	 * The loaded native library. Loaded on first access of this interface; if
	 * libfido2 cannot be loaded, that access fails with an
	 * {@link ExceptionInInitializerError} (caused by an
	 * {@link UnsatisfiedLinkError}).
	 */
	Fido2Native INSTANCE = loadInstance();

	/** Return code for success */
	int FIDO_OK = 0;

	/** Returned by fido_dev_make_cred()/fido_dev_get_assert() when the token requires its PIN to be supplied for this operation. */
	int FIDO_ERR_PIN_REQUIRED = 0x36;

	/** Extension flag for the hmac-secret extension (fido_cred_set_extensions(), fido_assert_set_extensions()) */
	int FIDO_EXT_HMAC_SECRET = 0x0001;

	/** COSE algorithm identifier for ECDSA with P-256 and SHA-256 */
	int COSE_ES256 = -7;

	// ---- Init ----

	/**
	 * Initializes libfido2, must be called once before any other function.
	 *
	 * @param flags 0 or {@link #FIDO_DEBUG}
	 */
	void fido_init(int flags);

	/** Flag for fido_init(): enables the debug log of libfido2. */
	int FIDO_DEBUG = 0x01;

	/** Receives the debug log lines of libfido2 (fido_log_handler_t). */
	interface LogHandler extends Callback {
		/**
		 * Called by libfido2 for every debug log line.
		 *
		 * @param message the log line
		 */
		void invoke(String message);
	}

	/**
	 * Redirects the debug log of libfido2, which otherwise is written to stderr.
	 * The caller must keep a strong reference to the handler as long as
	 * libfido2 may call it.
	 *
	 * @param handler the new log handler
	 */
	void fido_set_log_handler(LogHandler handler);

	// ---- Device enumeration ----

	/**
	 * Allocates a list of device information entries.
	 *
	 * @param n number of entries
	 * @return the list, or null on memory error
	 */
	Pointer fido_dev_info_new(SizeT n);

	/**
	 * Frees a list allocated by {@link #fido_dev_info_new(SizeT)}.
	 *
	 * @param devList reference to the list pointer
	 * @param n number of entries the list was allocated with
	 */
	void fido_dev_info_free(PointerByReference devList, SizeT n);

	/**
	 * Fills the list with the connected FIDO devices.
	 *
	 * devCountOut is a "size_t *": libfido2 writes Native.SIZE_T_SIZE (8) bytes into it.
	 * A 4-byte int[1] here caused a heap overflow (memory corruption, later SIGSEGV).
	 *
	 * @param devList list allocated by {@link #fido_dev_info_new(SizeT)}
	 * @param devListLen capacity of the list
	 * @param devCountOut receives the number of entries filled
	 * @return FIDO_OK or an error code
	 */
	int fido_dev_info_manifest(Pointer devList, SizeT devListLen, SizeT.ByRef devCountOut);

	/**
	 * Returns an entry of the device list.
	 *
	 * @param devList the device list
	 * @param index 0-based index of the entry
	 * @return pointer to the entry, only valid until the list is freed
	 */
	Pointer fido_dev_info_ptr(Pointer devList, SizeT index);

	/**
	 * Returns the path of a device, used for {@link #fido_dev_open(Pointer, String)}.
	 *
	 * @param devInfoEntry entry of the device list
	 * @return the device path, e.g. "/dev/hidraw3" or "windows://hello"
	 */
	String fido_dev_info_path(Pointer devInfoEntry);

	/**
	 * Returns the manufacturer of a device.
	 *
	 * @param devInfoEntry entry of the device list
	 * @return the manufacturer string, may be null or empty
	 */
	String fido_dev_info_manufacturer_string(Pointer devInfoEntry);

	/**
	 * Returns the product name of a device.
	 *
	 * @param devInfoEntry entry of the device list
	 * @return the product string, may be null or empty
	 */
	String fido_dev_info_product_string(Pointer devInfoEntry);

	// ---- Device handling ----

	/**
	 * Allocates a device handle.
	 *
	 * @return the handle, or null on memory error
	 */
	Pointer fido_dev_new();

	/**
	 * Frees a device handle allocated by {@link #fido_dev_new()}.
	 *
	 * @param dev reference to the handle pointer
	 */
	void fido_dev_free(PointerByReference dev);

	/**
	 * Opens the device with the given path.
	 *
	 * @param dev device handle
	 * @param path device path from {@link #fido_dev_info_path(Pointer)}
	 * @return FIDO_OK or an error code
	 */
	int fido_dev_open(Pointer dev, String path);

	/**
	 * Closes an opened device.
	 *
	 * @param dev device handle
	 * @return FIDO_OK or an error code
	 */
	int fido_dev_close(Pointer dev);

	/**
	 * Returns non-zero if the opened device supports FIDO2 (CTAP2). C "bool"
	 * (1 byte), see fido_dev_has_pin().
	 *
	 * @param dev opened device handle
	 * @return non-zero if FIDO2 is supported
	 */
	byte fido_dev_is_fido2(Pointer dev);

	/**
	 * Returns non-zero if the device has a PIN set, zero if not. This is a C
	 * "bool" (stdbool.h) return value, which is exactly 1 byte. It is
	 * deliberately declared here as "byte", NOT as a JNA "boolean" (which
	 * defaults to a 4-byte Win32 BOOL-style mapping): reading 4 bytes for a
	 * native function that only ever sets 1 byte picks up undefined
	 * register/stack content in the remaining 3 bytes, which can silently
	 * misread the actual flag depending on platform/compiler/ABI (observed
	 * on Windows; apparently coincidentally correct on Linux). Callers must
	 * compare the result against 0 themselves, e.g.
	 * "fido_dev_has_pin(dev) != 0".
	 * Reads a capability flag already retrieved during fido_dev_open(), so
	 * this requires no user interaction (no touch/activation prompt).
	 *
	 * @param dev opened device handle
	 * @return non-zero if a PIN is set
	 */
	byte fido_dev_has_pin(Pointer dev);

	/**
	 * Returns non-zero if dev is the Windows Hello platform-authenticator
	 * pseudo-device (i.e. its path is "windows://hello"), zero otherwise.
	 * Same "bool" (stdbool.h, 1 byte) return type consideration as
	 * fido_dev_has_pin() applies here: deliberately declared as "byte", not
	 * as a JNA "boolean". Callers must compare against 0 themselves, e.g.
	 * "fido_dev_is_winhello(dev) != 0".
	 *
	 * On Windows, fido_dev_info_manifest() always reports this pseudo-device
	 * in addition to (or, without elevated/administrator rights, instead
	 * of) any real FIDO2 USB/HID tokens. It does not represent a roaming
	 * USB authenticator at all, and does not support an application-
	 * supplied PIN (Windows shows its own system PIN/biometric prompt), so
	 * this application must filter it out of the regular token selection
	 * (see LibFido2.listDevices()).
	 *
	 * No-op on non-Windows systems (no such device is ever reported there).
	 *
	 * @param dev opened device handle
	 * @return non-zero for the Windows WebAuthn pseudo-device
	 */
	byte fido_dev_is_winhello(Pointer dev);

	// ---- Credential (fido_cred_t) ----

	/**
	 * Allocates a credential.
	 *
	 * @return the credential, or null on memory error
	 */
	Pointer fido_cred_new();

	/**
	 * Frees a credential allocated by {@link #fido_cred_new()}.
	 *
	 * @param cred reference to the credential pointer
	 */
	void fido_cred_free(PointerByReference cred);

	/**
	 * Sets the key type of the credential.
	 *
	 * @param cred the credential
	 * @param cose_type COSE algorithm, e.g. {@link #COSE_ES256}
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_set_type(Pointer cred, int cose_type);

	/**
	 * Sets the hash of the client data.
	 *
	 * @param cred the credential
	 * @param ptr SHA-256 hash of the client data
	 * @param len length of ptr
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_set_clientdata_hash(Pointer cred, byte[] ptr, SizeT len);

	/**
	 * Sets the client data itself, libfido2 calculates its hash. Unlike
	 * fido_cred_set_clientdata_hash() this also works with the Windows
	 * WebAuthn API backend ("windows://hello"), which needs the client data
	 * and calculates the hash itself.
	 *
	 * @param cred the credential
	 * @param ptr the client data
	 * @param len length of ptr
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_set_clientdata(Pointer cred, byte[] ptr, SizeT len);

	/**
	 * Sets the relying party.
	 *
	 * @param cred the credential
	 * @param id relying party id
	 * @param name relying party display name, may be null
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_set_rp(Pointer cred, String id, String name);

	/**
	 * Sets the user the credential is created for.
	 *
	 * @param cred the credential
	 * @param userId user handle
	 * @param userIdLen length of userId
	 * @param name user name
	 * @param displayName user display name, may be null
	 * @param icon user icon URL, may be null
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_set_user(Pointer cred, byte[] userId, SizeT userIdLen, String name, String displayName, String icon);

	/**
	 * Enables extensions for the credential.
	 *
	 * @param cred the credential
	 * @param flags e.g. {@link #FIDO_EXT_HMAC_SECRET}
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_set_extensions(Pointer cred, int flags);

	/**
	 * Sets whether a resident key (discoverable credential) is created.
	 *
	 * @param cred the credential
	 * @param onOrOff {@link #FIDO_OPT_OMIT}, {@link #FIDO_OPT_FALSE} or {@link #FIDO_OPT_TRUE}
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_set_rk(Pointer cred, int onOrOff);

	/**
	 * Sets whether user verification is required.
	 *
	 * @param cred the credential
	 * @param onOrOff {@link #FIDO_OPT_OMIT}, {@link #FIDO_OPT_FALSE} or {@link #FIDO_OPT_TRUE}
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_set_uv(Pointer cred, int onOrOff);

	/**
	 * Creates the credential on the device. Blocks until the user touched
	 * the token (or a timeout occurs).
	 *
	 * @param dev opened device handle
	 * @param cred the prepared credential, filled on success
	 * @param pin the token's PIN, or null
	 * @return FIDO_OK, {@link #FIDO_ERR_PIN_REQUIRED} or another error code
	 */
	int fido_dev_make_cred(Pointer dev, Pointer cred, String pin);

	/**
	 * Verifies the attestation signature of a created credential.
	 *
	 * @param cred the created credential
	 * @return FIDO_OK or an error code
	 */
	int fido_cred_verify(Pointer cred);

	/**
	 * Returns the id of a created credential.
	 *
	 * @param cred the created credential
	 * @return pointer to the id, only valid until the credential is freed
	 */
	Pointer fido_cred_id_ptr(Pointer cred);

	/**
	 * Returns the length of the id of a created credential.
	 *
	 * @param cred the created credential
	 * @return length in bytes
	 */
	SizeT fido_cred_id_len(Pointer cred);

	// ---- Assertion (fido_assert_t) ----

	/**
	 * Allocates an assertion.
	 *
	 * @return the assertion, or null on memory error
	 */
	Pointer fido_assert_new();

	/**
	 * Frees an assertion allocated by {@link #fido_assert_new()}.
	 *
	 * @param assertPtr reference to the assertion pointer
	 */
	void fido_assert_free(PointerByReference assertPtr);

	/**
	 * Sets the relying party id.
	 *
	 * @param assertPtr the assertion
	 * @param id relying party id
	 * @return FIDO_OK or an error code
	 */
	int fido_assert_set_rp(Pointer assertPtr, String id);

	/**
	 * Sets the hash of the client data.
	 *
	 * @param assertPtr the assertion
	 * @param ptr SHA-256 hash of the client data
	 * @param len length of ptr
	 * @return FIDO_OK or an error code
	 */
	int fido_assert_set_clientdata_hash(Pointer assertPtr, byte[] ptr, SizeT len);

	/**
	 * Sets the client data itself. See fido_cred_set_clientdata().
	 *
	 * @param assertPtr the assertion
	 * @param ptr the client data
	 * @param len length of ptr
	 * @return FIDO_OK or an error code
	 */
	int fido_assert_set_clientdata(Pointer assertPtr, byte[] ptr, SizeT len);

	/**
	 * Adds a credential id to the allow list of the assertion. May be called
	 * several times, the token then uses whichever credential belongs to it.
	 *
	 * @param assertPtr the assertion
	 * @param credId credential id
	 * @param credIdLen length of credId
	 * @return FIDO_OK or an error code
	 */
	int fido_assert_allow_cred(Pointer assertPtr, byte[] credId, SizeT credIdLen);

	/**
	 * Enables extensions for the assertion.
	 *
	 * @param assertPtr the assertion
	 * @param flags e.g. {@link #FIDO_EXT_HMAC_SECRET}
	 * @return FIDO_OK or an error code
	 */
	int fido_assert_set_extensions(Pointer assertPtr, int flags);

	/**
	 * Sets the salt for the hmac-secret extension.
	 *
	 * @param assertPtr the assertion
	 * @param salt 32 byte salt
	 * @param saltLen length of salt
	 * @return FIDO_OK or an error code
	 */
	int fido_assert_set_hmac_salt(Pointer assertPtr, byte[] salt, SizeT saltLen);

	/**
	 * Sets whether user presence (touch) is required.
	 *
	 * @param assertPtr the assertion
	 * @param onOrOff {@link #FIDO_OPT_OMIT}, {@link #FIDO_OPT_FALSE} or {@link #FIDO_OPT_TRUE}
	 * @return FIDO_OK or an error code
	 */
	int fido_assert_set_up(Pointer assertPtr, int onOrOff);

	/**
	 * Sets whether user verification is required.
	 *
	 * @param assertPtr the assertion
	 * @param onOrOff {@link #FIDO_OPT_OMIT}, {@link #FIDO_OPT_FALSE} or {@link #FIDO_OPT_TRUE}
	 * @return FIDO_OK or an error code
	 */
	int fido_assert_set_uv(Pointer assertPtr, int onOrOff);

	/**
	 * Obtains the assertion from the device. Blocks until the user touched
	 * the token (or a timeout occurs).
	 *
	 * @param dev opened device handle
	 * @param assertPtr the prepared assertion, filled on success
	 * @param pin the token's PIN, or null
	 * @return FIDO_OK, {@link #FIDO_ERR_PIN_REQUIRED} or another error code
	 */
	int fido_dev_get_assert(Pointer dev, Pointer assertPtr, String pin);

	/**
	 * Returns the number of assertion statements.
	 *
	 * @param assertPtr the obtained assertion
	 * @return number of statements
	 */
	SizeT fido_assert_count(Pointer assertPtr);

	/**
	 * Returns the hmac-secret of an assertion statement.
	 *
	 * @param assertPtr the obtained assertion
	 * @param idx 0-based statement index
	 * @return pointer to the secret, only valid until the assertion is freed
	 */
	Pointer fido_assert_hmac_secret_ptr(Pointer assertPtr, SizeT idx);

	/**
	 * Returns the length of the hmac-secret of an assertion statement.
	 *
	 * @param assertPtr the obtained assertion
	 * @param idx 0-based statement index
	 * @return length in bytes, 0 if there is none
	 */
	SizeT fido_assert_hmac_secret_len(Pointer assertPtr, SizeT idx);

	/**
	 * Credential id used by assertion statement idx (the token picks one of
	 * the allowed credentials, so this identifies the matching one).
	 *
	 * @param assertPtr the obtained assertion
	 * @param idx 0-based statement index
	 * @return pointer to the id, only valid until the assertion is freed
	 */
	Pointer fido_assert_id_ptr(Pointer assertPtr, SizeT idx);

	/**
	 * Returns the length of the credential id of an assertion statement.
	 *
	 * @param assertPtr the obtained assertion
	 * @param idx 0-based statement index
	 * @return length in bytes
	 */
	SizeT fido_assert_id_len(Pointer assertPtr, SizeT idx);

	// ---- Error strings ----

	/**
	 * Translates a return code into its name.
	 *
	 * @param errorCode return code of a libfido2 function
	 * @return the name of the code, e.g. "FIDO_ERR_NO_CREDENTIALS"
	 */
	String fido_strerr(int errorCode);

	// ---- Onoff constants used by libfido2 (fido/param.h) ----

	/** fido_opt_t: option is not sent to the token (token default applies) */
	int FIDO_OPT_OMIT = 0;
	/** fido_opt_t: option is explicitly disabled */
	int FIDO_OPT_FALSE = 1;
	/** fido_opt_t: option is explicitly enabled */
	int FIDO_OPT_TRUE = 2;
}
