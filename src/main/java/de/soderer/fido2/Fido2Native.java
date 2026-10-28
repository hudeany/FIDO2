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
 * Fido2Utilities instead. This interface (like SizeT) is only public because
 * JNA needs reflective access to it and its callback type.
 *
 * All C "size_t" parameters and return values are mapped to SizeT (8 bytes
 * on 64-bit systems), never to int.
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

	Fido2Native INSTANCE = loadInstance();

	int FIDO_OK = 0;

	/** Returned by fido_dev_make_cred()/fido_dev_get_assert() when the token requires its PIN to be supplied for this operation. */
	int FIDO_ERR_PIN_REQUIRED = 0x36;

	int FIDO_EXT_HMAC_SECRET = 0x0001;

	int COSE_ES256 = -7;

	// ---- Init ----

	void fido_init(int flags);

	/** Flag for fido_init(): enables the debug log of libfido2. */
	int FIDO_DEBUG = 0x01;

	/** Receives the debug log lines of libfido2 (fido_log_handler_t). */
	interface LogHandler extends Callback {
		void invoke(String message);
	}

	/** Redirects the debug log of libfido2, which otherwise is written to stderr. */
	void fido_set_log_handler(LogHandler handler);

	// ---- Device enumeration ----

	Pointer fido_dev_info_new(SizeT n);

	void fido_dev_info_free(PointerByReference devList, SizeT n);

	/**
	 * devCountOut is a "size_t *": libfido2 writes Native.SIZE_T_SIZE (8) bytes into it.
	 * A 4-byte int[1] here caused a heap overflow (memory corruption, later SIGSEGV).
	 */
	int fido_dev_info_manifest(Pointer devList, SizeT devListLen, SizeT.ByRef devCountOut);

	Pointer fido_dev_info_ptr(Pointer devList, SizeT index);

	String fido_dev_info_path(Pointer devInfoEntry);

	String fido_dev_info_manufacturer_string(Pointer devInfoEntry);

	String fido_dev_info_product_string(Pointer devInfoEntry);

	// ---- Device handling ----

	Pointer fido_dev_new();

	void fido_dev_free(PointerByReference dev);

	int fido_dev_open(Pointer dev, String path);

	int fido_dev_close(Pointer dev);

	/** C "bool" (1 byte), see fido_dev_has_pin() */
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
	 */
	byte fido_dev_is_winhello(Pointer dev);

	// ---- Credential (fido_cred_t) ----

	Pointer fido_cred_new();

	void fido_cred_free(PointerByReference cred);

	int fido_cred_set_type(Pointer cred, int cose_type);

	int fido_cred_set_clientdata_hash(Pointer cred, byte[] ptr, SizeT len);

	/**
	 * Sets the client data itself, libfido2 calculates its hash. Unlike
	 * fido_cred_set_clientdata_hash() this also works with the Windows
	 * WebAuthn API backend ("windows://hello"), which needs the client data
	 * and calculates the hash itself.
	 */
	int fido_cred_set_clientdata(Pointer cred, byte[] ptr, SizeT len);

	int fido_cred_set_rp(Pointer cred, String id, String name);

	int fido_cred_set_user(Pointer cred, byte[] userId, SizeT userIdLen, String name, String displayName, String icon);

	int fido_cred_set_extensions(Pointer cred, int flags);

	int fido_cred_set_rk(Pointer cred, int onOrOff);

	int fido_cred_set_uv(Pointer cred, int onOrOff);

	int fido_dev_make_cred(Pointer dev, Pointer cred, String pin);

	int fido_cred_verify(Pointer cred);

	Pointer fido_cred_id_ptr(Pointer cred);

	SizeT fido_cred_id_len(Pointer cred);

	// ---- Assertion (fido_assert_t) ----

	Pointer fido_assert_new();

	void fido_assert_free(PointerByReference assertPtr);

	int fido_assert_set_rp(Pointer assertPtr, String id);

	int fido_assert_set_clientdata_hash(Pointer assertPtr, byte[] ptr, SizeT len);

	/** See fido_cred_set_clientdata(). */
	int fido_assert_set_clientdata(Pointer assertPtr, byte[] ptr, SizeT len);

	int fido_assert_allow_cred(Pointer assertPtr, byte[] credId, SizeT credIdLen);

	int fido_assert_set_extensions(Pointer assertPtr, int flags);

	int fido_assert_set_hmac_salt(Pointer assertPtr, byte[] salt, SizeT saltLen);

	int fido_assert_set_up(Pointer assertPtr, int onOrOff);

	int fido_assert_set_uv(Pointer assertPtr, int onOrOff);

	int fido_dev_get_assert(Pointer dev, Pointer assertPtr, String pin);

	SizeT fido_assert_count(Pointer assertPtr);

	Pointer fido_assert_hmac_secret_ptr(Pointer assertPtr, SizeT idx);

	SizeT fido_assert_hmac_secret_len(Pointer assertPtr, SizeT idx);

	/**
	 * Credential id used by assertion statement idx (the token picks one of
	 * the allowed credentials, so this identifies the matching one).
	 */
	Pointer fido_assert_id_ptr(Pointer assertPtr, SizeT idx);

	SizeT fido_assert_id_len(Pointer assertPtr, SizeT idx);

	// ---- Error strings ----

	String fido_strerr(int errorCode);

	// ---- Onoff constants used by libfido2 (fido/param.h) ----

	int FIDO_OPT_OMIT = 0;
	int FIDO_OPT_FALSE = 1;
	int FIDO_OPT_TRUE = 2;
}