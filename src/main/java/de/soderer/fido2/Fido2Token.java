package de.soderer.fido2;

import java.util.Collections;
import java.util.List;

/**
 * A usable FIDO2 token, as returned by
 * {@link Fido2Utilities#listTokens(boolean)} or
 * {@link Fido2Utilities#findToken()}.
 *
 * This may be a directly accessed USB/HID token, or an access path provided
 * by the operating system (Windows WebAuthn API, where Windows lets the user
 * select the security key in its own dialog). Callers do not need to
 * distinguish these, {@link Fido2Utilities} handles the differences.
 */
public final class Fido2Token {
	private final String id;
	private final String displayName;
	private final List<String> details;
	private final boolean systemApi;

	/**
	 * Creates a new token description.
	 *
	 * @param id device path as used by libfido2
	 * @param displayName human readable name
	 * @param details additional display information, may be null (stored as
	 *        an unmodifiable copy)
	 * @param systemApi true if the operating system handles touch and PIN
	 *        with its own dialogs
	 */
	Fido2Token(final String id, final String displayName, final List<String> details, final boolean systemApi) {
		this.id = id;
		this.displayName = displayName;
		this.details = details == null ? Collections.emptyList() : List.copyOf(details);
		this.systemApi = systemApi;
	}

	/**
	 * Returns the technical identification, for display and logging only.
	 *
	 * @return e.g. "/dev/hidraw3"
	 */
	public String getId() {
		return id;
	}

	/**
	 * Returns the human readable name.
	 *
	 * @return e.g. "Yubico YubiKey OTP+FIDO+CCID"
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Additional display information, e.g. the security keys detected by the
	 * operating system, if the token is accessed via an operating system API.
	 * Only filled by {@link Fido2Utilities#listTokens(boolean)} with
	 * includeDetails = true, otherwise empty.
	 *
	 * @return unmodifiable list of display lines, never null
	 */
	public List<String> getDetails() {
		return details;
	}

	/**
	 * Tells whether the token is accessed via an operating system API.
	 *
	 * @return true if the operating system handles touch and PIN with its
	 *         own dialogs
	 */
	boolean isSystemApi() {
		return systemApi;
	}

	/**
	 * Returns the display name followed by the id.
	 *
	 * @return e.g. "Yubico YubiKey OTP+FIDO+CCID (/dev/hidraw3)"
	 */
	@Override
	public String toString() {
		return displayName + " (" + id + ")";
	}
}
