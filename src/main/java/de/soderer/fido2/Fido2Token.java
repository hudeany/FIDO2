package de.soderer.fido2;

import java.util.Collections;
import java.util.List;

/**
 * A usable FIDO2 token, as returned by Fido2Utilities.listTokens() or
 * Fido2Utilities.findToken().
 *
 * This may be a directly accessed USB/HID token, or an access path provided
 * by the operating system (Windows WebAuthn API, where Windows lets the user
 * select the security key in its own dialog). Callers do not need to
 * distinguish these, Fido2Utilities handles the differences.
 */
public final class Fido2Token {
	private final String id;
	private final String displayName;
	private final List<String> details;
	private final boolean systemApi;

	Fido2Token(final String id, final String displayName, final List<String> details, final boolean systemApi) {
		this.id = id;
		this.displayName = displayName;
		this.details = details == null ? Collections.emptyList() : List.copyOf(details);
		this.systemApi = systemApi;
	}

	/** Technical identification (e.g. "/dev/hidraw3"), for display and logging only */
	public String getId() {
		return id;
	}

	/** Human readable name, e.g. "Yubico YubiKey OTP+FIDO+CCID" */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Additional display information, e.g. the security keys detected by the
	 * operating system, if the token is accessed via an operating system API.
	 * Only filled by Fido2Utilities.listTokens(true), otherwise empty.
	 */
	public List<String> getDetails() {
		return details;
	}

	/** True if the operating system handles touch and PIN with its own dialogs */
	boolean isSystemApi() {
		return systemApi;
	}

	@Override
	public String toString() {
		return displayName + " (" + id + ")";
	}
}
