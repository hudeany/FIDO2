package de.soderer.fido2;

import java.util.function.BiConsumer;
import java.util.function.Supplier;

/**
 * Callbacks for the user interaction during a FIDO2 token operation.
 *
 * All methods have no-op defaults, so implementations only override what
 * they need. The methods are called from the thread that runs the token
 * operation (typically a background thread), so GUI implementations must
 * marshal to their UI thread themselves.
 *
 * Operating system specifics are handled by {@link Fido2Utilities}: e.g.
 * when the operating system shows its own dialogs for touch and PIN (Windows
 * WebAuthn API), {@link #onTouchRequired()}/{@link #onTouchCompleted()} and
 * {@link #requestPin()} are simply not called.
 */
public interface Fido2Interaction {
	/** Interaction without any callbacks (no PIN available, no touch notification) */
	Fido2Interaction NONE = new Fido2Interaction() {
		// Only defaults
	};

	/**
	 * Called only if the token actually needs its PIN for the current
	 * operation, at most once per token operation.
	 *
	 * @return the PIN, or null if none is available (e.g. user cancelled),
	 *         which ends the operation with a {@link Fido2PinRequiredException}
	 */
	default String requestPin() {
		return null;
	}

	/** Called immediately before a blocking call that waits for the user to touch the token */
	default void onTouchRequired() {
		// No notification by default
	}

	/** Called immediately after such a blocking call returned, successful or not */
	default void onTouchCompleted() {
		// No notification by default
	}

	/**
	 * Called before a credential of a list of candidate credentials is tried
	 * (see
	 * {@link Fido2Utilities#getHmacSecret(Fido2Token, String, java.util.List, Fido2Interaction)}).
	 *
	 * @param credentialNumber 1-based number of the credential tried now
	 * @param credentialCount number of candidate credentials
	 */
	default void onCredentialAttempt(final int credentialNumber, final int credentialCount) {
		// No notification by default
	}

	/**
	 * Creates an interaction from single callbacks, each of them may be null.
	 *
	 * @param pinSupplier supplies the PIN for {@link #requestPin()}; null
	 *        means no PIN is available
	 * @param onTouchRequired called for {@link #onTouchRequired()}, may be null
	 * @param onTouchCompleted called for {@link #onTouchCompleted()}, may be
	 *        null
	 * @param onCredentialAttempt called with credentialNumber and
	 *        credentialCount for
	 *        {@link #onCredentialAttempt(int, int)}, may be null
	 * @return a new interaction delegating to the given callbacks
	 */
	static Fido2Interaction of(final Supplier<String> pinSupplier, final Runnable onTouchRequired, final Runnable onTouchCompleted, final BiConsumer<Integer, Integer> onCredentialAttempt) {
		return new Fido2Interaction() {
			@Override
			public String requestPin() {
				return pinSupplier != null ? pinSupplier.get() : null;
			}

			@Override
			public void onTouchRequired() {
				if (onTouchRequired != null) {
					onTouchRequired.run();
				}
			}

			@Override
			public void onTouchCompleted() {
				if (onTouchCompleted != null) {
					onTouchCompleted.run();
				}
			}

			@Override
			public void onCredentialAttempt(final int credentialNumber, final int credentialCount) {
				if (onCredentialAttempt != null) {
					onCredentialAttempt.accept(credentialNumber, credentialCount);
				}
			}
		};
	}
}
