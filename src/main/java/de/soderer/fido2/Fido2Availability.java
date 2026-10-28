package de.soderer.fido2;

/**
 * Result of {@link Fido2Utilities#checkAvailability()}.
 */
public final class Fido2Availability {
	/**
	 * Whether FIDO2 tokens can be used, and if not, why.
	 */
	public enum State {
		/** FIDO2 tokens can be used */
		READY,

		/** The native libfido2 library was not found (e.g. package "libfido2-1" not installed on Linux) */
		LIBRARY_NOT_FOUND,

		/** The native libfido2 library was found, but could not be loaded */
		LIBRARY_LOAD_ERROR,

		/**
		 * The library is available, but the operating system does not allow
		 * access to FIDO2 tokens for this process (Windows before 10 1903
		 * without administrator rights)
		 */
		NO_TOKEN_ACCESS
	}

	private final State state;
	private final String detail;

	/**
	 * Creates a new availability result.
	 *
	 * @param state the availability state
	 * @param detail technical detail, may be null
	 */
	Fido2Availability(final State state, final String detail) {
		this.state = state;
		this.detail = detail;
	}

	/**
	 * Returns the availability state.
	 *
	 * @return the state, never null
	 */
	public State getState() {
		return state;
	}

	/**
	 * Shortcut for {@code getState() == State.READY}.
	 *
	 * @return true if FIDO2 tokens can be used
	 */
	public boolean isReady() {
		return state == State.READY;
	}

	/**
	 * Returns a technical detail, e.g. the message of the loading error.
	 *
	 * @return the detail, may be null
	 */
	public String getDetail() {
		return detail;
	}

	/**
	 * Returns the state name, followed by the detail if there is one.
	 *
	 * @return e.g. "READY" or "LIBRARY_NOT_FOUND: Unable to load library 'fido2'"
	 */
	@Override
	public String toString() {
		return detail == null ? state.name() : state.name() + ": " + detail;
	}
}
