package de.soderer.fido2;

/**
 * Result of Fido2Utilities.checkAvailability().
 */
public final class Fido2Availability {
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

	Fido2Availability(final State state, final String detail) {
		this.state = state;
		this.detail = detail;
	}

	public State getState() {
		return state;
	}

	public boolean isReady() {
		return state == State.READY;
	}

	/** Technical detail (e.g. the message of the loading error), may be null */
	public String getDetail() {
		return detail;
	}

	@Override
	public String toString() {
		return detail == null ? state.name() : state.name() + ": " + detail;
	}
}
