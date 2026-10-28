package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class Fido2ExceptionTest {
	@Test
	public void testFido2Exception() {
		final Fido2Exception exception = new Fido2Exception("message");
		assertEquals("message", exception.getMessage());
		assertNull(exception.getCause());
	}

	@Test
	public void testFido2ExceptionWithCause() {
		final UnsatisfiedLinkError cause = new UnsatisfiedLinkError("libfido2 missing");
		final Fido2Exception exception = new Fido2Exception("message", cause);
		assertEquals("message", exception.getMessage());
		assertSame(cause, exception.getCause());
	}

	@Test
	public void testPinRequiredWithoutPin() {
		final Fido2PinRequiredException exception = new Fido2PinRequiredException("PIN needed", false);
		assertEquals("PIN needed", exception.getMessage());
		assertFalse(exception.isPinWasAlreadyAttempted());
	}

	@Test
	public void testPinRequiredAfterWrongPin() {
		final Fido2PinRequiredException exception = new Fido2PinRequiredException("PIN wrong", true);
		assertTrue(exception.isPinWasAlreadyAttempted());
	}

	@Test
	public void testNoMatchingCredential() {
		final Fido2NoMatchingCredentialException exception = new Fido2NoMatchingCredentialException("wrong token");
		assertEquals("wrong token", exception.getMessage());
	}
}
