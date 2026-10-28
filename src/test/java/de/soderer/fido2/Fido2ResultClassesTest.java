package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Tests of the simple value classes Fido2Availability, Fido2HmacSecret and
 * Fido2Token.
 */
@SuppressWarnings("static-method")
public class Fido2ResultClassesTest {
	@Test
	public void testAvailabilityReady() {
		final Fido2Availability availability = new Fido2Availability(Fido2Availability.State.READY, null);
		assertSame(Fido2Availability.State.READY, availability.getState());
		assertTrue(availability.isReady());
		assertNull(availability.getDetail());
		assertEquals("READY", availability.toString());
	}

	@Test
	public void testAvailabilityIsReadyOnlyForStateReady() {
		for (final Fido2Availability.State state : Fido2Availability.State.values()) {
			assertEquals(state == Fido2Availability.State.READY, new Fido2Availability(state, "detail").isReady(), state.name());
		}
	}

	@Test
	public void testAvailabilityWithDetail() {
		final Fido2Availability availability = new Fido2Availability(Fido2Availability.State.LIBRARY_NOT_FOUND, "Unable to load library 'fido2'");
		assertSame(Fido2Availability.State.LIBRARY_NOT_FOUND, availability.getState());
		assertFalse(availability.isReady());
		assertEquals("Unable to load library 'fido2'", availability.getDetail());
		assertEquals("LIBRARY_NOT_FOUND: Unable to load library 'fido2'", availability.toString());
	}

	@Test
	public void testHmacSecret() {
		final byte[] secret = new byte[32];
		final Fido2HmacSecret hmacSecret = new Fido2HmacSecret(2, secret);
		assertEquals(2, hmacSecret.getCredentialIndex());
		// Documented: not copied, so the caller can wipe the original array
		assertSame(secret, hmacSecret.getSecret());
	}

	@Test
	public void testToken() {
		final Fido2Token token = new Fido2Token("/dev/hidraw3", "Yubico YubiKey OTP+FIDO+CCID", List.of("detail 1", "detail 2"), false);
		assertEquals("/dev/hidraw3", token.getId());
		assertEquals("Yubico YubiKey OTP+FIDO+CCID", token.getDisplayName());
		assertEquals(List.of("detail 1", "detail 2"), token.getDetails());
		assertFalse(token.isSystemApi());
		assertEquals("Yubico YubiKey OTP+FIDO+CCID (/dev/hidraw3)", token.toString());
	}

	@Test
	public void testTokenSystemApi() {
		final Fido2Token token = new Fido2Token(LibFido2.WINDOWS_WEBAUTHN_PATH, "Windows WebAuthn", null, true);
		assertTrue(token.isSystemApi());
	}

	@Test
	public void testTokenNullDetailsBecomeEmptyList() {
		final Fido2Token token = new Fido2Token("/dev/hidraw0", "Token", null, false);
		assertTrue(token.getDetails().isEmpty());
	}

	@Test
	public void testTokenDetailsAreUnmodifiableCopy() {
		final List<String> details = new ArrayList<>();
		details.add("original");
		final Fido2Token token = new Fido2Token("/dev/hidraw0", "Token", details, false);

		details.add("added later");
		assertEquals(List.of("original"), token.getDetails());

		assertThrows(UnsupportedOperationException.class, () -> token.getDetails().add("not allowed"));
	}
}
