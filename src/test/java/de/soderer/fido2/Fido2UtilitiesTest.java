package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Tests of Fido2Utilities that need no FIDO2 token. They work with and
 * without an installed native libfido2 library: tests that depend on it are
 * skipped by assumptions.
 */
@SuppressWarnings("static-method")
public class Fido2UtilitiesTest {
	private static final Fido2Token DUMMY_TOKEN = new Fido2Token("/dev/null", "Dummy token", null, false);

	@Test
	public void testSaltLength() {
		assertEquals(32, Fido2Utilities.HMAC_SALT_LENGTH);
		assertEquals(Fido2Utilities.HMAC_SALT_LENGTH, Fido2Utilities.generateSalt().length);
	}

	@Test
	public void testGeneratedSaltsAreRandom() {
		final byte[] firstSalt = Fido2Utilities.generateSalt();
		final byte[] secondSalt = Fido2Utilities.generateSalt();
		assertNotSame(firstSalt, secondSalt);
		assertFalse(Arrays.equals(firstSalt, secondSalt));
		assertFalse(Arrays.equals(new byte[Fido2Utilities.HMAC_SALT_LENGTH], firstSalt));
	}

	@Test
	public void testGeneratedSaltIsAcceptedByCredential() {
		assertDoesNotThrow(() -> new Fido2Credential(new byte[] { 1 }, Fido2Utilities.generateSalt(), null));
	}

	@Test
	public void testCreateCredentialRejectsNullArguments() {
		assertEquals("token", assertThrows(NullPointerException.class, () -> Fido2Utilities.createCredential(null, "rp", "user", null)).getMessage());
		assertEquals("relyingPartyId", assertThrows(NullPointerException.class, () -> Fido2Utilities.createCredential(DUMMY_TOKEN, null, "user", null)).getMessage());
		assertEquals("userName", assertThrows(NullPointerException.class, () -> Fido2Utilities.createCredential(DUMMY_TOKEN, "rp", null, null)).getMessage());
	}

	@Test
	public void testGetHmacSecretRejectsInvalidArguments() {
		final byte[] credentialId = new byte[] { 1, 2, 3 };
		final byte[] salt = Fido2Utilities.generateSalt();

		assertThrows(NullPointerException.class, () -> Fido2Utilities.getHmacSecret(null, "rp", credentialId, salt, null));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.getHmacSecret(DUMMY_TOKEN, null, credentialId, salt, null));
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.getHmacSecret(DUMMY_TOKEN, "rp", null, salt, null));
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.getHmacSecret(DUMMY_TOKEN, "rp", credentialId, new byte[16], null));
	}

	@Test
	public void testGetHmacSecretRejectsMissingCandidates() {
		final List<Fido2Credential> candidates = List.of(new Fido2Credential(new byte[] { 1 }, Fido2Utilities.generateSalt(), null));

		assertThrows(NullPointerException.class, () -> Fido2Utilities.getHmacSecret(null, "rp", candidates, null));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.getHmacSecret(DUMMY_TOKEN, null, candidates, null));
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.getHmacSecret(DUMMY_TOKEN, "rp", null, null));
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.getHmacSecret(DUMMY_TOKEN, "rp", new ArrayList<>(), null));
	}

	@Test
	public void testCheckAvailabilityNeverThrowsAndIsStable() {
		final Fido2Availability firstAvailability = assertDoesNotThrow(Fido2Utilities::checkAvailability);
		assertNotNull(firstAvailability);
		assertNotNull(firstAvailability.getState());
		assertSame(firstAvailability.getState(), Fido2Utilities.checkAvailability().getState());
	}

	@Test
	public void testOperationsFailCleanlyWithoutLibrary() {
		final Fido2Availability availability = Fido2Utilities.checkAvailability();
		assumeFalse(availability.isReady(), "Only without usable native libfido2 library");
		assumeTrue(availability.getState() == Fido2Availability.State.LIBRARY_NOT_FOUND || availability.getState() == Fido2Availability.State.LIBRARY_LOAD_ERROR,
				"Only if the native library could not be loaded");

		final Fido2Exception listException = assertThrows(Fido2Exception.class, () -> Fido2Utilities.listTokens(false));
		assertTrue(listException.getMessage().contains(availability.getDetail()), listException.getMessage());

		assertThrows(Fido2Exception.class, Fido2Utilities::findToken);
		assertThrows(Fido2Exception.class, () -> Fido2Utilities.createCredential(DUMMY_TOKEN, "rp", "user", null));
		assertThrows(Fido2Exception.class, () -> Fido2Utilities.getHmacSecret(DUMMY_TOKEN, "rp", new byte[] { 1 }, Fido2Utilities.generateSalt(), null));

		// The cached load failure is reported again, without a new loading attempt
		assertSame(availability, Fido2Utilities.checkAvailability());
	}

	@Test
	public void testListTokensWithLibrary() {
		assumeTrue(Fido2Utilities.checkAvailability().isReady(), "Only with usable native libfido2 library");

		final List<Fido2Token> tokens = assertDoesNotThrow(() -> Fido2Utilities.listTokens(false));
		for (final Fido2Token token : tokens) {
			assertNotNull(token.getId());
			assertNotNull(token.getDisplayName());
			assertTrue(token.getDetails().isEmpty());
		}

		if (tokens.isEmpty()) {
			final Fido2Exception exception = assertThrows(Fido2Exception.class, Fido2Utilities::findToken);
			assertTrue(exception.getMessage().startsWith("No FIDO2 USB token found."), exception.getMessage());
		} else {
			assertEquals(tokens.get(0).getId(), Fido2Utilities.findToken().getId());
		}
	}

	@Test
	public void testLibraryLoadFailureNotFound() throws Exception {
		final Fido2Availability availability = createLibraryLoadFailure(new UnsatisfiedLinkError("Unable to load library 'fido2'"));
		assertSame(Fido2Availability.State.LIBRARY_NOT_FOUND, availability.getState());
		assertEquals("Unable to load library 'fido2'", availability.getDetail());
	}

	@Test
	public void testLibraryLoadFailureUnwrapsInitializerError() throws Exception {
		// Native.load() in the static initializer of Fido2Native is wrapped in an ExceptionInInitializerError
		final Fido2Availability availability = createLibraryLoadFailure(new ExceptionInInitializerError(new UnsatisfiedLinkError("Unable to load library 'fido2'")));
		assertSame(Fido2Availability.State.LIBRARY_NOT_FOUND, availability.getState());
		assertEquals("Unable to load library 'fido2'", availability.getDetail());
	}

	@Test
	public void testLibraryLoadFailureOtherError() throws Exception {
		final Fido2Availability availability = createLibraryLoadFailure(new ExceptionInInitializerError(new IllegalStateException("broken")));
		assertSame(Fido2Availability.State.LIBRARY_LOAD_ERROR, availability.getState());
		assertEquals("broken", availability.getDetail());

		final Fido2Availability otherAvailability = createLibraryLoadFailure(new NoClassDefFoundError("Could not initialize class de.soderer.fido2.Fido2Native"));
		assertSame(Fido2Availability.State.LIBRARY_LOAD_ERROR, otherAvailability.getState());
	}

	@Test
	public void testLibraryLoadFailureWithoutMessage() throws Exception {
		final Fido2Availability availability = createLibraryLoadFailure(new UnsatisfiedLinkError());
		assertSame(Fido2Availability.State.LIBRARY_NOT_FOUND, availability.getState());
		assertEquals("java.lang.UnsatisfiedLinkError", availability.getDetail());
		assertNotEquals("null", availability.getDetail());
	}

	/** Calls the private Fido2Utilities.createLibraryLoadFailure(), which does not touch the cached state */
	private static Fido2Availability createLibraryLoadFailure(final LinkageError error) throws Exception {
		final Method method = Fido2Utilities.class.getDeclaredMethod("createLibraryLoadFailure", LinkageError.class);
		method.setAccessible(true);
		return (Fido2Availability) method.invoke(null, error);
	}
}
