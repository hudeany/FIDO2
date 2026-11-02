package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Integration test with a real FIDO2 token. Disabled by default, because it
 * needs a plugged in token with hmac-secret support and several touches.
 *
 * Enable with the system property "fido2.hardwareTest=true". If the token has
 * a PIN set, pass it with the system property "fido2.pin".
 *
 * Note: on Windows without administrator rights, Windows shows its own
 * dialogs (and an error dialog for the non-matching credential).
 */
@SuppressWarnings("static-method")
@EnabledIfSystemProperty(named = "fido2.hardwareTest", matches = "true")
public class Fido2HardwareTest {
	private static final String RELYING_PARTY_ID = "de.soderer.fido2.test";

	@Test
	public void testCredentialAndHmacSecretRoundTrip() {
		final Fido2Availability availability = Fido2Utilities.checkAvailability();
		assertTrue(availability.isReady(), availability.toString());

		final Fido2Token token = Fido2Utilities.findToken();
		System.out.println("FIDO2 hardware test with token: " + token);
		final Fido2Interaction interaction = Fido2Interaction.of(
				() -> System.getProperty("fido2.pin"),
				() -> System.out.println("Please touch the token ..."),
				null,
				(credentialNumber, credentialCount) -> System.out.println("Trying credential " + credentialNumber + " of " + credentialCount));

		final byte[] credentialId = Fido2Utilities.createCredential(token, RELYING_PARTY_ID, "junit", interaction);
		assertTrue(credentialId.length > 0);

		// Same credential and salt always give the same secret
		final byte[] salt = Fido2Utilities.generateSalt();
		final byte[] firstSecret = Fido2Utilities.getHmacSecret(token, RELYING_PARTY_ID, credentialId, salt, interaction);
		final byte[] secondSecret = Fido2Utilities.getHmacSecret(token, RELYING_PARTY_ID, credentialId, salt, interaction);
		assertEquals(32, firstSecret.length);
		assertArrayEquals(firstSecret, secondSecret);

		// Another salt gives another secret
		final byte[] otherSecret = Fido2Utilities.getHmacSecret(token, RELYING_PARTY_ID, credentialId, Fido2Utilities.generateSalt(), interaction);
		assertFalse(Arrays.equals(firstSecret, otherSecret));

		// The matching credential is found among foreign ones
		final byte[] foreignCredentialId = Fido2Utilities.generateSalt();
		final Fido2HmacSecret hmacSecret = Fido2Utilities.getHmacSecret(token, RELYING_PARTY_ID, List.of(
				new Fido2Credential(foreignCredentialId, Fido2Utilities.generateSalt(), "foreign token"),
				new Fido2Credential(credentialId, salt, token.getDisplayName())), interaction);
		assertEquals(1, hmacSecret.getCredentialIndex());
		assertArrayEquals(firstSecret, hmacSecret.getSecret());

		// A foreign credential alone does not match
		assertThrows(Fido2NoMatchingCredentialException.class,
				() -> Fido2Utilities.getHmacSecret(token, RELYING_PARTY_ID, foreignCredentialId, salt, interaction));
	}

	@Test
	public void testSignatureRoundTrip() {
		final Fido2Availability availability = Fido2Utilities.checkAvailability();
		assertTrue(availability.isReady(), availability.toString());

		final Fido2Token token = Fido2Utilities.findToken();
		System.out.println("FIDO2 signature hardware test with token: " + token);
		final Fido2Interaction interaction = Fido2Interaction.of(
				() -> System.getProperty("fido2.pin"),
				() -> System.out.println("Please touch the token ..."),
				null,
				null);

		final Fido2Registration registration = Fido2Utilities.register(token, RELYING_PARTY_ID, "junit", interaction, Fido2VerificationMode.USER_PRESENCE);
		assertTrue(registration.getCredentialId().length > 0);

		// User presence only: also works via the Windows WebAuthn API, without PIN
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final byte[] foreignCredentialId = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = Fido2Utilities.authenticate(token, RELYING_PARTY_ID, List.of(foreignCredentialId, registration.getCredentialId()), challenge, interaction,
				Fido2VerificationMode.USER_PRESENCE);
		assertEquals(1, assertion.getCredentialIndex());
		assertArrayEquals(registration.getCredentialId(), assertion.getCredentialId());
		assertTrue(assertion.isUserPresent());
		assertTrue(Fido2Utilities.verifyAssertion(assertion, registration.getPublicKey(), RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));

		// The signature is bound to the challenge and relying party
		assertFalse(Fido2Utilities.verifyAssertion(assertion, registration.getPublicKey(), RELYING_PARTY_ID, Fido2Utilities.generateChallenge(), Fido2VerificationMode.USER_PRESENCE));
		assertFalse(Fido2Utilities.verifyAssertion(assertion, registration.getPublicKey(), "other.relying.party", challenge, Fido2VerificationMode.USER_PRESENCE));

		// User verification, only if a PIN is given (Windows WebAuthn asks itself)
		if (System.getProperty("fido2.pin") != null || token.isSystemApi()) {
			final byte[] verifiedChallenge = Fido2Utilities.generateChallenge();
			final Fido2Assertion verifiedAssertion = Fido2Utilities.authenticate(token, RELYING_PARTY_ID, List.of(registration.getCredentialId()), verifiedChallenge, interaction,
					Fido2VerificationMode.USER_VERIFICATION);
			assertTrue(verifiedAssertion.isUserVerified());
			assertTrue(Fido2Utilities.verifyAssertion(verifiedAssertion, registration.getPublicKey(), RELYING_PARTY_ID, verifiedChallenge, Fido2VerificationMode.USER_VERIFICATION));
		}

		// A foreign credential alone does not match
		assertThrows(Fido2NoMatchingCredentialException.class,
				() -> Fido2Utilities.authenticate(token, RELYING_PARTY_ID, List.of(foreignCredentialId), Fido2Utilities.generateChallenge(), interaction, Fido2VerificationMode.USER_PRESENCE));
	}
}
