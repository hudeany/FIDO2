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
}
