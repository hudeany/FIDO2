package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class Fido2CredentialTest {
	private static byte[] bytes(final int length, final int startValue) {
		final byte[] result = new byte[length];
		for (int i = 0; i < length; i++) {
			result[i] = (byte) (startValue + i);
		}
		return result;
	}

	@Test
	public void testGetters() {
		final byte[] credentialId = bytes(64, 1);
		final byte[] salt = bytes(Fido2Utilities.HMAC_SALT_LENGTH, 100);
		final Fido2Credential credential = new Fido2Credential(credentialId, salt, "YubiKey 5");

		assertArrayEquals(credentialId, credential.getCredentialId());
		assertArrayEquals(salt, credential.getSalt());
		assertEquals("YubiKey 5", credential.getTokenName());
	}

	@Test
	public void testTokenNameMayBeNull() {
		final Fido2Credential credential = new Fido2Credential(bytes(1, 0), bytes(Fido2Utilities.HMAC_SALT_LENGTH, 0), null);
		assertNull(credential.getTokenName());
	}

	@Test
	public void testConstructorCopiesArrays() {
		final byte[] credentialId = bytes(16, 1);
		final byte[] salt = bytes(Fido2Utilities.HMAC_SALT_LENGTH, 1);
		final Fido2Credential credential = new Fido2Credential(credentialId, salt, null);

		// Changes of the caller's arrays must not affect the credential
		credentialId[0] = 99;
		salt[0] = 99;

		assertEquals(1, credential.getCredentialId()[0]);
		assertEquals(1, credential.getSalt()[0]);
	}

	@Test
	public void testGettersReturnCopies() {
		final Fido2Credential credential = new Fido2Credential(bytes(16, 1), bytes(Fido2Utilities.HMAC_SALT_LENGTH, 1), null);

		final byte[] credentialId = credential.getCredentialId();
		final byte[] salt = credential.getSalt();
		credentialId[0] = 99;
		salt[0] = 99;

		assertEquals(1, credential.getCredentialId()[0]);
		assertEquals(1, credential.getSalt()[0]);
		assertNotSame(credential.getCredentialId(), credential.getCredentialId());
		assertNotSame(credential.getSalt(), credential.getSalt());
	}

	@Test
	public void testMissingCredentialIdIsRejected() {
		final byte[] salt = bytes(Fido2Utilities.HMAC_SALT_LENGTH, 0);
		assertThrows(IllegalArgumentException.class, () -> new Fido2Credential(null, salt, null));
		assertThrows(IllegalArgumentException.class, () -> new Fido2Credential(new byte[0], salt, null));
	}

	@Test
	public void testInvalidSaltIsRejected() {
		final byte[] credentialId = bytes(16, 0);
		assertThrows(IllegalArgumentException.class, () -> new Fido2Credential(credentialId, null, null));
		assertThrows(IllegalArgumentException.class, () -> new Fido2Credential(credentialId, new byte[0], null));
		assertThrows(IllegalArgumentException.class, () -> new Fido2Credential(credentialId, new byte[Fido2Utilities.HMAC_SALT_LENGTH - 1], null));
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new Fido2Credential(credentialId, new byte[Fido2Utilities.HMAC_SALT_LENGTH + 1], null));
		assertEquals("Salt must be exactly 32 bytes long", exception.getMessage());
	}
}
