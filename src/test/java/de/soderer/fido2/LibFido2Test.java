package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Tests of the parts of LibFido2 that do not need the native library.
 */
@SuppressWarnings("static-method")
public class LibFido2Test {
	private static final Pattern CLIENT_DATA_PATTERN = Pattern.compile("\\{\"type\":\"([^\"]*)\",\"challenge\":\"([^\"]*)\",\"origin\":\"(.*)\",\"crossOrigin\":false\\}");

	@Test
	public void testDisplayNameWithManufacturerAndProduct() {
		assertEquals("Yubico YubiKey OTP+FIDO+CCID", new LibFido2.DeviceEntry("/dev/hidraw3", "Yubico", "YubiKey OTP+FIDO+CCID").getDisplayName());
	}

	@Test
	public void testDisplayNameWithoutManufacturer() {
		assertEquals("Nitrokey 3", new LibFido2.DeviceEntry("/dev/hidraw3", null, "Nitrokey 3").getDisplayName());
		assertEquals("Nitrokey 3", new LibFido2.DeviceEntry("/dev/hidraw3", " ", "Nitrokey 3").getDisplayName());
	}

	@Test
	public void testDisplayNameWithoutProductFallsBackToPath() {
		assertEquals("/dev/hidraw3", new LibFido2.DeviceEntry("/dev/hidraw3", "Yubico", null).getDisplayName());
		assertEquals("/dev/hidraw3", new LibFido2.DeviceEntry("/dev/hidraw3", "Yubico", "").getDisplayName());
		assertEquals("/dev/hidraw3", new LibFido2.DeviceEntry("/dev/hidraw3", null, "  ").getDisplayName());
	}

	@Test
	public void testWindowsWebAuthnPath() {
		assertEquals("windows://hello", LibFido2.WINDOWS_WEBAUTHN_PATH);
	}

	@Test
	public void testClientDataStructure() throws Exception {
		final Matcher matcher = matchClientData("webauthn.create", "Fido2Crypt");
		assertEquals("webauthn.create", matcher.group(1));
		assertEquals("Fido2Crypt", matcher.group(3));

		// 32 random bytes, base64url without padding
		assertTrue(matcher.group(2).matches("[A-Za-z0-9_-]{43}"), "Unexpected challenge: " + matcher.group(2));
	}

	@Test
	public void testClientDataChallengeIsRandom() throws Exception {
		final String firstChallenge = matchClientData("webauthn.get", "Fido2Crypt").group(2);
		final String secondChallenge = matchClientData("webauthn.get", "Fido2Crypt").group(2);
		assertNotEquals(firstChallenge, secondChallenge);
	}

	@Test
	public void testClientDataOriginIsJsonEscaped() throws Exception {
		assertEquals("a\\\"b\\\\c", matchClientData("webauthn.get", "a\"b\\c").group(3));
	}

	@Test
	public void testClientDataIsUtf8() throws Exception {
		final byte[] clientData = createClientData("webauthn.get", "Bücher");
		assertTrue(new String(clientData, StandardCharsets.UTF_8).contains("\"origin\":\"Bücher\""));
	}

	private static Matcher matchClientData(final String type, final String origin) throws Exception {
		final String clientDataJson = new String(createClientData(type, origin), StandardCharsets.UTF_8);
		final Matcher matcher = CLIENT_DATA_PATTERN.matcher(clientDataJson);
		assertTrue(matcher.matches(), "Unexpected client data: " + clientDataJson);
		return matcher;
	}

	/** Calls the private LibFido2.createClientData(), which does not need the native library */
	private static byte[] createClientData(final String type, final String origin) throws Exception {
		final Method method = LibFido2.class.getDeclaredMethod("createClientData", String.class, String.class);
		method.setAccessible(true);
		return (byte[]) method.invoke(null, type, origin);
	}
}
