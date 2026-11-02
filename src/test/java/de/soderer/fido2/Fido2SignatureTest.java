package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Tests of the signature functions (register/authenticate/verifyAssertion)
 * that do not need a token: verification with software generated keys and
 * signatures in the exact format of a FIDO2 token, encoding of public keys,
 * CBOR unwrapping and parameter checks.
 */
@SuppressWarnings("static-method")
public class Fido2SignatureTest {
	private static final String RELYING_PARTY_ID = "de.soderer.fido2.test";

	private static final int FLAGS_UP = 0x01;
	private static final int FLAGS_UP_UV = 0x05;

	/** Software stand-in for a token: a P-256 key pair with its raw and encoded public key */
	private static final class TestKey {
		final PrivateKey privateKey;
		final byte[] rawPublicKey;
		final byte[] encodedPublicKey;

		TestKey() throws Exception {
			final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			final KeyPair keyPair = generator.generateKeyPair();
			privateKey = keyPair.getPrivate();
			final ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			rawPublicKey = new byte[64];
			copyUnsigned32(publicKey.getW().getAffineX(), rawPublicKey, 0);
			copyUnsigned32(publicKey.getW().getAffineY(), rawPublicKey, 32);
			encodedPublicKey = publicKey.getEncoded();
		}

		private static void copyUnsigned32(final BigInteger value, final byte[] target, final int offset) {
			final byte[] bytes = value.toByteArray();
			final int length = Math.min(bytes.length, 32);
			System.arraycopy(bytes, bytes.length - length, target, offset + 32 - length, length);
		}

		/** Signs like a token: ECDSA over authenticatorData || SHA-256(clientData), DER encoded */
		Fido2Assertion sign(final byte[] authenticatorData, final byte[] clientData) throws Exception {
			final Signature signer = Signature.getInstance("SHA256withECDSA");
			signer.initSign(privateKey);
			signer.update(authenticatorData);
			signer.update(MessageDigest.getInstance("SHA-256").digest(clientData));
			return new Fido2Assertion(new byte[] { 1, 2, 3 }, clientData, authenticatorData, signer.sign());
		}
	}

	private static byte[] authenticatorData(final String relyingPartyId, final int flags, final long signatureCounter) throws Exception {
		final byte[] authenticatorData = new byte[37];
		System.arraycopy(MessageDigest.getInstance("SHA-256").digest(relyingPartyId.getBytes(StandardCharsets.UTF_8)), 0, authenticatorData, 0, 32);
		authenticatorData[32] = (byte) flags;
		authenticatorData[33] = (byte) (signatureCounter >>> 24);
		authenticatorData[34] = (byte) (signatureCounter >>> 16);
		authenticatorData[35] = (byte) (signatureCounter >>> 8);
		authenticatorData[36] = (byte) signatureCounter;
		return authenticatorData;
	}

	private static byte[] clientData(final byte[] challenge) {
		return LibFido2.createClientData("webauthn.get", RELYING_PARTY_ID, challenge);
	}

	// ---- Public key encoding ----

	@Test
	public void testEncodedPublicKeyMatchesJavaEncoding() throws Exception {
		for (int i = 0; i < 20; i++) {
			// Several keys, so coordinates with leading zero bytes are covered too
			final TestKey key = new TestKey();
			assertArrayEquals(key.encodedPublicKey, Fido2Utilities.encodeEs256PublicKey(key.rawPublicKey));
		}
	}

	@Test
	public void testEncodePublicKeyRejectsWrongLength() {
		assertThrows(Fido2Exception.class, () -> Fido2Utilities.encodeEs256PublicKey(new byte[63]));
		assertThrows(Fido2Exception.class, () -> Fido2Utilities.encodeEs256PublicKey(new byte[65]));
		assertThrows(Fido2Exception.class, () -> Fido2Utilities.encodeEs256PublicKey(null));
	}

	// ---- Verification ----

	@Test
	public void testValidAssertionUserPresence() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7), clientData(challenge));
		assertTrue(Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testValidAssertionUserVerification() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP_UV, 7), clientData(challenge));
		assertTrue(Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_VERIFICATION));
		// Additional verification is accepted when only presence is required
		assertTrue(Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testUserVerificationRequiredButMissing() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7), clientData(challenge));
		assertFalse(Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_VERIFICATION));
	}

	@Test
	public void testUserPresenceMissing() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, 0x00, 7), clientData(challenge));
		assertFalse(Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testWrongChallenge() throws Exception {
		final TestKey key = new TestKey();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7), clientData(Fido2Utilities.generateChallenge()));
		assertFalse(Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, Fido2Utilities.generateChallenge(), Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testWrongRelyingParty() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData("other.relying.party", FLAGS_UP, 7), clientData(challenge));
		assertFalse(Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testWrongPublicKey() throws Exception {
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = new TestKey().sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7), clientData(challenge));
		assertFalse(Fido2Utilities.verifyAssertion(assertion, new TestKey().encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testTamperedData() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7), clientData(challenge));

		// Signature counter changed after signing
		final byte[] tamperedAuthenticatorData = assertion.getAuthenticatorData();
		tamperedAuthenticatorData[36]++;
		assertFalse(Fido2Utilities.verifyAssertion(new Fido2Assertion(assertion.getCredentialId(), assertion.getClientData(), tamperedAuthenticatorData, assertion.getSignature()),
				key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));

		// Origin in the client data changed after signing (challenge still matches)
		final byte[] tamperedClientData = new String(assertion.getClientData(), StandardCharsets.UTF_8).replace(RELYING_PARTY_ID, "evil").getBytes(StandardCharsets.UTF_8);
		assertFalse(Fido2Utilities.verifyAssertion(new Fido2Assertion(assertion.getCredentialId(), tamperedClientData, assertion.getAuthenticatorData(), assertion.getSignature()),
				key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));

		// Signature changed
		final byte[] tamperedSignature = assertion.getSignature();
		tamperedSignature[tamperedSignature.length - 1]++;
		assertFalse(Fido2Utilities.verifyAssertion(new Fido2Assertion(assertion.getCredentialId(), assertion.getClientData(), assertion.getAuthenticatorData(), tamperedSignature),
				key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testWrongClientDataType() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7), LibFido2.createClientData("webauthn.create", RELYING_PARTY_ID, challenge));
		assertFalse(Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testMalformedPublicKeyAndSignature() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7), clientData(challenge));
		assertFalse(Fido2Utilities.verifyAssertion(assertion, new byte[] { 1, 2, 3 }, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
		// Raw key instead of the encoded one
		assertFalse(Fido2Utilities.verifyAssertion(assertion, key.rawPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));

		final Fido2Assertion garbageSignature = new Fido2Assertion(assertion.getCredentialId(), assertion.getClientData(), assertion.getAuthenticatorData(), new byte[] { 0x30, 0x01, 0x00 });
		assertFalse(Fido2Utilities.verifyAssertion(garbageSignature, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testOtherCurveIsRejected() throws Exception {
		final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp384r1"));
		final KeyPair keyPair = generator.generateKeyPair();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final byte[] authenticatorData = authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7);
		final byte[] clientData = clientData(challenge);
		final Signature signer = Signature.getInstance("SHA256withECDSA");
		signer.initSign(keyPair.getPrivate());
		signer.update(authenticatorData);
		signer.update(MessageDigest.getInstance("SHA-256").digest(clientData));
		final Fido2Assertion assertion = new Fido2Assertion(new byte[] { 1 }, clientData, authenticatorData, signer.sign());
		assertFalse(Fido2Utilities.verifyAssertion(assertion, keyPair.getPublic().getEncoded(), RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testVerifyNullParameters() throws Exception {
		final TestKey key = new TestKey();
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final Fido2Assertion assertion = key.sign(authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 7), clientData(challenge));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.verifyAssertion(null, key.encodedPublicKey, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.verifyAssertion(assertion, null, RELYING_PARTY_ID, challenge, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, null, challenge, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.verifyAssertion(assertion, key.encodedPublicKey, RELYING_PARTY_ID, challenge, null));
	}

	// ---- Result classes ----

	@Test
	public void testAssertionFlagsAndCounter() throws Exception {
		final byte[] clientData = clientData(Fido2Utilities.generateChallenge());

		final Fido2Assertion presentOnly = new Fido2Assertion(new byte[] { 1 }, clientData, authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 0xFFFFFFFEL), new byte[] { 1 });
		assertTrue(presentOnly.isUserPresent());
		assertFalse(presentOnly.isUserVerified());
		assertEquals(0xFFFFFFFEL, presentOnly.getSignatureCounter());
		assertEquals(-1, presentOnly.getCredentialIndex());

		final Fido2Assertion verified = new Fido2Assertion(2, new byte[] { 1 }, clientData, authenticatorData(RELYING_PARTY_ID, FLAGS_UP_UV, 42), new byte[] { 1 });
		assertTrue(verified.isUserPresent());
		assertTrue(verified.isUserVerified());
		assertEquals(42L, verified.getSignatureCounter());
		assertEquals(2, verified.getCredentialIndex());
	}

	@Test
	public void testAssertionValidatesAndCopies() throws Exception {
		final byte[] credentialId = { 1, 2, 3 };
		final byte[] clientData = clientData(Fido2Utilities.generateChallenge());
		final byte[] authenticatorData = authenticatorData(RELYING_PARTY_ID, FLAGS_UP, 1);
		final byte[] signature = { 9, 8, 7 };

		assertThrows(IllegalArgumentException.class, () -> new Fido2Assertion(null, clientData, authenticatorData, signature));
		assertThrows(IllegalArgumentException.class, () -> new Fido2Assertion(new byte[0], clientData, authenticatorData, signature));
		assertThrows(IllegalArgumentException.class, () -> new Fido2Assertion(credentialId, null, authenticatorData, signature));
		assertThrows(IllegalArgumentException.class, () -> new Fido2Assertion(credentialId, clientData, new byte[36], signature));
		assertThrows(IllegalArgumentException.class, () -> new Fido2Assertion(credentialId, clientData, authenticatorData, new byte[0]));

		final Fido2Assertion assertion = new Fido2Assertion(credentialId, clientData, authenticatorData, signature);
		credentialId[0] = 99;
		authenticatorData[32] = 0;
		assertEquals(1, assertion.getCredentialId()[0]);
		assertTrue(assertion.isUserPresent());
		assertion.getSignature()[0] = 0;
		assertEquals(9, assertion.getSignature()[0]);
	}

	@Test
	public void testRegistrationCopies() {
		final byte[] credentialId = { 1, 2, 3 };
		final byte[] publicKey = { 4, 5, 6 };
		final Fido2Registration registration = new Fido2Registration(credentialId, publicKey);
		credentialId[0] = 99;
		publicKey[0] = 99;
		assertArrayEquals(new byte[] { 1, 2, 3 }, registration.getCredentialId());
		assertArrayEquals(new byte[] { 4, 5, 6 }, registration.getPublicKey());
		registration.getPublicKey()[0] = 0;
		assertEquals(4, registration.getPublicKey()[0]);
	}

	// ---- Helpers ----

	@Test
	public void testUnwrapCborByteString() {
		// Length in the initial byte (0..23)
		assertArrayEquals(new byte[] { 1, 2, 3, 4, 5 }, LibFido2.unwrapCborByteString(new byte[] { 0x45, 1, 2, 3, 4, 5 }));
		assertArrayEquals(new byte[0], LibFido2.unwrapCborByteString(new byte[] { 0x40 }));

		// 1 byte length (typical authenticator data of 37 bytes)
		final byte[] content37 = new byte[37];
		Arrays.fill(content37, (byte) 7);
		final byte[] encoded37 = new byte[39];
		encoded37[0] = 0x58;
		encoded37[1] = 37;
		System.arraycopy(content37, 0, encoded37, 2, 37);
		assertArrayEquals(content37, LibFido2.unwrapCborByteString(encoded37));

		// 2 byte length
		final byte[] encoded300 = new byte[303];
		encoded300[0] = 0x59;
		encoded300[1] = 0x01;
		encoded300[2] = 0x2C;
		assertEquals(300, LibFido2.unwrapCborByteString(encoded300).length);
	}

	@Test
	public void testUnwrapCborByteStringRejectsInvalidData() {
		assertThrows(Fido2Exception.class, () -> LibFido2.unwrapCborByteString(null));
		assertThrows(Fido2Exception.class, () -> LibFido2.unwrapCborByteString(new byte[0]));
		// Text string instead of byte string
		assertThrows(Fido2Exception.class, () -> LibFido2.unwrapCborByteString(new byte[] { 0x63, 'a', 'b', 'c' }));
		// Too short and too long content
		assertThrows(Fido2Exception.class, () -> LibFido2.unwrapCborByteString(new byte[] { 0x45, 1, 2 }));
		assertThrows(Fido2Exception.class, () -> LibFido2.unwrapCborByteString(new byte[] { 0x42, 1, 2, 3 }));
		// Truncated length field
		assertThrows(Fido2Exception.class, () -> LibFido2.unwrapCborByteString(new byte[] { 0x59, 1 }));
		// Indefinite length is not supported
		assertThrows(Fido2Exception.class, () -> LibFido2.unwrapCborByteString(new byte[] { 0x5F, 0x41, 1, (byte) 0xFF }));
	}

	@Test
	public void testJsonStringValue() {
		final String json = "{\"type\":\"webauthn.get\",\"challenge\":\"abc_-123\",\"origin\":\"a\\\"b\",\"crossOrigin\":false}";
		assertEquals("webauthn.get", Fido2Utilities.getJsonStringValue(json, "type"));
		assertEquals("abc_-123", Fido2Utilities.getJsonStringValue(json, "challenge"));
		assertEquals("a\\\"b", Fido2Utilities.getJsonStringValue(json, "origin"));
		assertNull(Fido2Utilities.getJsonStringValue(json, "crossOrigin"));
		assertNull(Fido2Utilities.getJsonStringValue(json, "missing"));
		assertEquals("x", Fido2Utilities.getJsonStringValue("{ \"type\" : \"x\" }", "type"));
	}

	@Test
	public void testClientDataContainsChallenge() {
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final String json = new String(clientData(challenge), StandardCharsets.UTF_8);
		assertEquals(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(challenge), Fido2Utilities.getJsonStringValue(json, "challenge"));
		assertEquals(RELYING_PARTY_ID, Fido2Utilities.getJsonStringValue(json, "origin"));
	}

	@Test
	public void testGenerateChallenge() {
		final byte[] first = Fido2Utilities.generateChallenge();
		final byte[] second = Fido2Utilities.generateChallenge();
		assertEquals(Fido2Utilities.CHALLENGE_LENGTH, first.length);
		assertNotEquals(Arrays.toString(first), Arrays.toString(second));
	}

	// ---- Parameter checks before any token access ----

	@Test
	public void testAuthenticateParameterChecks() {
		final Fido2Token token = new Fido2Token("/dev/hidraw0", "Token", null, false);
		final byte[] challenge = Fido2Utilities.generateChallenge();
		final List<byte[]> credentialIds = List.of(new byte[] { 1 });

		assertThrows(NullPointerException.class, () -> Fido2Utilities.authenticate(null, RELYING_PARTY_ID, credentialIds, challenge, null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.authenticate(token, null, credentialIds, challenge, null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.authenticate(token, RELYING_PARTY_ID, credentialIds, null, null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.authenticate(token, RELYING_PARTY_ID, credentialIds, challenge, null, null));
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.authenticate(token, RELYING_PARTY_ID, null, challenge, null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.authenticate(token, RELYING_PARTY_ID, Collections.emptyList(), challenge, null, Fido2VerificationMode.USER_PRESENCE));
		final List<byte[]> withNull = new ArrayList<>();
		withNull.add(null);
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.authenticate(token, RELYING_PARTY_ID, withNull, challenge, null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.authenticate(token, RELYING_PARTY_ID, List.of(new byte[0]), challenge, null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(IllegalArgumentException.class, () -> Fido2Utilities.authenticate(token, RELYING_PARTY_ID, credentialIds, new byte[Fido2Utilities.MIN_CHALLENGE_LENGTH - 1], null, Fido2VerificationMode.USER_PRESENCE));
	}

	@Test
	public void testRegisterParameterChecks() {
		final Fido2Token token = new Fido2Token("/dev/hidraw0", "Token", null, false);
		assertThrows(NullPointerException.class, () -> Fido2Utilities.register(null, RELYING_PARTY_ID, "user", null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.register(token, null, "user", null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.register(token, RELYING_PARTY_ID, null, null, Fido2VerificationMode.USER_PRESENCE));
		assertThrows(NullPointerException.class, () -> Fido2Utilities.register(token, RELYING_PARTY_ID, "user", null, null));
	}
}
