package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class Fido2InteractionTest {
	@Test
	public void testNoneHasNoPinAndIgnoresNotifications() {
		assertNull(Fido2Interaction.NONE.requestPin());
		assertDoesNotThrow(() -> {
			Fido2Interaction.NONE.onTouchRequired();
			Fido2Interaction.NONE.onTouchCompleted();
			Fido2Interaction.NONE.onCredentialAttempt(1, 2);
		});
	}

	@Test
	public void testDefaultMethodsOfPartialImplementation() {
		final Fido2Interaction interaction = new Fido2Interaction() {
			@Override
			public String requestPin() {
				return "1234";
			}
		};

		assertEquals("1234", interaction.requestPin());
		assertDoesNotThrow(() -> {
			interaction.onTouchRequired();
			interaction.onTouchCompleted();
			interaction.onCredentialAttempt(1, 1);
		});
	}

	@Test
	public void testOfWithOnlyNullCallbacks() {
		final Fido2Interaction interaction = Fido2Interaction.of(null, null, null, null);

		assertNull(interaction.requestPin());
		assertDoesNotThrow(() -> {
			interaction.onTouchRequired();
			interaction.onTouchCompleted();
			interaction.onCredentialAttempt(1, 3);
		});
	}

	@Test
	public void testOfDelegatesToCallbacks() {
		final AtomicInteger pinRequests = new AtomicInteger();
		final AtomicInteger touchRequired = new AtomicInteger();
		final AtomicInteger touchCompleted = new AtomicInteger();
		final List<String> credentialAttempts = new ArrayList<>();

		final Fido2Interaction interaction = Fido2Interaction.of(
				() -> {
					pinRequests.incrementAndGet();
					return "123456";
				},
				touchRequired::incrementAndGet,
				touchCompleted::incrementAndGet,
				(credentialNumber, credentialCount) -> credentialAttempts.add(credentialNumber + "/" + credentialCount));

		assertEquals("123456", interaction.requestPin());
		interaction.onTouchRequired();
		interaction.onTouchRequired();
		interaction.onTouchCompleted();
		interaction.onCredentialAttempt(1, 3);
		interaction.onCredentialAttempt(2, 3);

		assertEquals(1, pinRequests.get());
		assertEquals(2, touchRequired.get());
		assertEquals(1, touchCompleted.get());
		assertEquals(List.of("1/3", "2/3"), credentialAttempts);
	}

	@Test
	public void testOfPinSupplierMayReturnNull() {
		final Fido2Interaction interaction = Fido2Interaction.of(() -> null, null, null, null);
		assertNull(interaction.requestPin());
	}
}
