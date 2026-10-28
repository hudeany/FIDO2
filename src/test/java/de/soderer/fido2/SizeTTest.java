package de.soderer.fido2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;

import com.sun.jna.Native;

@SuppressWarnings("static-method")
public class SizeTTest {
	@Test
	public void testDefaultValueIsZero() {
		assertEquals(0L, new SizeT().longValue());
	}

	@Test
	public void testValue() {
		assertEquals(42L, new SizeT(42).longValue());
		assertEquals(42, new SizeT(42).intValue());
		// Largest value that fits on 32-bit and 64-bit systems
		assertEquals(0xFFFFFFFFL, new SizeT(0xFFFFFFFFL).longValue());
	}

	@Test
	public void testValueBeyond32BitOn64BitSystem() {
		assumeTrue(Native.SIZE_T_SIZE == 8, "Only on 64-bit systems");
		assertEquals(0x1_0000_0001L, new SizeT(0x1_0000_0001L).longValue());
	}

	@Test
	public void testValueBeyond32BitIsRejectedOn32BitSystem() {
		assumeTrue(Native.SIZE_T_SIZE == 4, "Only on 32-bit systems");
		assertThrows(IllegalArgumentException.class, () -> new SizeT(0x1_0000_0000L));
	}

	@Test
	public void testByRefIsInitializedWithZero() {
		// JNA does not zero native memory by itself, ByRef must do it
		assertEquals(0L, new SizeT.ByRef().getValue());
	}

	@Test
	public void testByRefSetAndGet() {
		final SizeT.ByRef reference = new SizeT.ByRef();
		reference.setValue(7);
		assertEquals(7L, reference.getValue());

		// Read as unsigned value also on 32-bit systems
		reference.setValue(0xFFFFFFFFL);
		assertEquals(0xFFFFFFFFL, reference.getValue());
	}

	@Test
	public void testByRefWritesFullSizeTOn64BitSystem() {
		assumeTrue(Native.SIZE_T_SIZE == 8, "Only on 64-bit systems");
		final SizeT.ByRef reference = new SizeT.ByRef();
		reference.setValue(0x1234_5678_9ABC_DEF0L);
		assertEquals(0x1234_5678_9ABC_DEF0L, reference.getValue());
		assertEquals(0x1234_5678_9ABC_DEF0L, reference.getPointer().getLong(0));
	}
}
