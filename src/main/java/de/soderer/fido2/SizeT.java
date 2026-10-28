package de.soderer.fido2;

import com.sun.jna.IntegerType;
import com.sun.jna.Native;
import com.sun.jna.ptr.ByReference;

/**
 * JNA mapping of the C type "size_t" (unsigned, 8 bytes on 64-bit Linux,
 * macOS and Windows, 4 bytes on 32-bit systems).
 *
 * Neither "int" (always 4 bytes) nor NativeLong (only 4 bytes on 64-bit
 * Windows) is correct for size_t on all platforms.
 */
public class SizeT extends IntegerType {
	private static final long serialVersionUID = 1L;

	/** Needed by JNA for return values */
	public SizeT() {
		this(0);
	}

	public SizeT(final long value) {
		super(Native.SIZE_T_SIZE, value, true);
	}

	/**
	 * JNA mapping of "size_t *" for output parameters. The native side
	 * writes Native.SIZE_T_SIZE bytes, so a 4-byte int[1] or IntByReference
	 * must never be used for this (heap overflow on 64-bit systems).
	 */
	public static class ByRef extends ByReference {
		public ByRef() {
			super(Native.SIZE_T_SIZE);
			// JNA does not zero the allocated native memory
			getPointer().clear(Native.SIZE_T_SIZE);
		}

		public void setValue(final long value) {
			if (Native.SIZE_T_SIZE == 8) {
				getPointer().setLong(0, value);
			} else {
				getPointer().setInt(0, (int) value);
			}
		}

		public long getValue() {
			if (Native.SIZE_T_SIZE == 8) {
				return getPointer().getLong(0);
			} else {
				return getPointer().getInt(0) & 0xFFFFFFFFL;
			}
		}
	}
}
