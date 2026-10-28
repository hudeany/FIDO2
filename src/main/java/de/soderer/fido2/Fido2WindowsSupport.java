package de.soderer.fido2;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Windows specific parts of the FIDO2 access. All methods are safe to call on
 * any operating system, they are no-ops (or return neutral values) on
 * non-Windows systems.
 *
 * INTERNAL: Only used by the classes of this package.
 */
final class Fido2WindowsSupport {
	/**
	 * The four native libfido2 Windows DLLs that are bundled as classpath
	 * resources under "win32-x86-64/".
	 */
	private static final String[] BUNDLED_LIBRARY_FILE_NAMES = { "fido2.dll", "cbor.dll", "crypto-56.dll", "zlib1.dll" };

	private static final boolean IS_WINDOWS = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");

	private static boolean bundledLibrariesExtracted = false;

	/** Cached result of checkRunningAsAdministrator(), elevation does not change while the process runs. */
	private static volatile Boolean runningAsAdministrator = null;

	private Fido2WindowsSupport() {
		// Utility class
	}

	static boolean isWindows() {
		return IS_WINDOWS;
	}

	/**
	 * Extracts the bundled DLLs into a single directory under the user's temp
	 * folder, using their original file names, and points jna.library.path
	 * at that directory.
	 *
	 * JNA's own automatic resource extraction only extracts the one library
	 * requested via Native.load() (fido2.dll), renamed to a random name, but
	 * not its dependencies (cbor.dll, crypto-56.dll, zlib1.dll), which
	 * fido2.dll loads via the normal Windows LoadLibrary() search. The
	 * resources are read via the classloader, so this also works with a
	 * jar-in-jar loader ("rsrc:" URLs).
	 *
	 * On failure only a warning is printed: Native.load() then fails with
	 * its own LinkageError, which is reported by Fido2Utilities.checkAvailability().
	 */
	static synchronized void extractBundledLibrariesIfNeeded() {
		if (bundledLibrariesExtracted || !IS_WINDOWS) {
			return;
		}
		bundledLibrariesExtracted = true;

		try {
			final File targetDirectory = new File(System.getProperty("java.io.tmpdir"), "Fido2Crypt-native-win32-x86-64");
			if (!targetDirectory.exists() && !targetDirectory.mkdirs()) {
				System.err.println("FIDO2: could not create native library extraction directory: " + targetDirectory.getAbsolutePath());
				return;
			}

			for (final String libraryFileName : BUNDLED_LIBRARY_FILE_NAMES) {
				final File targetFile = new File(targetDirectory, libraryFileName);
				final String resourcePath = "/win32-x86-64/" + libraryFileName;

				try (InputStream resourceStream = Fido2WindowsSupport.class.getResourceAsStream(resourcePath)) {
					if (resourceStream == null) {
						System.err.println("FIDO2: bundled native library resource not found: " + resourcePath);
						continue;
					}

					final byte[] resourceBytes = resourceStream.readAllBytes();
					if (targetFile.exists() && targetFile.length() == resourceBytes.length) {
						// Already extracted by a previous run
						continue;
					}

					try (OutputStream targetStream = Files.newOutputStream(targetFile.toPath())) {
						targetStream.write(resourceBytes);
					}
				}
			}

			System.setProperty("jna.library.path", targetDirectory.getAbsolutePath());
		} catch (final IOException e) {
			System.err.println("FIDO2: could not extract bundled native libraries: " + e.getMessage());
		}
	}

	/**
	 * Checks whether this process runs with elevated (administrator) rights.
	 * Without elevation, Windows (since Windows 10 1903) denies direct HID
	 * access to FIDO devices, then only the Windows WebAuthn API can be used.
	 *
	 * Always true on non-Windows systems. Uses "net session", which only
	 * succeeds with elevated rights, to avoid a jna-platform dependency.
	 */
	static boolean isRunningAsAdministrator() {
		if (!IS_WINDOWS) {
			return true;
		}

		Boolean result = runningAsAdministrator;
		if (result == null) {
			result = checkRunningAsAdministrator();
			runningAsAdministrator = result;
		}
		return result;
	}

	private static boolean checkRunningAsAdministrator() {
		try {
			final Process process = new ProcessBuilder("net", "session").redirectErrorStream(true).start();
			process.getInputStream().readAllBytes();
			return process.waitFor() == 0;
		} catch (@SuppressWarnings("unused") final InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return false;
		}
	}

	/**
	 * PowerShell script listing the present FIDO HID devices (usage page
	 * 0xF1D0) with their product name and the USB device carrying the serial
	 * number (for composite devices the parent of the interface). Device
	 * manager data is readable without administrator rights, unlike the
	 * devices themselves.
	 */
	private static final String SECURITY_KEY_LIST_SCRIPT = String.join("\n",
			"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
			"Get-PnpDevice -PresentOnly -Class HIDClass -ErrorAction SilentlyContinue | Where-Object { (@($_.HardwareID) + @($_.CompatibleID)) -match 'HID_DEVICE_UP:F1D0' } | ForEach-Object {",
			"  $parent = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data",
			"  $name = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_BusReportedDeviceDesc' -ErrorAction SilentlyContinue).Data",
			"  if (-not $name -and $parent) { $name = (Get-PnpDeviceProperty -InstanceId $parent -KeyName 'DEVPKEY_Device_BusReportedDeviceDesc' -ErrorAction SilentlyContinue).Data }",
			"  if (-not $name) { $name = $_.FriendlyName }",
			"  $usbDevice = $parent",
			"  if ($usbDevice -match '&MI_[0-9A-F]{2}') { $usbDevice = (Get-PnpDeviceProperty -InstanceId $usbDevice -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data }",
			"  [string]$name + '|' + $_.InstanceId + '|' + [string]$usbDevice",
			"}");

	private static final Pattern VID_PID_PATTERN = Pattern.compile("VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})");

	/**
	 * Lists the FIDO security keys known to the Windows device manager, only
	 * for display (e.g. "YubiKey OTP+FIDO+CCID (VID 1050, PID 0407, SN 1234)").
	 * Without administrator rights libfido2 cannot open them, they are used
	 * via the Windows WebAuthn API instead. Takes about a second (PowerShell).
	 *
	 * @return display lines, empty if none were found or on other systems
	 */
	static List<String> listSecurityKeyDescriptions() {
		final List<String> result = new ArrayList<>();
		if (!IS_WINDOWS) {
			return result;
		}

		try {
			final String encodedScript = Base64.getEncoder().encodeToString(SECURITY_KEY_LIST_SCRIPT.getBytes(StandardCharsets.UTF_16LE));
			final Process process = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedScript)
					.redirectError(ProcessBuilder.Redirect.DISCARD)
					.start();
			process.getOutputStream().close();
			final String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
			if (!process.waitFor(15, TimeUnit.SECONDS)) {
				process.destroyForcibly();
				return result;
			}

			for (final String line : output.split("\\r?\\n")) {
				final String[] fields = line.split("\\|", -1);
				if (fields.length >= 2 && !fields[1].isBlank()) {
					final String name = fields[0].strip();
					final String instanceId = fields[1].strip();
					final String parentInstanceId = fields.length >= 3 ? fields[2].strip() : "";

					final List<String> details = new ArrayList<>();
					final Matcher vidPidMatcher = VID_PID_PATTERN.matcher(instanceId);
					if (vidPidMatcher.find()) {
						details.add("VID " + vidPidMatcher.group(1).toUpperCase(Locale.ROOT) + ", PID " + vidPidMatcher.group(2).toUpperCase(Locale.ROOT));
					}
					final String serialNumber = getUsbSerialNumber(parentInstanceId);
					if (serialNumber != null) {
						details.add("SN " + serialNumber);
					}
					result.add((name.isEmpty() ? "FIDO security key" : name) + (details.isEmpty() ? "" : " (" + String.join(", ", details) + ")"));
				}
			}
		} catch (@SuppressWarnings("unused") final InterruptedException e) {
			Thread.currentThread().interrupt();
		} catch (@SuppressWarnings("unused") final Exception e) {
			// Display only: without PowerShell no names are shown
		}
		return result;
	}

	/**
	 * The serial number of a USB device is the last part of its Windows
	 * device instance id (e.g. "USB\\VID_0483&PID_A2CA\\205D329D304B"). For
	 * devices without serial number Windows generates this part, it then
	 * contains a "&" and is no serial number.
	 *
	 * @return serial number, or null if the device has none
	 */
	static String getUsbSerialNumber(final String usbInstanceId) {
		if (usbInstanceId == null || !usbInstanceId.toUpperCase(Locale.ROOT).startsWith("USB\\")) {
			return null;
		}
		final String lastPart = usbInstanceId.substring(usbInstanceId.lastIndexOf('\\') + 1).strip();
		return lastPart.isEmpty() || lastPart.contains("&") ? null : lastPart;
	}
}
