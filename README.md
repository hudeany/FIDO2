# soderer-fido2

**Derive stable secret keys from FIDO2 hardware tokens in plain Java.**

`soderer-fido2` gives Java applications access to FIDO2 security keys
(YubiKey, Nitrokey, SoloKey, …) through the **hmac-secret** extension. Plug in
the token, touch it, and you get a 32 byte secret, the same one every time for
the same credential and salt. You can use it as a key for file encryption, a
password vault or anything else that should only open with the physical key.

The library binds to the native [libfido2](https://github.com/Yubico/libfido2)
via JNA and hides all operating system specifics behind one small API.

```java
Fido2Token token = Fido2Utilities.findToken();
byte[] credentialId = Fido2Utilities.createCredential(token, "MyApp", "alice", interaction);
byte[] salt = Fido2Utilities.generateSalt();

byte[] secret = Fido2Utilities.getHmacSecret(token, "MyApp", credentialId, salt, interaction);
// -> 32 bytes, always the same for this token, credential and salt
```

---

## Features

- 🔑 **hmac-secret** key derivation from any FIDO2 token that supports the
  extension
- 🖥️ **Same API on every operating system**: Linux, macOS and Windows,
  including Windows without administrator rights (through the Windows WebAuthn
  API)
- 📦 **Windows works out of the box**: the libfido2 DLLs are bundled and
  extracted automatically
- 👥 **Several tokens per secret**: give a list of candidate credentials and
  the library finds the one that belongs to the connected token
- 🔐 **PIN on demand**: the PIN is only requested when the token actually
  needs it, with a dedicated exception for missing or wrong PINs
- 🧵 **Thread-safe**: all token operations are serialized internally
- 🩺 **Startup check** that never throws and tells you why FIDO2 is not
  available
- ⚖️ **Only one dependency**: [JNA](https://github.com/java-native-access/jna)

## Requirements

| | |
|---|---|
| Java | 17 or newer |
| JNA | 5.x (`net.java.dev.jna:jna`) |
| Linux | libfido2 from the distribution, e.g. `sudo apt install libfido2-1`. The user needs access to the token's hidraw device, which the distribution's udev rules usually provide. |
| macOS | `brew install libfido2` |
| Windows | Nothing to install (bundled x86-64 DLLs) |
| Token | FIDO2 security key with the hmac-secret extension |

## Installation

### Maven

```xml
<dependency>
    <groupId>de.soderer</groupId>
    <artifactId>soderer-fido2</artifactId>
    <version>VERSION</version>
</dependency>
```

### Plain jar

Download `soderer-fido2-VERSION.jar` from the releases and put it on the
classpath together with `jna-5.x.jar`.

## Usage

### 1. Check availability

`checkAvailability()` never throws, so it is suitable for a check at startup:

```java
Fido2Availability availability = Fido2Utilities.checkAvailability();
if (!availability.isReady()) {
    switch (availability.getState()) {
        case LIBRARY_NOT_FOUND -> System.err.println("Please install libfido2");
        case LIBRARY_LOAD_ERROR -> System.err.println("libfido2 could not be loaded: " + availability.getDetail());
        case NO_TOKEN_ACCESS -> System.err.println("Please run as administrator or update Windows");
        default -> { }
    }
}
```

### 2. Handle user interaction

Token operations block until the user touches the token. A
`Fido2Interaction` tells your UI when to show the touch prompt and supplies
the PIN only if the token asks for it:

```java
Fido2Interaction interaction = Fido2Interaction.of(
        () -> askUserForPin(),                    // return null to cancel
        () -> showMessage("Please touch your security key"),
        () -> hideMessage(),
        null);                                    // optional: credential attempt notifications
```

The callbacks run on the thread of the token operation. Run token operations
on a background thread, never on the GUI thread, and marshal UI updates
yourself.

### 3. Register a token

```java
Fido2Token token = Fido2Utilities.findToken();
byte[] credentialId = Fido2Utilities.createCredential(token, "MyApp", "alice", interaction);
byte[] salt = Fido2Utilities.generateSalt();
// Store credentialId and salt (they are not secret), e.g. in a file header
```

### 4. Retrieve the secret

```java
byte[] secret = Fido2Utilities.getHmacSecret(token, "MyApp", credentialId, salt, interaction);
try {
    // use the secret, e.g. as AES-256 key (or key encryption key)
} finally {
    Arrays.fill(secret, (byte) 0);
}
```

The relying party id (`"MyApp"`) must be the same for creation and retrieval.

### Several tokens for the same data

For data that several tokens can unlock (e.g. a primary key and a backup
key), pass all candidate credentials. The result tells you which one
matched:

```java
List<Fido2Credential> candidates = List.of(
        new Fido2Credential(primaryCredentialId, primarySalt, "YubiKey 5 NFC"),
        new Fido2Credential(backupCredentialId, backupSalt, "Nitrokey 3"));

Fido2HmacSecret result = Fido2Utilities.getHmacSecret(token, "MyApp", candidates, interaction);
int matchingIndex = result.getCredentialIndex();
byte[] secret = result.getSecret();
```

## Error handling

All exceptions are unchecked.

| Exception | Meaning | Typical reaction |
|---|---|---|
| `Fido2PinRequiredException` | The token needs its PIN, and none was given or the given one was wrong (`isPinWasAlreadyAttempted()`) | Ask for the PIN (again) and retry |
| `Fido2NoMatchingCredentialException` | The connected token does not hold the credential | "Please plug in the correct token" |
| `Fido2Exception` | Any other problem: no token found, library missing, communication error | Show the message |

## Operating system behaviour

You do not have to handle these differences yourself. This table only
explains what your users will see.

| | Linux / macOS | Windows (administrator) | Windows (normal user) |
|---|---|---|---|
| Token access | Direct (HID) | Direct (HID) | Windows WebAuthn API |
| Touch prompt / PIN | Your `Fido2Interaction` | Your `Fido2Interaction` | Windows' own dialogs |
| Token selection | First token found | First token found | Windows dialog |

Secrets are the same on all access paths, so data encrypted on Linux can be
decrypted on Windows with the same token.

## Debug logging

Set the system property or environment variable `FIDO2CRYPT_DEBUG` to write
the libfido2 debug log to a file: either a file path, or `1` for
`Fido2Crypt-debug.log` in the user's home directory.

## Building

The project is built with Apache Ant:

```sh
ant              # compile, test (incl. coverage), javadoc, jars into build/
```

The build downloads its dependencies into `lib/`, `lib_test/` and
`lib_coverage/` and creates these files:

- `build/soderer-fido2-VERSION.jar`
- `build/soderer-fido2-VERSION-sources.jar`
- `build/soderer-fido2-VERSION-javadoc.jar`
- `build/coverage/index.html` (JaCoCo report)

### Hardware test

The unit tests run without a token. An additional integration test with a
real token is disabled by default. It needs several touches:

```sh
java ... -Dfido2.hardwareTest=true -Dfido2.pin=123456 ...
```

## License

See [LICENSE.txt](LICENSE.txt).
