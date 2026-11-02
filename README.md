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
- ✍️ **Signatures like a WebAuthn login**: register a credential, let the
  token sign a challenge and verify it in pure Java (also on a server
  without token)
- 👥 **Several tokens per secret**: give a list of candidate credentials and
  the library finds the one that belongs to the connected token
- 👆 **Touch only or touch + PIN**: choose per call between user presence
  (touch is enough) and user verification (the token's PIN is always
  required)
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

### User presence or user verification

Every token operation can be called with a `Fido2VerificationMode`:

| Mode | The user has to … | Protects against |
|---|---|---|
| `USER_PRESENCE` (default) | touch the token | remote attacks, the token must be physically present |
| `USER_VERIFICATION` | touch the token **and** enter its PIN | additionally someone who has stolen the token |

The methods without a mode parameter use `USER_PRESENCE`. To use user
verification, pass the mode to every call:

```java
byte[] credentialId = Fido2Utilities.createCredential(token, "MyApp", "alice", interaction,
        Fido2VerificationMode.USER_VERIFICATION);
byte[] salt = Fido2Utilities.generateSalt();

byte[] secret = Fido2Utilities.getHmacSecret(token, "MyApp", credentialId, salt, interaction,
        Fido2VerificationMode.USER_VERIFICATION);
```

> **Important:** the token derives a **different secret** in each mode for
> the same credential and salt. Data protected in one mode can only be
> unlocked in the same mode. Store the mode together with the credential id
> and salt, and always use the stored mode for retrieval.

Details:

- `USER_PRESENCE`: no PIN is ever sent for retrieving the secret. Creating
  a credential on a token with a PIN set usually needs the PIN anyway (CTAP
  2.0 tokens demand it), retrieving the secret does not.
  **Not available on Windows without administrator rights**: the Windows
  WebAuthn API always enforces user verification for the hmac-secret
  extension (it even forces creating a PIN on tokens without one). Also not
  available with tokens that enforce user verification themselves ("alwaysUv",
  fingerprint tokens). Check with
  `Fido2Utilities.isUserPresenceOnlySupported(token)` (or, without a token,
  `Fido2Utilities.isUserPresenceOnlyAvailable()` for presetting a UI).
- `USER_VERIFICATION`: the PIN is always requested through
  `Fido2Interaction.requestPin()` (on Windows without administrator rights the
  Windows dialog asks for it). With direct access, tokens without a PIN set
  are rejected, set a PIN first (e.g. `fido2-token -S <device>`).
- **The secret always matches the requested mode:** after every assertion the
  user verification flag reported by the token is compared with the requested
  mode. If they differ, or the mode is not possible with the token, a
  `Fido2VerificationModeException` is thrown instead of returning a secret of
  the wrong mode.
- With several candidate credentials and `USER_VERIFICATION`, the matching
  credential is determined first with a touch only, so the PIN is requested
  just once.

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

There is also an overload with a `Fido2VerificationMode`. The mode applies
to all candidates of the call.

### Signatures (like a WebAuthn login)

Besides the hmac-secret, a token can prove its presence by signing a
challenge, exactly like a website login with a security key. No secret key
is derived, so this is not suitable for encryption, but for authentication:

```java
// Once: register the token, store credential id and public key (neither is secret)
Fido2Registration registration = Fido2Utilities.register(token, "MyApp", "alice", interaction,
        Fido2VerificationMode.USER_PRESENCE);
byte[] credentialId = registration.getCredentialId();
byte[] publicKey = registration.getPublicKey();   // ECDSA P-256, X.509 SubjectPublicKeyInfo (DER)

// Every login: a fresh random challenge, the token signs it
byte[] challenge = Fido2Utilities.generateChallenge();
Fido2Assertion assertion = Fido2Utilities.authenticate(token, "MyApp", List.of(credentialId), challenge,
        interaction, Fido2VerificationMode.USER_PRESENCE);

// Verification: pure Java, needs neither the token nor libfido2
boolean valid = Fido2Utilities.verifyAssertion(assertion, publicKey, "MyApp", challenge,
        Fido2VerificationMode.USER_PRESENCE);
```

- **Several registered tokens:** pass all credential ids of the user to
  `authenticate()`, the token uses its own one.
  `assertion.getCredentialIndex()` tells you which public key to verify with.
- **Verification on another system:** transfer credential id, client data,
  authenticator data and signature of the assertion and rebuild it there with
  `new Fido2Assertion(credentialId, clientData, authenticatorData, signature)`.
- **What `verifyAssertion()` checks:** the relying party id hash, the "user
  present" flag (and "user verified" for `USER_VERIFICATION`), type and
  challenge in the client data, and the ECDSA signature. Not checked: the
  origin in the client data and the signature counter. To detect cloned
  tokens, compare `assertion.getSignatureCounter()` with the last stored
  value yourself (some tokens always report 0).
- **Use every challenge only once**, otherwise a recorded assertion could be
  replayed.
- **Windows without administrator rights:** unlike the hmac-secret, both
  modes work here. Windows honors user presence only for plain signatures,
  like for website logins.
- With `USER_PRESENCE`, an additional user verification by the token (e.g.
  a fingerprint token) is accepted; with `USER_VERIFICATION` it is required.

## Error handling

All exceptions are unchecked.

| Exception | Meaning | Typical reaction |
|---|---|---|
| `Fido2PinRequiredException` | The token needs its PIN, and none was given or the given one was wrong (`isPinWasAlreadyAttempted()`) | Ask for the PIN (again) and retry |
| `Fido2VerificationModeException` | The secret cannot be retrieved in the requested verification mode with this token (e.g. user presence on Windows without administrator rights, user verification on a token without PIN, or the token reported a different user verification state) | Use the other mode, or run with administrator rights |
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
| User verification | PIN passed to the token | PIN passed to the token | Windows asks for the PIN |
| hmac-secret, `USER_PRESENCE` (touch only) | ✅ | ✅ | ❌ (Windows enforces user verification) |
| hmac-secret, `USER_VERIFICATION` (PIN) | ✅ | ✅ | ✅ |
| Signatures, both modes | ✅ | ✅ | ✅ |

In the same verification mode, secrets are the same on all access paths, so
data protected with `USER_VERIFICATION` on Linux can be unlocked on Windows
with the same token and vice versa. Data protected with `USER_PRESENCE` can
only be unlocked with direct token access (Linux, macOS, Windows with
administrator rights).

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
