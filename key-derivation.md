# Creating WebAuthN/FIDO2 Credentials Deterministically from Seeds

This specification defines how create credentials for WebAuthN/FIDO2
from a 256-bit seed key _seedKey_.

On calls to [authenticatorMakeCredential](https://www.w3.org/TR/webauthn/#op-make-cred), an authenticator will use _s_ to generate a [Credential ID](https://www.w3.org/TR/webauthn/#credential-id) and public/private key pair for authentication.

On calls to [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion), an authenticator will use _s_ to validate that
the Credential Id was generated from _s_, for use by the relying party making
the request, and to and re-derive the public/private key pair needed to authenticate on calls to [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion). 


## Terminology

### Hash function H


We will assume a keyed hash function H(_key_, _value_).

**TO DO**
Determine which to use.


### Relying Party ID (`rpId`)

We use `rpId` to indicate the [relying party identifier](https://www.w3.org/TR/webauthn/#relying-party-identifier) passed to [`authenticatorMakeCredential`](https://www.w3.org/TR/webauthn/#op-make-cred) via the the [`id`](https://www.w3.org/TR/webauthn/#dom-publickeycredentialrpentity-id) field of the [`rpEntity`](https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity) parameter, and passed to [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion) via the  `rpId` parameter. 

### User ID (`userId`)

We use `userId` to indicate the user identifier passed to [authenticatorMakeCredential](https://www.w3.org/TR/webauthn/#op-make-cred) via the [`id`](https://www.w3.org/TR/webauthn/#dom-publickeycredentialrpentity-id) field of the [`userEntity`](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity) parameter.
(It is not available on calls to [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion).)


## The Credential ID format

Credential IDs are concatenations of four fields, three of fixed length and an optional field (`extState`)  of variable length.

```
    version || uniqueId || extState || credentialMac
```

**`version`** is a single byte and should be set to `1`.

If [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion) encounters a Credential ID with the `version` byte set to `0` or to a number greater than the authenticator supports, it should fail.  (FIXME -- describe proper failure response.)


**`uniqueId`** is a 32-byte value that ensures the Credential Id meets the WebAuthN's requirement of having at least 100 bits of entropy to ensure uniqueness.

Some authenticators may want to have a deterministic mode in which an observer that knows the seed _s_ can verify that the authenticator is behaving correctly.  The recommended deterministic algorithm for generating the uniqueId field is:

```
    H(seedKey, b"uniqueId" || rpId || userId || hash)
```

where hash is the `hash` field of [authenticatorMakeCredential](https://www.w3.org/TR/webauthn/#op-make-cred).

**`extState`** is an optional byte array of length [0..256]. It can store external written to the authenticator along with the seed, and its inclusion in the Credential ID will ensure this information is stored by the relying party. One use of this field would be to store information needed to salt the seed or to identify which of the user's seeds was stored in the authenticator. If no `extState` is specified it is treated as being of zero length.  It's length can be calculated as the length of the credential ID minus 65 (the collective lengths of the one byte `version`, the 32-byte `uniqueId` and the 32-byte `credentialMac`).

**`credentialMac`** is a message authentication code that ensures the Credential ID has not been modified since it was created by the authenticator.

```
credentialMac = H(seedKey, b"credentialMac" || rpId || version || uniqueId || extState)
```

## Deriving ES256 the secret key

The secret key is derived from the `seedKey`, the `rpId` (relying party identifier) which is passed to both [authenticatorMakeCredential](https://www.w3.org/TR/webauthn/#op-make-cred) and [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion), and the `credentialMac` field.

```
es256SecretKey = H(seedKey, b"es256SecretKey" || rpId || credentialMac)
```

Nicolas had written
> tag [now credentialMac] is used as we don't have the RP in the raw ID

Stuart writes
> But `rpId` is passed to [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion), so it should be available when we need to re-derive the secret key.


## Implementing [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion)

Extract the four fields of the Credential ID.
```
// The first byte of es256SecretKey is the version
version = CredentialId[0]

// The unique ID is the next 32 bytes
uniqueId = credentialId[1...32]

// The credentialMac is the last 32 bytes and extData is any bytes in between
extData = credentialId[33...(credentialId.length -32)]
credentialMac = credentialId[(credentialId.length -32)...credentialId.length]
```

Continue only if `version == 1`.
Otherwise, _FIXME_.

```
recalculatedCredentialMac = H(seedKey, b"credentialMac" || rpId || version || uniqueId || extState)
```

Continue only if `recalculatedCredentialMac == credentialMac`.
Otherwise, _FIXME_.

Recalculate `es256SecretKey` using the formula above.
