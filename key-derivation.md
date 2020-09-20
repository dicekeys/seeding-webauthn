# Seeded WebAuthN Authenticator Specification

This specification defines how create credentials for [WebAuthN]((https://www.w3.org/TR/webauthn))/FIDO2 from a 256-bit seed key (**`seedKey`**) and to authenticate with those credentials.

Specifically, on calls to [authenticatorMakeCredential](https://www.w3.org/TR/webauthn/#op-make-cred), an authenticator will use the `seedKey` to generate a [Credential ID](https://www.w3.org/TR/webauthn/#credential-id) and public/private authentication key pair, sending the Credential ID and public key to the relying party.

On calls to [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion), an authenticator will use the `seedKey` to validate that the Credential ID was generated from `seedKey` for use by the requesting relying party, and then to re-derive the private key needed to authenticate.


## Prerequisites

## Inputs

### The secret seed key (**`seedKey`**)

**`seedKey`** is a fixed-length 256-bit (32 byte) secret key written into an authenticator to give it an replicable identity. It is so named as it seeds all other cryptographic operations.
This secret key is the only information an authenticator should require to authenticate via the [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion) operation, even if a different authenticator used the same seed to create the Credential ID and accompanying public key during the [`authenticatorMakeCredential`](https://www.w3.org/TR/webauthn/#op-make-cred) operation.

### External state stored with the `seedKey` (**`extState`**)

**`extState`** is an optional field of 0 and 256 bytes and is written to the authenticator along with the `seedKey`.  It is stored in plaintext within the Credential ID so that the relying party will keep a copy of it and share it with any party that attempts to authenticate. The field may contain information used to locate or re-generate the `seedKey` if an authenticator needs to be replaced.  Since this field is stored in plaintext with the relying party, it should not be used without careful consideration of the risks of sharing the information therein with the relying party, and the potential to make Credential IDs linkable.  (The degree of this risk depends on whether the value is quite common among multiple users or unique to each user.)

### Relying Party ID (**`rpId`**)

**`rpId`** is the [relying party identifier](https://www.w3.org/TR/webauthn/#relying-party-identifier) passed to [`authenticatorMakeCredential`](https://www.w3.org/TR/webauthn/#op-make-cred) via the the [`id`](https://www.w3.org/TR/webauthn/#dom-publickeycredentialrpentity-id) field of the [`rpEntity`](https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity) parameter, and passed to [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion) via the  `rpId` parameter. 

## Implementing [authenticatorMakeCredential](https://www.w3.org/TR/webauthn/#op-make-cred)


### Generating a [Credential ID](https://www.w3.org/TR/webauthn/#credential-id) (**`credentialId`**)

Generate a Credential ID by concatenating four fields.

```
credentialId = version || uniqueId || extState || credentialMac
```

**`version`** is a single byte and should be set to 1 (`0x01`).

**`uniqueId`** is _any_ 32-byte value that ensures the Credential Id meets the WebAuthN's requirement of having at least 100 bits of entropy to ensure uniqueness.

To support an optional deterministic mode, in which an observer that knows `seekKey` can verify that the authenticator generated the `credentialId` correctly, one can use a deterministic formula such as the one below to calculate the `uniqueID`:

```
uniqueId = SHA256HMAC( SHA256HMAC( seedKey, salt ) , rpId || userId || hash)
```

where **`salt`** is any string of the implementers choosing and  **`hash`** is a parameter passed to [authenticatorMakeCredential](https://www.w3.org/TR/webauthn/#op-make-cred) and **`userId`** is the [`id`](https://www.w3.org/TR/webauthn/#dom-publickeycredentialrpentity-id) field of the [`userEntity`](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity) parameter.

**`extState`** , defined [above](#Inputs) is an optional byte array of any length from 0 to 256 bytes, where the absence of the optional value is treated as a zero-length byte array.


**`credentialMac`** is a message authentication code that ensures the Credential ID has not been modified since it was created by the authenticator.

```
credentialMac = SHA256HMAC(seedKey, rpId || version || uniqueId || extState)
```

### Deriving the ES256 public key

Derive the private key **`es256SPrivateKey`**  from the `seedKey` on the authenticator, the `rpId` from the relying party, and the `credentialMac` field from the `credentialId` (which, as a MAC, effectively encapsulates the three other fields of `credentialId`.


Following [NIST FIPS 186.4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) Section Section B.4.2,
derive the secret key by testing randomly-generated 32-byte candidate sequences c_0, c_1, ... c_i of the form 

```
c[0] = SHA256HMAC(seedKey, rpId || credentialMac)
c[i] = SHA256HMAC(seedKey, c[i-1])
```

The 32-byte blocks are converted to numbers by interpreting them in little endian form. 
So, the algorithm is:

```
b = SHA256HMAC(seedKey, rpId || credentialMac);
c = BYTE_ARRAY_TO_UNSIGNED_BIT_INT_LITTLE_ENDIAN(b);
while (c <= p-2) {
  b = SHA256HMAC(seedKey, c);
  c = BYTE_ARRAY_TO_UNSIGNED_BIT_INT_LITTLE_ENDIAN(b);
}
// d is the private key
d = c + 1;
// Q is the public key
Q = dG;
```

### Setting the [Signature Counter](https://www.w3.org/TR/webauthn/#signature-counter)

The [W3C's WebAuthN specification](https://www.w3.org/TR/webauthn/#signature-counter) states that "Authenticators SHOULD implement a signature counter feature" and that "the signature counter's purpose is to aid Relying Parties in detecting cloned authenticators."  The W3C uses "SHOULD" as defined by [IETF RFC 2119](https://www.ietf.org/rfc/rfc2119.txt), which states

> This word, or the adjective "RECOMMENDED", mean that there may exist valid reasons in particular circumstances to ignore a particular item, but the full implications must be understood and carefully weighed before choosing a different course.

No reason could be more valid than to support users who choose purchase an authenticator that can be cloned because they want the ability to clone it.  Authenticators following our standard MUST use the approach specified in [WebAuthN Specification Section 6.2.3](https://www.w3.org/TR/webauthn/#op-make-cred), item 10, option 3 to set no signature counter.

> **no signature counter**
>
> let the signature counter value for the new credential be constant at zero.


## Implementing [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion)

Decoding and validating credential Ids is part of step 3 of the WebAuthN specification for [authenticatorGetAssertion](https://www.w3.org/TR/webauthn/#op-get-assertion).

### Extracting the four fields of the `credentialId`

Since the only variable length field is `extData`, its length can be calculated by subtracting the length of the other fields (65 bytes, the collective lengths of the one byte `version`, the 32-byte `uniqueId` and the 32-byte `credentialMac`) from the length of the Credential ID.

```
// The first byte of credentialId is the version field
version = CredentialId[0]

// The next 32 bytes are the uniqueID field
uniqueId = credentialId[1...32] // inclusive

// The credentialMac is the last 32 bytes and extData is any remaining bytes before the credentialMac
extData = credentialId[33...(credentialId.length - 33)] // [33...32] indicates a 0-length array
credentialMac = credentialId[(credentialId.length - 32)...(credentialId.length - 1)]
```

### Validating the `credentialID`.

If `version 1 != 1` terminate the processing of this Credential ID. If no valid Credential IDs are found, the list of credentials will be empty and step 6 of the [specification of `authenticatorGetAssertion`](https://www.w3.org/TR/webauthn/#op-get-assertion) dictates that the operation be terminated with a ["NotAllowedError"](https://heycam.github.io/webidl/#notallowederror).

Next, recalculate the MAC so that we can verify the Credential ID has not been modified.

```
recalculatedCredentialMac = SHA256HMAC(seedKey, rpId || version || uniqueId || extState)
```

If `recalculatedCredentialMac != credentialMac`, terminate the processing of this Credential ID.  Again, if no valid Credential IIs are found, the list of credentials will be empty and step 6 of the [specification of `authenticatorGetAssertion`](https://www.w3.org/TR/webauthn/#op-get-assertion) dictates that the operation be terminated with a ["NotAllowedError"](https://heycam.github.io/webidl/#notallowederror).


### Re-deriving the **`es256SPrivateKey`**

Iff all steps of the above validation process succeed, use the same formula was was used above and authenticate with the secret key (_d_).
