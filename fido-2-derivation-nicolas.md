## Key Derivation Proposal

The (my..) goal is to find the minimal/simplest yet safe construction which implements the mental model "U2F with just one secret". Authenticators already have to support SHA-256, P256 (and AES). Resident keys cannot be automatically shared without some synchronization process, so we're in the simplest possible case: "f(DiceKey, rp_id, user_id) -> P256 keypair".

This proposal is *versioned,* the current version is **1**. (If changes are made, authenticators supporting >1 should also support version 1. Future *spec* changes are fully flexible in backwards incompatible ways, just change the first byte of credential ID).



Independently of this proposal, 32B seed `S` is produced (for instance: take set of DiceKeys, somehow generate a rotation-independent string, hash it down). I strongly think there should be *one* standard/recommended way to generate such a seed out of the actual ~196b entropy.



Conforming key is flashed with `S` (and, implicitly `V1`, and a fixed AAGUID as discussed).

Setting:

- `H = SHA-256`
- `HMAC = HMAC-SHA256`
- `b"..."` byte string

Authenticator generates and possibly stores three core derived symmetric keys:

- `K1 = HMAC(S, b"privacy")`
- `K2 = HMAC(S, b"authentic")`
- `K3 = HMAC(S, b"deterministic")`

Byte strings very bikesheddable, just want to have/use three independent keys.



### MakeCredential

Note/Motivation: The mental model is that "credential ID" is a (versioned) AEAD construction applied to (a serialization of) the "credential data" defining the credential (possibly with full RP name, user name, extensions, etc.), using the RP ID as associated data. 

Since we don't ever need userId in GetAssertion, we can just hash instead of encrypt, and leave out rpId and its hash.



Inputs: rpIdHash (32B, e.g. H(example.com)), userId (RP-assigned and password-verified bytes, not e.g. the Unicode string "email")

Construct:

- version = 1 = 0x01
- raw_credential_id = `H(K1 || userId)`
- tag = `H(K2 || raw_credential_id || rpIdHash)`
- P256 seed (secret scalar) = `H(K3 || tag)`: tag is used as we don't have the RP in the raw ID

If cryptographically necessary, use HMAC(K, -) instead of H(K || -) as appropriate, I don't think there are any length extension attacks applicable here.

We should specify (independent of used crypto library) whether P256 seed is interpreted as little/big-endian scalar; and whether we care about modulo bias (I think we should be fine just reducing).



Outputs (sent to RP):

- Credential ID: `[version, raw_credential_id, tag]` (1 + 32 + 32 = 65B)
- P256 public key



Note that the signatures the authenticator makes are over clientData (which contains the challenge from the RP) and authenticator data (cf. subfigure io https://www.w3.org/TR/webauthn/#fig-attStructs, with rpIdHash, AAGUID, credentialId, credentialPublicKey...)



### GetAssertion

Inputs: credentiald, rpIdHash

Steps:

- confirm length 65, version 1, tag is correct for raw_credential_id (and RP, where SSL+browser are trusted...)
- regenerate P256 key
- generate signature



### Separate Considerations

- Naming: do we have an idea for what we call this project? Catchy/not just referencing Dice or Solo keys?
- PIN protection: we could either have different credentials based on whether PIN is passed or not (by hashing in a flag), or insist on PINs. 
- Choice of shared AAGUID: should just pick one and add to the spec
- Consideration of non-resident keys, or extensions such as hmac-secret: out of scope, better to leave out fully in v1
- Documentation of how seed is generated: If this is really really wanted, we can add a length field + associated "storage" space in the credential ID (and hash it into the tag). I feel credential ID is not the place to store this though.