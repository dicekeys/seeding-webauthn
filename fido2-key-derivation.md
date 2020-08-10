# ECDSA Service Key Pair Derivation

This document specifies a deterministic algorithm for deriving an application-specific ECDSA key pair from a 256-bit seed secret _s_ and a key identifier (KEYID) of arbitrary length.

It is intended to specify a common mechanism for seeding FIDO2
security keys.

## Design requirements
Only use cryptographic primitives from the [FIDO Authenticator Allowed Cryptography List](https://fidoalliance.org/specs/fido-security-requirements-v1.2-2018/fido-authenticator-allowed-cryptography-list-v1.0-wd-20180629.html), favoring those that are the most widely implemented.
  - AES-256 from [Section 3.1](https://fidoalliance.org/specs/fido-security-requirements-v1.2-2018/fido-authenticator-allowed-cryptography-list-v1.0-wd-20180629.html#confidentiality-algorithms), where the 256 indicates the key size (AES has a foxed 128-bit block size).
  - SHA-256 from [Section 3.2](https://fidoalliance.org/specs/fido-security-requirements-v1.2-2018/fido-authenticator-allowed-cryptography-list-v1.0-wd-20180629.html#hashing-algorithms).

## Algorithm

First, generate a fixed-length 256-bit key identifier _i_ from the arbitrary-length KEYID field.

> _i_ = SHA-256(_KEYID_)

The KEYID is not a secret and so there are no concerns about side-channels.

To generate the private key _k_ encrypt the fixed-length key identifier _i_ with the seed secret _s_ using AES-256 in cipher-block chaining mode (CBC).  Since the key identifier is a hashed and the output will be kept secret by the FIDO key, we can use initialization vector of 0. (Should we need to derive longer keys in the future, we can do so by zero-padding _i_ to the length of the desired key.)

> k = AES-256-CBC(key=_s_, _iv_=0, _i_)

For 256-bit keys, this means generating the following two AES blocks. 

  > _k_[0-15] = AES-256(key=_s_, plaintext=_i_[0-15])

  > _k_[16-31] = AES-256(key=_s_, plaintext=_i_[16-31] xor _k_[0-15])

In ECDSA, public-keys are directly derivable from their corresponding private key, and so once we have derived the private key we have derived the key pair.

Since the seed _s_ is the secret used to derive all key pairs, implementers should choose the most side-channel resistant implementation of AES-256 available to them.  It should never be used for any other purpose than generating keys which are also secrets that will not be shared outside of the authenticator.

Since CBC is a feedback mode of AES, it is permitted as a "KDF in feedback mode" option for deriving keys under [Section 3.6 of the FIDO Authenticator Allowed Cryptography List](https://fidoalliance.org/specs/fido-security-requirements-v1.2-2018/fido-authenticator-allowed-cryptography-list-v1.0-wd-20180629.html#key-derivation-functions-kdfs).

