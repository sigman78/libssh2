# The mbedTLS backend on the PSA Crypto API

This note records why the mbedTLS backend (`src/mbedtls.c`, `src/mbedtls.h`)
looks the way it does after the move from the legacy Mbed TLS API to the
PSA Crypto API, which design choices were made, what was deliberately left
out, and how the result is tested. It is a fork document; the upstream
contract for every function mentioned here is `src/HACKING-CRYPTO.md`.

Acronyms: PSA is the Platform Security Architecture crypto API that Mbed TLS
implements. TF-PSA-Crypto is the crypto library Mbed TLS 4 is built on. DER
is the binary ASN.1 encoding used by PKCS#1 and PKCS#8 key files. CRT means
the Chinese remainder theorem parameters of an RSA private key. AEAD is
authenticated encryption with associated data. GCM is the Galois/Counter mode
of AES. KEX is the SSH key exchange. DRBG is a deterministic random bit
generator. PKCS is the Public-Key Cryptography Standards family. PEM is the
base64 text armour around DER.

## Why

Mbed TLS 4.0 (shipped in ESP-IDF 6) moved its legacy bignum, RSA, elliptic
curve, cipher and GCM interfaces under `mbedtls/private/` and made the pk
parser drop its RNG arguments. libssh2 up to upstream `94629f16` called every
one of those. The PSA port removes all of them except one, described under
"Residual private API".

## Shape of the port

* **Keys are PSA key identifiers.** `ssh2_rsa_ctx`, `ssh2_ecdsa_ctx` and
  `ssh2_ec_key` are all `psa_key_id_t` held on the heap. The PSA key store
  has 32 volatile slots by default, so every function destroys its key on
  every failure path, and `tests/test_crypto.c` asserts the slot count is
  zero after each test group.
* **Private keys still go through the mbedTLS pk parser.** PSA has no PEM or
  PKCS#8 parser. `mbedtls_pk_parse_key()` reads PEM, PKCS#8 and their
  encrypted variants, and `mbedtls_pk_import_into_psa()` (Mbed TLS 3.6 and
  later) moves the result into PSA. That is why the minimum version is 3.6.0.
  OpenSSH-format private keys (`openssh-key-v1`) are parsed by libssh2 itself
  and imported as raw material: the ECDSA case imports the scalar, the
  ed25519 case needs no PSA at all. One dispatcher, `mbed_openssh_load()`,
  decrypts the envelope once and hands the body to the importer for its key
  type; `ssh2_ecdsa_new_priv()`, `ssh2_ed25519_new_priv()` and
  `ssh2_pub_privkey()` all go through it, so the envelope parser's own error
  reaches every caller. A wrong passphrase is
  `LIBSSH2_ERROR_KEYFILE_AUTH_FAILED` (authenticated ciphers report a failed
  decrypt, which is mapped to it). The header may follow other lines, as in
  the envelope parser; the comment and the padding bytes are checked and the
  decrypted envelope is wiped before release. Unencrypted PKCS#8 ed25519 keys
  are recognised by their fixed DER prefix. Encrypted PKCS#8 ed25519 is not
  supported, because the pk parser cannot decrypt a key type it does not
  know; the Docker test `test_auth_pubkey_ok_ed25519_pkcs8_encrypted` is
  skipped for this backend. OpenSSH-format RSA is not supported either.
* **No dependency on the TLS library.** Parser errors are mapped by hand
  (`mbed_pk_err()`) instead of `mbedtls_strerror()`, which lives in
  libmbedtls on Mbed TLS 4. Linking `tfpsacrypto` (or `mbedcrypto` on 3.x)
  alone is enough, also for a manual `find_library` or pkg-config setup; a
  static `tfpsacrypto` on Windows additionally needs `bcrypt`, which
  `cmake/FindMbedTLS.cmake` adds.
* **The throwaway import for public key derivation uses the key pair.** A
  public-only import of a parsed RSA private key fails on Mbed TLS 4 because
  its RSA parser does not fill `pk->pub_raw`. The pair is imported and the
  public half exported instead.
* **Wire formats are converted at the boundary.**
  * SSH carries RSA signatures modulus-sized, and so does PSA PKCS#1 v1.5.
    Verification pads or trims to the modulus size because some peers strip
    leading zero bytes.
  * SSH carries ECDSA signatures as two mpints; PSA wants fixed-width
    `r || s`. Leading zero bytes and sign bytes are stripped on the way in and
    re-added via `ssh2_store_bignum_bytes()` on the way out. The curve enum
    value is the PSA key size in bits (256, 384, 521), so `PSA_BITS_TO_BYTES`
    gives the field width directly (66 for P-521).
  * The uncompressed EC point PSA exports is byte-for-byte the SSH
    `Q` string, and a DER INTEGER body is byte-for-byte an SSH mpint. Public
    key blobs are therefore lifted out of DER without a bignum.
* **Ciphers keep one PSA multipart operation alive per direction.** CBC and
  CTR chaining state must persist across `ssh2_cipher_crypt()` calls, so the
  operation is set up once in `ssh2_cipher_init()` and never finished. Data
  passes through a small stack buffer because PSA does not promise in-place
  operation.
* **AES-GCM is set up per packet.** The transport calls the backend with a
  16-byte FIRST block (4 bytes of packet length, which is associated data,
  plus 12 bytes of payload), 16-byte MIDDLE blocks, and a LAST call of 16 or
  20 bytes carrying the tag. Each FIRST call starts a fresh PSA AEAD operation
  on the stored 12-byte nonce; the invocation counter in nonce bytes 4..11 is
  incremented after every packet, whether or not it authenticated, exactly as
  the legacy code and the OpenSSL backend do.
* **The transport HMAC key is imported once per direction.** The backend
  announces `LIBSSH2_HMAC_KEYED` and offers `ssh2_hmac_key_import()`,
  `ssh2_hmac_init_key()` and `ssh2_hmac_key_destroy()`. `mac.c` imports the
  PSA key on the first packet of a MAC method, wipes and frees the key bytes
  at that point, and destroys the key when the method is torn down (rekey or
  session free). A context started from a key handle does not own the key.
  The plain `ssh2_hmac_init()` still imports and destroys a key per call.
* **Randomness is PSA's.** The private entropy + CTR-DRBG pair is gone;
  `psa_generate_random()` feeds everything, including the DH exponent, whose
  temporary buffer is wiped before release.

## Residual private API

SSH Diffie-Hellman uses the RFC 3526 groups (group14, group16, group18) and
server-chosen GEX groups. PSA finite-field DH covers only the RFC 7919 groups,
and PSA has no general modular exponentiation. `ssh2_bn` therefore stays
`mbedtls_mpi`, pulled from `<mbedtls/private/bignum.h>` on Mbed TLS 4 under
`MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS`. The same mpi is used to marshal the
shared secret `K` in every KEX and to derive missing CRT exponents when an
OpenSSH-format RSA key is wrapped. Upstream carries the same dependency; there
is no PSA way around it.

## What PSA cannot do here

* **No EdDSA.** TF-PSA-Crypto 1.0 defines the `PSA_ALG_PURE_EDDSA` macros but
  ships no implementation. ed25519 host keys, user keys and the
  `curve25519-sha256` KEX therefore use the vendored Monocypher 4.0.2
  (`src/monocypher*.c`), independent of the Mbed TLS build. The files are
  licensed BSD-2-Clause OR CC0-1.0 (both texts are under `LICENSES/`),
  compiled only for the mbedTLS backend (CMake and automake), and excluded
  from `scripts/checksrc-all.pl`. They are C99: CMake builds them with
  `-std=gnu99 -w` outside any unity batch; automake has no per-file flags,
  so an autotools build needs a C99 compiler. X25519 could move to PSA
  (`PSA_WANT_ECC_MONTGOMERY_255` is on by default); it stays on Monocypher to
  keep one code path per curve. The shared secret is rejected when it is all
  zero, as RFC 8731 requires.
* **RSA keys above 4096 bits, or with a bit length that is not a multiple
  of 8, are refused.** `PSA_VENDOR_RSA_MAX_KEY_BITS` is a build constant of
  the PSA core. The backend reports a specific error instead of a generic
  parse failure. The legacy backend accepted such keys.
* **No key consistency check at import.** The legacy `mbedtls_rsa_check_privkey()`
  ran when a key was wrapped from components; PSA import does not. A corrupt
  key now fails at the first signature instead.

## Behaviour that predates the port and is left alone

* `libssh2_exit()` calls `mbedtls_psa_crypto_free()`, which tears down the
  PSA instance for the whole process. An application that shares PSA with
  libssh2 must use `LIBSSH2_INIT_NO_CRYPTO` or avoid `libssh2_exit()`.
* `ssh2_crypto_init()` is `void` in the backend contract, so a failing
  `psa_crypto_init()` surfaces later as unclear errors.
* User authentication without a `.pub` file decrypts an encrypted OpenSSH key
  twice (once to derive the public key, once to load the private key). This
  is how every backend behaves; it is only noticeable on slow targets.

## ESP-IDF hardware AES and GCM

ESP-IDF's hardware AES driver (`port/aes/esp_aes_gcm.c`, selected by
`CONFIG_MBEDTLS_HARDWARE_AES`) restarts its counter stream and zero-pads its
GHASH input on every update call. It is correct only when every update is a
multiple of 16 bytes. libssh2's first GCM update is always 12 bytes, so the
driver produces wrong ciphertext and wrong tags for `aes128-gcm@openssh.com`
and `aes256-gcm@openssh.com`. This is a driver limitation, present with the
legacy GCM code as well; it was invisible because `chacha20-poly1305@openssh.com`
precedes AES-GCM in the cipher preference list. A device build must define
`LIBSSH2_NO_AES_GCM` when the hardware AES driver is enabled, or patch the
driver to keep its partial-block state in the context.

## Version support

Mbed TLS 3.6.0 and later. On 3.x the pk parser takes an RNG callback
(`mbedtls_psa_get_random`); on 4.x it takes none, and `tfpsacrypto` replaces
`mbedcrypto` as the link library (`cmake/FindMbedTLS.cmake` tries both).
Everything else is version-neutral PSA.

## Commit structure

The branch is ordered so that each tests commit precedes the port commit it
covers and passes against the legacy code that commit replaces (except the
ed25519 tests, which have no legacy counterpart in this backend). The PSA
commits come first and touch only `src/mbedtls.*`, `tests/`, CMake and
`docs/DEPENDENCIES.md`, so they can be offered upstream as they are; the
Monocypher and ed25519 commits and this document are fork-only.

## Testing

`tests/test_crypto` is a standalone, server-less test of the backend contract
using the fixtures under `tests/keys`. It covers key loading from file and
memory in PEM, PKCS#8, OpenSSH and encrypted variants; public key derivation
compared byte-for-byte with the `ssh-keygen` `.pub` files; sign and verify
with raw mpint inputs including sign bytes and short values; OpenSSH-made
P-521 and ed25519 certificate signatures; RFC 8032 ed25519 vectors, signed
through an in-memory PKCS#8 key; ECDH and X25519 agreement including the
low-order point refusals and the RFC 7748 known answer; OpenSSH envelopes
with disagreeing public halves and the `ssh2_pub_privkey()` error codes; NIST SP 800-38A CTR and CBC
vectors; RFC 4231 HMAC and SHA-256 known answers; the exact transport
chunking for AES-GCM over consecutive packets, cross-checked against
single-shot `psa_aead_encrypt()`; refusal cases; and PSA key slot hygiene.
Every tests commit on the branch was first run against the legacy code it
replaces, so the tests describe the contract rather than the implementation.
The file is built by every crypto backend; cases a backend lacks (PKCS#8,
encrypted PEM, short RSA signatures) are guarded, and WinCNG passes it.

The branch builds and passes on Mbed TLS 3.6.7 and on Mbed TLS 4.0.0 with
TF-PSA-Crypto 1.0.0 (Windows, MSVC). Interoperability against a live sshd and
on the ESP32-S3 target is the next phase and is not covered by this document.
