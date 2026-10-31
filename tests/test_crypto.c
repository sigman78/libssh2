/* Copyright (C) The libssh2 project and its contributors.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Round-trip tests for the crypto backend API (src/HACKING-CRYPTO.md)
 * that need no SSH server: key loading in the formats under tests/keys,
 * public key derivation, sign/verify, key agreement and ciphers.
 */

#include "libssh2_priv.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FAIL(msg) do { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
    goto fail; } while(0)
#define EXPECT(cond) do { if(!(cond)) FAIL("expected " #cond); } while(0)

static const char *srcdir = ".";

static const char *keypath(const char *name)
{
    static char path[1024];
    snprintf(path, sizeof(path), "%s/keys/%s", srcdir, name);
    return path;
}

/* Decodes the key blob of a "<type> <base64> [comment]" .pub file */
static int read_pub_blob(LIBSSH2_SESSION *session, const char *name,
                         unsigned char **blob, size_t *blob_len)
{
    char *text = NULL, *b64, *end;
    size_t text_len;
    char pubname[256];
    int rc = 1;

    snprintf(pubname, sizeof(pubname), "%s.pub", name);
    if(ssh2_file_to_blob(session, keypath(pubname), &text, &text_len))
        FAIL("cannot read .pub file");

    b64 = memchr(text, ' ', text_len);
    EXPECT(b64);
    b64++;
    end = b64;
    while(end < text + text_len && *end != ' ' && *end != '\n' &&
          *end != '\r')
        end++;

    EXPECT(ssh2_base64_decode(session, (char **)blob, blob_len,
                              b64, (size_t)(end - b64)) == 0);
    rc = 0;

fail:
    SSH2_FREE(session, text);
    return rc;
}

/* The derived public key must match what ssh-keygen wrote next to the
   private key. */
static int check_pub_privkey(LIBSSH2_SESSION *session, const char *name,
                             const char *passphrase,
                             const char *expected_method,
                             unsigned char **blob, size_t *blob_len)
{
    char *method = NULL, *priv = NULL;
    unsigned char *pubkey = NULL, *expected = NULL;
    size_t pubkey_len = 0, expected_len = 0, priv_len = 0;
    int rc = 1;

    *blob = NULL;

    if(read_pub_blob(session, name, &expected, &expected_len))
        goto fail;

    /* from file */
    if(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                        keypath(name), NULL, 0, passphrase))
        FAIL(name);
    EXPECT(strcmp(method, expected_method) == 0);
    EXPECT(pubkey_len == expected_len);
    EXPECT(memcmp(pubkey, expected, expected_len) == 0);
    SSH2_SAFEFREE(session, method);
    SSH2_SAFEFREE(session, pubkey);

    /* from memory */
    EXPECT(ssh2_file_to_blob(session, keypath(name), &priv, &priv_len) == 0);
    if(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                        NULL, priv, priv_len, passphrase))
        FAIL(name);
    EXPECT(pubkey_len == expected_len);
    EXPECT(memcmp(pubkey, expected, expected_len) == 0);

    *blob = expected;
    *blob_len = expected_len;
    expected = NULL;
    rc = 0;

fail:
    SSH2_FREE(session, method);
    SSH2_FREE(session, pubkey);
    ssh2_zero_free(session, priv, priv_len);
    SSH2_FREE(session, expected);
    return rc;
}

static int flip_byte_verify_fails(int verify_rc)
{
    return verify_rc == 0;
}

#if LIBSSH2_RSA
static int test_rsa(LIBSSH2_SESSION *session)
{
    static const struct {
        const char *name;
        const char *passphrase;
    } keys[] = {
        { "id_rsa_pem", NULL },
        { "id_rsa_pkcs8", NULL },
        { "id_rsa_pem_encrypted", "libssh2" },
        { "id_rsa_pkcs8_encrypted", "libssh2" }
    };
    const unsigned char msg[] = "the quick brown fox";
    unsigned char tampered[sizeof(msg)];
    unsigned char hash[SSH2_SHA512_DIG_LEN];
    ssh2_rsa_ctx *priv = NULL, *pub = NULL;
    unsigned char *blob = NULL, *sig = NULL, *name, *e, *n;
    char *data = NULL;
    size_t blob_len = 0, sig_len, name_len, e_len, n_len, data_len = 0, i;
    struct string_buf buf;
    int rc = 1;

    /* public key derivation, all PEM-ish formats; keep the first blob */
    for(i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        unsigned char *b;
        size_t bl;
        if(check_pub_privkey(session, keys[i].name, keys[i].passphrase,
                             "ssh-rsa", &b, &bl))
            goto fail;
        if(i)
            SSH2_FREE(session, b);
        else {
            blob = b;
            blob_len = bl;
        }
    }

    /* private key loading, file and memory, with and without passphrase */
    for(i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if(ssh2_rsa_new_priv(&priv, session, keypath(keys[i].name),
                             NULL, 0, keys[i].passphrase))
            FAIL(keys[i].name);
        ssh2_rsa_free(priv, session);
        priv = NULL;

        EXPECT(ssh2_file_to_blob(session, keypath(keys[i].name),
                                 &data, &data_len) == 0);
        if(ssh2_rsa_new_priv(&priv, session, NULL, data, data_len,
                             keys[i].passphrase))
            FAIL(keys[i].name);
        ssh2_rsa_free(priv, session);
        priv = NULL;
        ssh2_zero_free(session, data, data_len);
        data = NULL;
    }

    /* wrong passphrase must fail */
    EXPECT(ssh2_rsa_new_priv(&priv, session,
                             keypath("id_rsa_pem_encrypted"),
                             NULL, 0, "wrong") != 0);
    EXPECT(!priv);

    /* public key from the wire blob: "ssh-rsa" || e || n */
    buf.data = buf.dataptr = blob;
    buf.len = blob_len;
    EXPECT(ssh2_get_string(&buf, &name, &name_len) == 0);
    EXPECT(ssh2_get_bignum_bytes(&buf, &e, &e_len) == 0);
    EXPECT(ssh2_get_bignum_bytes(&buf, &n, &n_len) == 0);
    EXPECT(ssh2_rsa_new(&pub, session, e, e_len, n, n_len,
                        NULL, 0, NULL, 0, NULL, 0,
                        NULL, 0, NULL, 0, NULL, 0) == 0);

    EXPECT(ssh2_rsa_new_priv(&priv, session, keypath("id_rsa_pem"),
                             NULL, 0, NULL) == 0);

    memcpy(tampered, msg, sizeof(msg));
    tampered[3] ^= 1;

    /* rsa-sha2-256 and rsa-sha2-512 round trips */
    for(i = 0; i < 2; i++) {
        ssh2_hash_alg alg = i ? SSH2_SHA512_ALG : SSH2_SHA256_ALG;
        size_t hash_len = i ? SSH2_SHA512_DIG_LEN : SSH2_SHA256_DIG_LEN;

        EXPECT(ssh2_hash(alg, msg, sizeof(msg), hash, hash_len));
        EXPECT(ssh2_rsa_sha2_sign(priv, session, hash, hash_len,
                                  &sig, &sig_len) == 0);
        EXPECT(sig_len == n_len);  /* modulus-sized */
        EXPECT(ssh2_rsa_sha2_verify(pub, session, hash_len, sig, sig_len,
                                    msg, sizeof(msg)) == 0);
        EXPECT(ssh2_rsa_sha2_verify(priv, session, hash_len, sig, sig_len,
                                    msg, sizeof(msg)) == 0);
        EXPECT(flip_byte_verify_fails(
                   ssh2_rsa_sha2_verify(pub, session, hash_len, sig, sig_len,
                                        tampered, sizeof(tampered))) == 0);
        /* a peer that strips leading zero bytes must still verify */
        if(sig[0] == 0)
            EXPECT(ssh2_rsa_sha2_verify(pub, session, hash_len,
                                        sig + 1, sig_len - 1,
                                        msg, sizeof(msg)) == 0);
        /* the other hash must not verify */
        EXPECT(ssh2_rsa_sha2_verify(pub, session,
                                    i ? SSH2_SHA256_DIG_LEN
                                      : SSH2_SHA512_DIG_LEN,
                                    sig, sig_len, msg, sizeof(msg)) != 0);
        SSH2_SAFEFREE(session, sig);
    }

    rc = 0;

fail:
    SSH2_FREE(session, sig);
    ssh2_rsa_free(priv, session);
    ssh2_rsa_free(pub, session);
    ssh2_zero_free(session, data, data_len);
    SSH2_FREE(session, blob);
    return rc;
}
#endif /* LIBSSH2_RSA */

int main(int argc, char *argv[])
{
    LIBSSH2_SESSION *session;
    const char *env;
    int rc;
    (void)argv;
    (void)argc;

    env = getenv("srcdir");
    if(env)
        srcdir = env;

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2_init() failed: %d\n", rc);
        return 1;
    }

    session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "libssh2_session_init() failed\n");
        return 1;
    }

    rc = 0;
#if LIBSSH2_RSA
    rc |= test_rsa(session);
#endif

    libssh2_session_free(session);

    libssh2_exit();

    return rc;
}
