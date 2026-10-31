/* Copyright (C) The libssh2 project and its contributors.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Round-trip tests for the crypto backend API (src/HACKING-CRYPTO.md)
 * that need no SSH server: key loading in the formats under tests/keys,
 * public key derivation, sign/verify, key agreement and ciphers.
 */

#ifdef LIBSSH2_MBEDTLS
/* mbedtls_psa_get_stats() fields are private */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

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
    EXPECT(strcmp(method, expected_method) == 0);
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

/* Every PSA key the backend created must have been destroyed */
static int check_no_key_slots(void)
{
#ifdef LIBSSH2_MBEDTLS
    mbedtls_psa_stats_t stats;

    mbedtls_psa_get_stats(&stats);
    if(stats.MBEDTLS_PRIVATE(volatile_slots) != 0) {
        fprintf(stderr, "%s:%d: %u PSA key slots leaked\n", __FILE__,
                __LINE__, (unsigned)stats.MBEDTLS_PRIVATE(volatile_slots));
        return 1;
    }
#endif
    return 0;
}

static int flip_byte_verify_fails(int verify_rc)
{
    return verify_rc == 0;
}

#if LIBSSH2_RSA
struct rsa_parts {
    unsigned char *n, *e, *d, *p, *q, *e1, *e2, *coeff;
    unsigned int nlen, elen, dlen, plen, qlen, e1len, e2len, coefflen;
};

/* Splits tests/keys/id_rsa_pem into its nine PKCS#1 components; `*raw`
   owns the memory the parts point into. */
static int rsa_split_pem(LIBSSH2_SESSION *session, unsigned char **raw,
                         struct rsa_parts *c)
{
    unsigned char *data, *ver;
    size_t datalen;
    unsigned int verlen;
    int rc = 1;

    *raw = NULL;
    if(ssh2_pem_parse(session, PEM_RSA_HEADER, PEM_RSA_FOOTER,
                      keypath("id_rsa_pem"), NULL, 0, NULL,
                      &data, &datalen, NULL))
        FAIL("pem parse");
    *raw = data;
    EXPECT(ssh2_pem_decode_sequence(&data, &datalen) == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen, &ver, &verlen) == 0);
    EXPECT(verlen == 1 && *ver == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen, &c->n, &c->nlen) == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen, &c->e, &c->elen) == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen, &c->d, &c->dlen) == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen, &c->p, &c->plen) == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen, &c->q, &c->qlen) == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen,
                                   &c->e1, &c->e1len) == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen,
                                   &c->e2, &c->e2len) == 0);
    EXPECT(ssh2_pem_decode_integer(&data, &datalen,
                                   &c->coeff, &c->coefflen) == 0);
    rc = 0;

fail:
    return rc;
}

static int rsa_sign_sha256(LIBSSH2_SESSION *session, ssh2_rsa_ctx *key,
                           const unsigned char *m, size_t m_len,
                           unsigned char **sig, size_t *sig_len)
{
    unsigned char hash[SSH2_SHA256_DIG_LEN];

    if(!ssh2_hash(SSH2_SHA256_ALG, m, m_len, hash, sizeof(hash)))
        return 1;
    return ssh2_rsa_sha2_sign(key, session, hash, sizeof(hash),
                              sig, sig_len);
}

static int rsa_verify_sha256(LIBSSH2_SESSION *session, ssh2_rsa_ctx *key,
                             const unsigned char *sig, size_t sig_len,
                             const unsigned char *m, size_t m_len)
{
    return ssh2_rsa_sha2_verify(key, session, SSH2_SHA256_DIG_LEN,
                                sig, sig_len, m, m_len);
}

/* Full private key built from raw components, the way the OpenSSH key
   parser does, must sign exactly like the one loaded from the file. */
static int check_rsa_from_components(LIBSSH2_SESSION *session,
                                     ssh2_rsa_ctx *ref_key,
                                     ssh2_rsa_ctx *pub)
{
    static const unsigned char msg[] = "components";
    struct rsa_parts c;
    ssh2_rsa_ctx *key = NULL;
    unsigned char *raw = NULL, *sig = NULL, *ref_sig = NULL;
    size_t sig_len = 0, ref_len = 0;
    int rc = 1;

    if(rsa_split_pem(session, &raw, &c))
        goto fail;
    EXPECT(rsa_sign_sha256(session, ref_key, msg, sizeof(msg),
                           &ref_sig, &ref_len) == 0);

    EXPECT(ssh2_rsa_new(&key, session, c.e, c.elen, c.n, c.nlen,
                        c.d, c.dlen, c.p, c.plen, c.q, c.qlen,
                        c.e1, c.e1len, c.e2, c.e2len,
                        c.coeff, c.coefflen) == 0);
    EXPECT(rsa_sign_sha256(session, key, msg, sizeof(msg),
                           &sig, &sig_len) == 0);
    EXPECT(sig_len == ref_len && memcmp(sig, ref_sig, sig_len) == 0);
    EXPECT(rsa_verify_sha256(session, pub, sig, sig_len,
                             msg, sizeof(msg)) == 0);
    SSH2_SAFEFREE(session, sig);
    ssh2_rsa_free(key, session);
    key = NULL;

    /* OpenSSH-format keys carry no dP, dQ, qInv: they are derived */
    EXPECT(ssh2_rsa_new(&key, session, c.e, c.elen, c.n, c.nlen,
                        c.d, c.dlen, c.p, c.plen, c.q, c.qlen,
                        NULL, 0, NULL, 0, NULL, 0) == 0);
    EXPECT(rsa_sign_sha256(session, key, msg, sizeof(msg),
                           &sig, &sig_len) == 0);
    EXPECT(sig_len == ref_len && memcmp(sig, ref_sig, sig_len) == 0);
    rc = 0;

fail:
    SSH2_FREE(session, sig);
    SSH2_FREE(session, ref_sig);
    ssh2_rsa_free(key, session);
    SSH2_FREE(session, raw);
    return rc;
}

/* Verifies with a key built the way src/hostkey.c does: e and n straight
   off the wire as SSH strings, sign byte included. */
static int check_rsa_hostkey_blob(LIBSSH2_SESSION *session,
                                  const unsigned char *blob, size_t blob_len,
                                  ssh2_rsa_ctx *priv)
{
    static const unsigned char msg[] = "hostkey";
    struct string_buf buf;
    unsigned char *name, *e, *n, *sig = NULL;
    size_t name_len, e_len, n_len, sig_len = 0;
    ssh2_rsa_ctx *pub = NULL;
    int rc = 1;

    buf.data = buf.dataptr = (unsigned char *)SSH2_UNCONST(blob);
    buf.len = blob_len;
    EXPECT(ssh2_get_string(&buf, &name, &name_len) == 0);
    EXPECT(ssh2_get_string(&buf, &e, &e_len) == 0);
    EXPECT(ssh2_get_string(&buf, &n, &n_len) == 0);
    EXPECT(n_len > 0 && n[0] == 0);  /* sign byte present */
    EXPECT(ssh2_rsa_new(&pub, session, e, e_len, n, n_len,
                        NULL, 0, NULL, 0, NULL, 0,
                        NULL, 0, NULL, 0, NULL, 0) == 0);
    EXPECT(rsa_sign_sha256(session, priv, msg, sizeof(msg),
                           &sig, &sig_len) == 0);
    EXPECT(rsa_verify_sha256(session, pub, sig, sig_len,
                             msg, sizeof(msg)) == 0);
    rc = 0;

fail:
    SSH2_FREE(session, sig);
    ssh2_rsa_free(pub, session);
    return rc;
}

/* Signatures that start with a zero byte: peers strip it or pad it */
static int check_rsa_leading_zero(LIBSSH2_SESSION *session,
                                  ssh2_rsa_ctx *priv, ssh2_rsa_ctx *pub)
{
    unsigned char *sig = NULL, *alt = NULL;
    size_t sig_len = 0;
    char msg[16];
    int i, rc = 1;

    for(i = 0; i < 2000; i++) {
        snprintf(msg, sizeof(msg), "m%d", i);
        EXPECT(rsa_sign_sha256(session, priv, (unsigned char *)msg,
                               strlen(msg), &sig, &sig_len) == 0);
        if(sig[0] == 0)
            break;
        SSH2_SAFEFREE(session, sig);
    }
    EXPECT(sig);  /* found a message with sig[0] == 0 */
    fprintf(stderr, "leading-zero signature at m%d\n", i);

    EXPECT(rsa_verify_sha256(session, pub, sig, sig_len,
                             (unsigned char *)msg, strlen(msg)) == 0);
#ifdef LIBSSH2_MBEDTLS
    /* only this backend promises to take stripped and padded signatures */
    EXPECT(rsa_verify_sha256(session, pub, sig + 1, sig_len - 1,
                             (unsigned char *)msg, strlen(msg)) == 0);

    alt = SSH2_CALLOC(session, sig_len + 1);
    EXPECT(alt);
    memcpy(alt + 1, sig, sig_len);
    EXPECT(rsa_verify_sha256(session, pub, alt, sig_len + 1,
                             (unsigned char *)msg, strlen(msg)) == 0);
    alt[0] = 1;
    EXPECT(rsa_verify_sha256(session, pub, alt, sig_len + 1,
                             (unsigned char *)msg, strlen(msg)) != 0);
#endif
    rc = 0;

fail:
    SSH2_FREE(session, sig);
    SSH2_FREE(session, alt);
    return rc;
}

/* Error paths must not leak PSA key slots (32 volatile ones by default) */
static int check_rsa_slot_hygiene(LIBSSH2_SESSION *session)
{
    static const unsigned char tiny_n[] = { 0x05 }, tiny_e[] = { 0x03 };
    ssh2_rsa_ctx *key = NULL;
    char *method = NULL;
    unsigned char *pubkey = NULL;
    size_t pubkey_len = 0;
    int i, rc = 1;

    for(i = 0; i < 48; i++) {
        EXPECT(ssh2_rsa_new_priv(&key, session, keypath("id_rsa_pem"),
                                 NULL, 0, NULL) == 0);
        ssh2_rsa_free(key, session);
        key = NULL;

        EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                                keypath("id_rsa_pem"), NULL, 0, NULL) == 0);
        SSH2_SAFEFREE(session, method);
        SSH2_SAFEFREE(session, pubkey);

        EXPECT(ssh2_rsa_new(&key, session, tiny_e, 1, tiny_n, 1,
                            NULL, 0, NULL, 0, NULL, 0,
                            NULL, 0, NULL, 0, NULL, 0) != 0);
        EXPECT(!key);

        EXPECT(ssh2_rsa_new_priv(&key, session,
                                 keypath("id_rsa_pem_encrypted"),
                                 NULL, 0, "wrong") != 0);
        EXPECT(!key);
        EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                                keypath("id_rsa_pem_encrypted"),
                                NULL, 0, "wrong") != 0);
    }

    EXPECT(ssh2_rsa_new_priv(&key, session, keypath("id_rsa_pem"),
                             NULL, 0, NULL) == 0);
    rc = 0;

fail:
    ssh2_rsa_free(key, session);
    SSH2_FREE(session, method);
    SSH2_FREE(session, pubkey);
    return rc;
}

static int check_rsa_edges(LIBSSH2_SESSION *session,
                           const unsigned char *blob, size_t blob_len,
                           ssh2_rsa_ctx *priv, ssh2_rsa_ctx *pub)
{
    static const unsigned char msg[] = "tamper";
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    ssh2_rsa_ctx *wrong = NULL;
    char *method = NULL;
    unsigned char *pubkey = NULL;
    size_t pubkey_len = 0;
    int rc = 1;

    if(check_rsa_from_components(session, priv, pub) ||
       check_rsa_hostkey_blob(session, blob, blob_len, priv) ||
       check_rsa_leading_zero(session, priv, pub))
        goto fail;

    /* one flipped byte in the middle of the signature */
    EXPECT(rsa_sign_sha256(session, priv, msg, sizeof(msg),
                           &sig, &sig_len) == 0);
    EXPECT(rsa_verify_sha256(session, pub, sig, sig_len,
                             msg, sizeof(msg)) == 0);
    sig[sig_len / 2] ^= 0x40;
    EXPECT(rsa_verify_sha256(session, pub, sig, sig_len,
                             msg, sizeof(msg)) != 0);

    /* an ECDSA key is not an RSA key */
    EXPECT(ssh2_rsa_new_priv(&wrong, session, keypath("id_ecdsa_pem"),
                             NULL, 0, NULL) != 0);
    EXPECT(!wrong);

    EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                            keypath("id_rsa_pem_encrypted"), NULL, 0,
                            "wrong") != 0);

    if(check_rsa_slot_hygiene(session))
        goto fail;
    rc = 0;

fail:
    SSH2_FREE(session, sig);
    SSH2_FREE(session, method);
    SSH2_FREE(session, pubkey);
    return rc;
}

/* RSA-SHA1 is compiled out unless LIBSSH2_RSA_SHA1_ENABLE is defined;
   the SHA-1 entry points are not covered here. */

static int test_rsa(LIBSSH2_SESSION *session)
{
    static const struct {
        const char *name;
        const char *passphrase;
    } keys[] = {
        { "id_rsa_pem", NULL },
#if LIBSSH2_MD5_PEM && LIBSSH2_AES_CBC
        { "id_rsa_pem_encrypted", "libssh2" },
#endif
#if !defined(LIBSSH2_LIBGCRYPT) && !defined(LIBSSH2_WINCNG)
        { "id_rsa_pkcs8", NULL },
        { "id_rsa_pkcs8_encrypted", "libssh2" },
#endif
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

    if(check_rsa_edges(session, blob, blob_len, priv, pub))
        goto fail;

    ssh2_rsa_free(priv, session);
    ssh2_rsa_free(pub, session);
    priv = pub = NULL;
    if(check_no_key_slots())
        goto fail;

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

#if LIBSSH2_ECDSA
static ssh2_hash_alg curve_hash(size_t bits, size_t *len)
{
    if(bits == 256) {
        *len = SSH2_SHA256_DIG_LEN;
        return SSH2_SHA256_ALG;
    }
    if(bits == 384) {
        *len = SSH2_SHA384_DIG_LEN;
        return SSH2_SHA384_ALG;
    }
    *len = SSH2_SHA512_DIG_LEN;
    return SSH2_SHA512_ALG;
}

/* Two parties derive the same K from well-formed points */
static int check_ecdh(LIBSSH2_SESSION *session, ssh2_curve_type curve,
                      size_t bits)
{
    ssh2_ec_key *a = NULL, *b = NULL, *c = NULL;
    unsigned char *pub_a = NULL, *pub_b = NULL, *pub_c = NULL;
    unsigned char *ka = NULL, *kb = NULL;
    size_t pub_a_len = 0, pub_b_len = 0, pub_c_len = 0;
    size_t ka_len = 0, kb_len = 0;
    ssh2_bn *k_a = NULL, *k_b = NULL;
    int rc = 1;

    EXPECT(ssh2_ecdsa_create_key(&a, session, &pub_a, &pub_a_len,
                                 curve) == 0);
    EXPECT(ssh2_ecdsa_create_key(&b, session, &pub_b, &pub_b_len,
                                 curve) == 0);
    EXPECT(pub_a_len == 1 + 2 * ((bits + 7) / 8));
    EXPECT(pub_b_len == pub_a_len);
    EXPECT(pub_a[0] == 0x04 && pub_b[0] == 0x04);
    EXPECT(memcmp(pub_a, pub_b, pub_a_len) != 0);

    k_a = ssh2_bn_init();
    k_b = ssh2_bn_init();
    EXPECT(k_a && k_b);
    EXPECT(ssh2_ecdh_gen_k(&k_a, session, a, pub_b, pub_b_len) == 0);
    EXPECT(ssh2_ecdh_gen_k(&k_b, session, b, pub_a, pub_a_len) == 0);

    ka_len = ssh2_bn_bytes(k_a);
    kb_len = ssh2_bn_bytes(k_b);
    EXPECT(ka_len > 0 && ka_len == kb_len);
    ka = SSH2_ALLOC(session, ka_len);
    kb = SSH2_ALLOC(session, kb_len);
    EXPECT(ka && kb);
    ssh2_bn_to_bin(k_a, ka);
    ssh2_bn_to_bin(k_b, kb);
    EXPECT(memcmp(ka, kb, ka_len) == 0);

    /* a point that is not on the curve must be refused */
    pub_b[pub_b_len - 1] ^= 1;
    EXPECT(ssh2_ecdh_gen_k(&k_a, session, a, pub_b, pub_b_len) != 0);

    /* so must a well-formed point of another curve */
    EXPECT(ssh2_ecdsa_create_key(&c, session, &pub_c, &pub_c_len,
                                 curve == SSH2_EC_CURVE_NISTP256 ?
                                 SSH2_EC_CURVE_NISTP384 :
                                 SSH2_EC_CURVE_NISTP256) == 0);
    EXPECT(ssh2_ecdh_gen_k(&k_a, session, a, pub_c, pub_c_len) != 0);

    rc = 0;

fail:
    ssh2_zero_free(session, ka, ka_len);
    ssh2_zero_free(session, kb, kb_len);
    ssh2_bn_free(k_a);
    ssh2_bn_free(k_b);
    ssh2_ecdsa_free(a, session);
    ssh2_ecdsa_free(b, session);
    ssh2_ecdsa_free(c, session);
    SSH2_FREE(session, pub_a);
    SSH2_FREE(session, pub_b);
    SSH2_FREE(session, pub_c);
    return rc;
}

/* An OpenSSH-made P-521 signature (id_ecdsa_openssh_signed-cert.pub, signed
   by ca_user_ecdsa) carries an s with a 0x00 sign byte and a short value,
   passed raw as hostkey.c does. */
static int check_cert_signature(LIBSSH2_SESSION *session)
{
    unsigned char *cert = NULL, *ca = NULL;
    unsigned char *str, *sig, *sigdata, *alg, *r, *s, *point;
    size_t cert_len = 0, ca_len = 0, str_len, sig_len, sigdata_len;
    size_t alg_len, r_len, s_len, point_len, signed_len, i;
    struct string_buf buf, sbuf;
    ssh2_ecdsa_ctx *ca_key = NULL;
    ssh2_curve_type curve;
    libssh2_uint64_t u64;
    uint32_t u32;
    int rc = 1;

    EXPECT(read_pub_blob(session, "id_ecdsa_openssh_signed-cert",
                         &cert, &cert_len) == 0);
    buf.data = buf.dataptr = cert;
    buf.len = cert_len;

    /* type, nonce, curve, Q */
    for(i = 0; i < 4; i++)
        EXPECT(ssh2_get_string(&buf, &str, &str_len) == 0);
    EXPECT(ssh2_get_u64(&buf, &u64) == 0);  /* serial */
    EXPECT(ssh2_get_u32(&buf, &u32) == 0);  /* type */
    /* key id, principals */
    for(i = 0; i < 2; i++)
        EXPECT(ssh2_get_string(&buf, &str, &str_len) == 0);
    EXPECT(ssh2_get_u64(&buf, &u64) == 0);  /* valid after */
    EXPECT(ssh2_get_u64(&buf, &u64) == 0);  /* valid before */
    /* critical options, extensions, reserved, signature key */
    for(i = 0; i < 4; i++)
        EXPECT(ssh2_get_string(&buf, &str, &str_len) == 0);

    signed_len = (size_t)(buf.dataptr - buf.data);
    EXPECT(ssh2_get_string(&buf, &sig, &sig_len) == 0);
    EXPECT(buf.dataptr == buf.data + buf.len);

    sbuf.data = sbuf.dataptr = sig;
    sbuf.len = sig_len;
    EXPECT(ssh2_get_string(&sbuf, &alg, &alg_len) == 0);
    EXPECT(alg_len == 19 && memcmp(alg, "ecdsa-sha2-nistp521", 19) == 0);
    EXPECT(ssh2_get_string(&sbuf, &sigdata, &sigdata_len) == 0);
    sbuf.data = sbuf.dataptr = sigdata;
    sbuf.len = sigdata_len;
    EXPECT(ssh2_get_string(&sbuf, &r, &r_len) == 0);
    EXPECT(ssh2_get_string(&sbuf, &s, &s_len) == 0);
    EXPECT(sbuf.dataptr == sbuf.data + sbuf.len);
    EXPECT(s_len > 1 && s[0] == 0);  /* sign byte */

    EXPECT(read_pub_blob(session, "ca_user_ecdsa", &ca, &ca_len) == 0);
    sbuf.data = sbuf.dataptr = ca;
    sbuf.len = ca_len;
    EXPECT(ssh2_get_string(&sbuf, &alg, &alg_len) == 0);
    EXPECT(ssh2_get_string(&sbuf, &str, &str_len) == 0);
    EXPECT(ssh2_get_string(&sbuf, &point, &point_len) == 0);
    EXPECT(ssh2_pem_ecdsa_curve_type_from_name(
               (const char *)alg, alg_len, &curve) == 0);
    EXPECT(ssh2_ecdsa_curve_name_with_octal_new(
               &ca_key, session, point, point_len, curve) == 0);

    EXPECT(ssh2_ecdsa_verify(ca_key, session, r, r_len, s, s_len,
                             cert, signed_len) == 0);
    EXPECT(ssh2_ecdsa_verify(ca_key, session, r, r_len, s, s_len,
                             cert, signed_len - 1) != 0);

    rc = 0;

fail:
    ssh2_ecdsa_free(ca_key, session);
    SSH2_FREE(session, cert);
    SSH2_FREE(session, ca);
    return rc;
}

#ifdef LIBSSH2_MBEDTLS
/* Keys this backend cannot use must fail cleanly, with the right error */
static int check_pub_privkey_errors(LIBSSH2_SESSION *session)
{
    static const char garbage[] = "this is not a private key\n";
    static const char junk[] = "\xef\xbb\xbf# made by hand\n";
    char *method = NULL, *file = NULL, *pre = NULL;
    unsigned char *pubkey = NULL, *expected = NULL;
    size_t pubkey_len = 0, file_len = 0, expected_len = 0;
    int rc = 1;

    /* OpenSSH-format RSA is not read by this backend */
    EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                            keypath("id_rsa_openssh"), NULL, 0, NULL) != 0);
    EXPECT(!method && !pubkey && pubkey_len == 0);

    EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                            NULL, garbage, sizeof(garbage) - 1, NULL) ==
           LIBSSH2_ERROR_FILE);
    EXPECT(!method && !pubkey && pubkey_len == 0);

    /* encrypted PKCS#8: wrong and missing passphrase */
    EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                            keypath("id_ecdsa_pkcs8_encrypted"), NULL, 0,
                            "wrong") == LIBSSH2_ERROR_KEYFILE_AUTH_FAILED);
    EXPECT(!method && !pubkey && pubkey_len == 0);
    EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                            keypath("id_ecdsa_pkcs8_encrypted"), NULL, 0,
                            NULL) == LIBSSH2_ERROR_KEYFILE_AUTH_FAILED);
    EXPECT(!method && !pubkey && pubkey_len == 0);

    /* a byte order mark and a comment before an OpenSSH header */
    EXPECT(read_pub_blob(session, "id_ecdsa_openssh",
                         &expected, &expected_len) == 0);
    EXPECT(ssh2_file_to_blob(session, keypath("id_ecdsa_openssh"),
                             &file, &file_len) == 0);
    pre = SSH2_ALLOC(session, file_len + sizeof(junk));
    EXPECT(pre);
    memcpy(pre, junk, sizeof(junk) - 1);
    memcpy(pre + sizeof(junk) - 1, file, file_len);
    EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len, NULL,
                            pre, file_len + sizeof(junk) - 1, NULL) == 0);
    EXPECT(pubkey_len == expected_len);
    EXPECT(memcmp(pubkey, expected, expected_len) == 0);
    rc = 0;

fail:
    SSH2_FREE(session, method);
    SSH2_FREE(session, pubkey);
    SSH2_FREE(session, expected);
    SSH2_FREE(session, pre);
    ssh2_zero_free(session, file, file_len + 1);
    return rc;
}
#endif

#ifdef LIBSSH2_MBEDTLS
/* A wrong passphrase on an OpenSSH key and a key of another type are
   reported as such by every loader */
static int check_loader_errors(LIBSSH2_SESSION *session)
{
    char *method = NULL;
    unsigned char *pubkey = NULL;
    size_t pubkey_len = 0;
    ssh2_ecdsa_ctx *ec = NULL;
    int rc = 1;

    EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                            keypath("id_ecdsa_openssh_encrypted"),
                            NULL, 0, "wrong") ==
           LIBSSH2_ERROR_KEYFILE_AUTH_FAILED);
    EXPECT(libssh2_session_last_errno(session) ==
           LIBSSH2_ERROR_KEYFILE_AUTH_FAILED);
    EXPECT(!method && !pubkey && pubkey_len == 0);

    /* OpenSSH RSA: an unsupported key type */
    EXPECT(ssh2_ecdsa_new_priv(&ec, session, keypath("id_rsa_openssh"),
                               NULL, 0, NULL) == -1);
    EXPECT(libssh2_session_last_errno(session) == LIBSSH2_ERROR_FILE);
    EXPECT(!ec);
    EXPECT(ssh2_pub_privkey(session, &method, &pubkey, &pubkey_len,
                            keypath("id_rsa_openssh"), NULL, 0, NULL) != 0);
    EXPECT(libssh2_session_last_errno(session) == LIBSSH2_ERROR_FILE);
    EXPECT(!method && !pubkey && pubkey_len == 0);

#if LIBSSH2_RSA
    {
        ssh2_rsa_ctx *rsa = NULL;

        EXPECT(ssh2_ecdsa_new_priv(&ec, session, keypath("id_rsa_pem"),
                                   NULL, 0, NULL) == -1);
        EXPECT(libssh2_session_last_errno(session) == LIBSSH2_ERROR_FILE);
        EXPECT(!ec);
        EXPECT(ssh2_rsa_new_priv(&rsa, session, keypath("id_ecdsa_pem"),
                                 NULL, 0, NULL) == -1);
        EXPECT(libssh2_session_last_errno(session) == LIBSSH2_ERROR_FILE);
        EXPECT(!rsa);
    }
#endif
    rc = 0;

fail:
    SSH2_FREE(session, method);
    SSH2_FREE(session, pubkey);
    ssh2_ecdsa_free(ec, session);
    return rc;
}
#endif

static int test_ecdsa(LIBSSH2_SESSION *session)
{
    static const struct {
        const char *name;
        const char *passphrase;
        const char *method;
        size_t bits;
        ssh2_curve_type curve;
    } keys[] = {
        { "id_ecdsa_pem", NULL, "ecdsa-sha2-nistp521", 521,
          SSH2_EC_CURVE_NISTP521 },
#if !defined(LIBSSH2_LIBGCRYPT) && !defined(LIBSSH2_WINCNG)
        { "id_ecdsa_pkcs8", NULL, "ecdsa-sha2-nistp384", 384,
          SSH2_EC_CURVE_NISTP384 },
        { "id_ecdsa_pkcs8_encrypted", "libssh2", "ecdsa-sha2-nistp521", 521,
          SSH2_EC_CURVE_NISTP521 },
#endif
        { "id_ecdsa_openssh", NULL, "ecdsa-sha2-nistp384", 384,
          SSH2_EC_CURVE_NISTP384 },
#if LIBSSH2_MD5_PEM && LIBSSH2_AES_CBC
        { "id_ecdsa_pem_encrypted", "libssh2", "ecdsa-sha2-nistp256", 256,
          SSH2_EC_CURVE_NISTP256 },
#endif
        { "id_ecdsa_openssh_encrypted", "libssh2", "ecdsa-sha2-nistp256", 256,
          SSH2_EC_CURVE_NISTP256 },
        /* OpenSSH format: 66-byte P-521 scalar padding, unencrypted P-256 */
        { "ca_user_ecdsa", NULL, "ecdsa-sha2-nistp521", 521,
          SSH2_EC_CURVE_NISTP521 },
        { "ca_host_ecdsa", NULL, "ecdsa-sha2-nistp256", 256,
          SSH2_EC_CURVE_NISTP256 }
    };
    static const ssh2_curve_type curves[] = {
        SSH2_EC_CURVE_NISTP256, SSH2_EC_CURVE_NISTP384, SSH2_EC_CURVE_NISTP521
    };
    static const size_t curve_bits[] = { 256, 384, 521 };
    const unsigned char msg[] = "the quick brown fox";
    unsigned char tampered[sizeof(msg)];
    unsigned char hash[SSH2_SHA512_DIG_LEN];
    ssh2_ecdsa_ctx *priv = NULL, *pub = NULL, *bad = NULL;
    unsigned char *blob = NULL, *sig = NULL;
    unsigned char *name, *cname, *point, *r, *s, *r_raw, *s_raw;
    unsigned char big[67];
    char *data = NULL;
    size_t blob_len = 0, sig_len = 0, name_len, cname_len, point_len;
    size_t r_len, s_len, r_raw_len, s_raw_len, n_len;
    size_t data_len = 0, hash_len, i;
    struct string_buf buf;
    ssh2_curve_type curve;
    int rc = 1;

    for(i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        ssh2_hash_alg alg;

        /* public key derivation, from file and from memory */
        if(check_pub_privkey(session, keys[i].name, keys[i].passphrase,
                             keys[i].method, &blob, &blob_len))
            goto fail;

        /* private key loading, file and memory */
        if(ssh2_ecdsa_new_priv(&priv, session, keypath(keys[i].name),
                               NULL, 0, keys[i].passphrase))
            FAIL(keys[i].name);
        EXPECT(ssh2_ecdsa_get_curve_type(priv) == keys[i].curve);
        ssh2_ecdsa_free(priv, session);
        priv = NULL;

        EXPECT(ssh2_file_to_blob(session, keypath(keys[i].name),
                                 &data, &data_len) == 0);
        if(ssh2_ecdsa_new_priv(&priv, session, NULL, data, data_len,
                               keys[i].passphrase))
            FAIL(keys[i].name);
        EXPECT(ssh2_ecdsa_get_curve_type(priv) == keys[i].curve);
        ssh2_zero_free(session, data, data_len);
        data = NULL;

        /* public key from the wire blob: method || curve || point */
        buf.data = buf.dataptr = blob;
        buf.len = blob_len;
        EXPECT(ssh2_get_string(&buf, &name, &name_len) == 0);
        EXPECT(ssh2_get_string(&buf, &cname, &cname_len) == 0);
        EXPECT(ssh2_get_string(&buf, &point, &point_len) == 0);
        EXPECT(ssh2_pem_ecdsa_curve_type_from_name(
                   (const char *)name, name_len, &curve) == 0);
        EXPECT(curve == keys[i].curve);
        EXPECT(ssh2_ecdsa_curve_name_with_octal_new(
                   &pub, session, point, point_len, curve) == 0);
        EXPECT(ssh2_ecdsa_get_curve_type(pub) == keys[i].curve);

        /* a truncated point must be refused */
        EXPECT(ssh2_ecdsa_curve_name_with_octal_new(
                   &bad, session, point, point_len - 1, curve) != 0);
        EXPECT(!bad);

        /* so must a point that belongs to another curve */
        EXPECT(ssh2_ecdsa_curve_name_with_octal_new(
                   &bad, session, point, point_len,
                   curve == SSH2_EC_CURVE_NISTP384 ?
                   SSH2_EC_CURVE_NISTP256 : SSH2_EC_CURVE_NISTP384) != 0);
        EXPECT(!bad);

        /* sign and verify with the curve's hash */
        alg = curve_hash(keys[i].bits, &hash_len);
        EXPECT(ssh2_hash(alg, msg, sizeof(msg), hash, hash_len));
        EXPECT(ssh2_ecdsa_sign(priv, session, hash, hash_len,
                               &sig, &sig_len) == 0);

        buf.data = buf.dataptr = sig;
        buf.len = sig_len;
        EXPECT(ssh2_get_bignum_bytes(&buf, &r, &r_len) == 0);
        EXPECT(ssh2_get_bignum_bytes(&buf, &s, &s_len) == 0);
        EXPECT(buf.dataptr == buf.data + buf.len);

        /* the same r and s as raw mpints, sign byte included */
        buf.data = buf.dataptr = sig;
        buf.len = sig_len;
        EXPECT(ssh2_get_string(&buf, &r_raw, &r_raw_len) == 0);
        EXPECT(ssh2_get_string(&buf, &s_raw, &s_raw_len) == 0);
        EXPECT(ssh2_ecdsa_verify(pub, session, r_raw, r_raw_len,
                                 s_raw, s_raw_len,
                                 msg, sizeof(msg)) == 0);

        EXPECT(ssh2_ecdsa_verify(pub, session, r, r_len, s, s_len,
                                 msg, sizeof(msg)) == 0);
        EXPECT(ssh2_ecdsa_verify(priv, session, r, r_len, s, s_len,
                                 msg, sizeof(msg)) == 0);

        memcpy(tampered, msg, sizeof(msg));
        tampered[3] ^= 1;
        EXPECT(ssh2_ecdsa_verify(pub, session, r, r_len, s, s_len,
                                 tampered, sizeof(tampered)) != 0);
        EXPECT(ssh2_ecdsa_verify(pub, session, s, s_len, r, r_len,
                                 msg, sizeof(msg)) != 0);

        /* r or s above the group order, or zero, must be refused */
        n_len = (keys[i].bits + 7) / 8;
        memset(big, 0xAA, sizeof(big));
        big[0] = 1;
        EXPECT(ssh2_ecdsa_verify(pub, session, big, n_len + 1, s, s_len,
                                 msg, sizeof(msg)) != 0);
        EXPECT(ssh2_ecdsa_verify(pub, session, r, r_len, big, n_len + 1,
                                 msg, sizeof(msg)) != 0);
        memset(big, 0, sizeof(big));
        EXPECT(ssh2_ecdsa_verify(pub, session, big, 1, s, s_len,
                                 msg, sizeof(msg)) != 0);
        EXPECT(ssh2_ecdsa_verify(pub, session, r, r_len, big, 1,
                                 msg, sizeof(msg)) != 0);

        /* the digest must match the curve */
        SSH2_SAFEFREE(session, sig);
        EXPECT(ssh2_ecdsa_sign(priv, session, hash, 20,
                               &sig, &sig_len) != 0);
        SSH2_SAFEFREE(session, sig);
        SSH2_SAFEFREE(session, blob);
        ssh2_ecdsa_free(priv, session);
        ssh2_ecdsa_free(pub, session);
        priv = pub = NULL;
    }

    /* wrong passphrase must fail */
    EXPECT(ssh2_ecdsa_new_priv(&priv, session,
                               keypath("id_ecdsa_pem_encrypted"),
                               NULL, 0, "wrong") != 0);
    EXPECT(!priv);
    EXPECT(ssh2_ecdsa_new_priv(&priv, session,
                               keypath("id_ecdsa_openssh_encrypted"),
                               NULL, 0, "wrong") != 0);
#ifdef LIBSSH2_MBEDTLS
    EXPECT(libssh2_session_last_errno(session) ==
           LIBSSH2_ERROR_KEYFILE_AUTH_FAILED);
#endif
    EXPECT(!priv);

    /* ECDH on every curve */
    for(i = 0; i < sizeof(curves) / sizeof(curves[0]); i++)
        if(check_ecdh(session, curves[i], curve_bits[i]))
            goto fail;

    if(check_cert_signature(session))
        goto fail;

#ifdef LIBSSH2_MBEDTLS
    if(check_pub_privkey_errors(session))
        goto fail;
    if(check_loader_errors(session))
        goto fail;
#endif

    ssh2_ecdsa_free(priv, session);
    ssh2_ecdsa_free(pub, session);
    priv = pub = NULL;
    if(check_no_key_slots())
        goto fail;

    rc = 0;

fail:
    SSH2_FREE(session, sig);
    ssh2_ecdsa_free(priv, session);
    ssh2_ecdsa_free(pub, session);
    ssh2_zero_free(session, data, data_len);
    SSH2_FREE(session, blob);
    return rc;
}
#endif /* LIBSSH2_ECDSA */

/* Known-answer vectors: SHA-256 and HMAC-SHA-256 (RFC 4231 case 2) */
static int test_hash_hmac(void)
{
    static const unsigned char sha_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    static const unsigned char hmac_exp[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };
    unsigned char key[4] = { 'J', 'e', 'f', 'e' };
    const char *data = "what do ya want for nothing?";
    unsigned char out[32];
    ssh2_hash_ctx hctx;
    ssh2_hmac_ctx mctx;
    int rc = 1;

    EXPECT(ssh2_hash(SSH2_SHA256_ALG, "abc", 3, out, sizeof(out)));
    EXPECT(memcmp(out, sha_abc, sizeof(out)) == 0);

    memset(out, 0, sizeof(out));
    EXPECT(ssh2_hash_init(&hctx, SSH2_SHA256_ALG));
    EXPECT(ssh2_hash_update(&hctx, "a", 1));
    EXPECT(ssh2_hash_update(&hctx, "bc", 2));
    EXPECT(ssh2_hash_final(&hctx, out, sizeof(out)));
    EXPECT(memcmp(out, sha_abc, sizeof(out)) == 0);

    memset(out, 0, sizeof(out));
    EXPECT(ssh2_hmac_ctx_init(&mctx));
    EXPECT(ssh2_hmac_init(&mctx, SSH2_SHA256_HMAC, key, sizeof(key)));
    EXPECT(ssh2_hmac_update(&mctx, data, strlen(data)));
    EXPECT(ssh2_hmac_final(&mctx, out, sizeof(out)));
    ssh2_hmac_cleanup(&mctx);
    EXPECT(memcmp(out, hmac_exp, sizeof(out)) == 0);

    rc = 0;

fail:
    return rc;
}

#if LIBSSH2_AES_CTR || LIBSSH2_AES_CBC
static const unsigned char nist_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const unsigned char nist_pt[2][16] = {
    { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a },
    { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
      0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }
};

/* Two chunks through one context: state must carry across calls */
static int cipher_kat(SSH2_CIPHER_T(algo), unsigned char *iv,
                      const unsigned char ct[2][16])
{
    ssh2_cipher_ctx c;
    unsigned char buf[2][16];
    int i, rc = 1;

    memcpy(buf, nist_pt, sizeof(buf));
    if(ssh2_cipher_init(&c, algo, iv, SSH2_UNCONST(nist_key), 1))
        FAIL("cipher init");
    for(i = 0; i < 2; i++) {
        if(ssh2_cipher_crypt(&c, algo, 1, buf[i], 16, MIDDLE_BLOCK)) {
            ssh2_cipher_dtor(&c);
            FAIL("cipher crypt");
        }
    }
    ssh2_cipher_dtor(&c);
    EXPECT(memcmp(buf, ct, sizeof(buf)) == 0);

    /* and back */
    if(ssh2_cipher_init(&c, algo, iv, SSH2_UNCONST(nist_key), 0))
        FAIL("cipher init");
    for(i = 0; i < 2; i++) {
        if(ssh2_cipher_crypt(&c, algo, 0, buf[i], 16, MIDDLE_BLOCK)) {
            ssh2_cipher_dtor(&c);
            FAIL("cipher crypt");
        }
    }
    ssh2_cipher_dtor(&c);
    EXPECT(memcmp(buf, nist_pt, sizeof(buf)) == 0);

    rc = 0;

fail:
    return rc;
}
#endif

#if LIBSSH2_AES_CTR
/* NIST SP 800-38A F.5.1, CTR-AES128 */
static int test_aes_ctr_kat(void)
{
    static const unsigned char ctr[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    static const unsigned char ct[2][16] = {
        { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
          0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce },
        { 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
          0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff }
    };
    SSH2_CIPHER_T(algo) = ssh2_cipher_aes128ctr;
    unsigned char iv[16];

    memcpy(iv, ctr, sizeof(iv));
    return cipher_kat(algo, iv, ct);
}
#endif

#if LIBSSH2_AES_CBC
/* NIST SP 800-38A F.2.1, CBC-AES128 */
static int test_aes_cbc_kat(void)
{
    static const unsigned char ct[2][16] = {
        { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
          0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d },
        { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
          0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 }
    };
    SSH2_CIPHER_T(algo) = ssh2_cipher_aes128;
    unsigned char iv[16];
    int i;

    for(i = 0; i < 16; i++)
        iv[i] = (unsigned char)i;
    return cipher_kat(algo, iv, ct);
}
#endif

/* PSA has 32 volatile key slots: many init/crypt/dtor rounds only work
   if every round gives its slot back. FIRST_BLOCK leaves a GCM operation
   active, so this also checks that dtor aborts it. */
/* Algorithm values are brace initialisers on some backends, so they can
   only be written in an initialiser: keep them in tables. */
struct cipher_case {
    const char *name;
    SSH2_CIPHER_T(algo);
    size_t keylen;
    size_t ivlen;
    size_t bs;
};

static int cipher_slot_loop(const struct cipher_case *cc)
{
    const char *name = cc->name;
    SSH2_CIPHER_T(algo) = cc->algo;
    size_t bs = cc->bs;
    unsigned char key[32], iv[16], buf[16];
    ssh2_cipher_ctx c;
    int i;

    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));
    for(i = 0; i < 48; i++) {
        memset(buf, 0, sizeof(buf));
        if(ssh2_cipher_init(&c, algo, iv, key, i & 1)) {
            fprintf(stderr, "%s: init failed in round %d\n", name, i);
            return 1;
        }
        if(ssh2_cipher_crypt(&c, algo, i & 1, buf, bs, FIRST_BLOCK)) {
            fprintf(stderr, "%s: crypt failed in round %d\n", name, i);
            ssh2_cipher_dtor(&c);
            return 1;
        }
        ssh2_cipher_dtor(&c);
    }
    return 0;
}

#ifdef LIBSSH2_MBEDTLS
/* Bare, double and failed-init teardown must all be harmless */
static int check_cipher_edges(void)
{
    ssh2_cipher_ctx c;
    unsigned char key[32] = { 0 }, iv[16] = { 0 }, buf[17] = { 0 };
    int rc = 1;

    memset(&c, 0, sizeof(c));
    ssh2_cipher_dtor(&c);
    ssh2_cipher_dtor(&c);

    /* the enum value exists for the API but the backend has no
       ChaCha20-Poly1305 yet */
    EXPECT(ssh2_cipher_init(&c, ssh2_cipher_chacha20, iv, key, 1) != 0);
    ssh2_cipher_dtor(&c);
    EXPECT(check_no_key_slots() == 0);

#if LIBSSH2_AES_CBC
    /* transport only passes whole blocks; PSA would hold a partial
       one back, so the length check in crypt() rejects it */
    EXPECT(ssh2_cipher_init(&c, ssh2_cipher_aes128, iv, key, 1) == 0);
    EXPECT(ssh2_cipher_crypt(&c, ssh2_cipher_aes128, 1, buf, 15,
                             MIDDLE_BLOCK) == -1);
    ssh2_cipher_dtor(&c);
    EXPECT(ssh2_cipher_init(&c, ssh2_cipher_aes128, iv, key, 1) == 0);
    EXPECT(ssh2_cipher_crypt(&c, ssh2_cipher_aes128, 1, buf, 17,
                             MIDDLE_BLOCK) == -1);
    ssh2_cipher_dtor(&c);
#else
    (void)buf;
#endif
    rc = 0;
fail:
    return rc;
}
#endif

static int test_cipher_slots(void)
{
    static const struct cipher_case cases[] = {
#if LIBSSH2_AES_CTR
        { "aes128-ctr", ssh2_cipher_aes128ctr, 16, 16, 16 },
        { "aes256-ctr", ssh2_cipher_aes256ctr, 32, 16, 16 },
#endif
#if LIBSSH2_AES_CBC
        { "aes128-cbc", ssh2_cipher_aes128, 16, 16, 16 },
        { "aes256-cbc", ssh2_cipher_aes256, 32, 16, 16 },
#endif
#if LIBSSH2_3DES
        { "3des-cbc", ssh2_cipher_3des, 24, 8, 8 },
#endif
#if LIBSSH2_AES_GCM
        { "aes128-gcm", ssh2_cipher_aes128gcm, 16, 12, 16 },
        { "aes256-gcm", ssh2_cipher_aes256gcm, 32, 12, 16 },
#endif
        { NULL }
    };
    int rc = 0;
    size_t i;

    for(i = 0; cases[i].name; i++)
        rc |= cipher_slot_loop(&cases[i]);
#ifdef LIBSSH2_MBEDTLS
    rc |= check_cipher_edges();
#endif
    rc |= check_no_key_slots();
    return rc;
}

#if LIBSSH2_AES_CTR || LIBSSH2_AES_CBC || LIBSSH2_3DES
/* The transport hands the cipher one block per call; only mbedTLS is
   asked to cope with several blocks at once. */
static int crypt_chunk(ssh2_cipher_ctx *c, SSH2_CIPHER_T(algo), int encrypt,
                       unsigned char *buf, size_t len, size_t bs)
{
#ifdef LIBSSH2_MBEDTLS
    (void)bs;
    return ssh2_cipher_crypt(c, algo, encrypt, buf, len, MIDDLE_BLOCK);
#else
    size_t off;

    for(off = 0; off < len; off += bs) {
        if(ssh2_cipher_crypt(c, algo, encrypt, buf + off, bs, MIDDLE_BLOCK))
            return -1;
    }
    return 0;
#endif
}

/* Random key and IV, four chunks of different multiples of the block
   size, in place; a second context decrypts chunk by chunk. */
static int cipher_roundtrip(const struct cipher_case *cc)
{
    const char *name = cc->name;
    SSH2_CIPHER_T(algo) = cc->algo;
    size_t keylen = cc->keylen, ivlen = cc->ivlen, bs = cc->bs;
    unsigned char key[32], iv[16], plain[512], buf[512];
    const size_t mult[4] = { 1, 3, 2, 5 };
    ssh2_cipher_ctx enc;
    ssh2_cipher_ctx dec;
    size_t i, off, total = 0;
    int have_enc = 0, have_dec = 0, rc = 1;

    for(i = 0; i < 4; i++)
        total += mult[i] * bs;

    EXPECT(ssh2_random(key, keylen) == 0);
    EXPECT(ssh2_random(iv, ivlen) == 0);
    EXPECT(ssh2_random(plain, total) == 0);
    memcpy(buf, plain, total);

    if(ssh2_cipher_init(&enc, algo, iv, key, 1))
        FAIL(name);
    have_enc = 1;
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;

    off = 0;
    for(i = 0; i < 4; i++) {
        if(crypt_chunk(&enc, algo, 1, buf + off, mult[i] * bs, bs))
            FAIL(name);
        off += mult[i] * bs;
    }
    EXPECT(memcmp(buf, plain, total) != 0);

    /* a flipped ciphertext byte must not decrypt to the original */
    buf[total / 2] ^= 0x01;
    off = 0;
    for(i = 0; i < 4; i++) {
        if(crypt_chunk(&dec, algo, 0, buf + off, mult[i] * bs, bs))
            FAIL(name);
        off += mult[i] * bs;
    }
    EXPECT(memcmp(buf, plain, total) != 0);

    /* now the undamaged path */
    ssh2_cipher_dtor(&dec);
    have_dec = 0;
    ssh2_cipher_dtor(&enc);
    have_enc = 0;
    memcpy(buf, plain, total);
    if(ssh2_cipher_init(&enc, algo, iv, key, 1))
        FAIL(name);
    have_enc = 1;
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    off = 0;
    for(i = 0; i < 4; i++) {
        if(crypt_chunk(&enc, algo, 1, buf + off, mult[i] * bs, bs))
            FAIL(name);
        off += mult[i] * bs;
    }
    off = 0;
    for(i = 0; i < 4; i++) {
        if(crypt_chunk(&dec, algo, 0, buf + off, mult[i] * bs, bs))
            FAIL(name);
        off += mult[i] * bs;
    }
    EXPECT(memcmp(buf, plain, total) == 0);
    rc = 0;

fail:
    if(have_enc)
        ssh2_cipher_dtor(&enc);
    if(have_dec)
        ssh2_cipher_dtor(&dec);
    return rc;
}

static int test_cipher_roundtrips(void)
{
    static const struct cipher_case cases[] = {
#if LIBSSH2_AES_CTR
        { "aes128-ctr", ssh2_cipher_aes128ctr, 16, 16, 16 },
        { "aes192-ctr", ssh2_cipher_aes192ctr, 24, 16, 16 },
        { "aes256-ctr", ssh2_cipher_aes256ctr, 32, 16, 16 },
#endif
#if LIBSSH2_AES_CBC
        { "aes128-cbc", ssh2_cipher_aes128, 16, 16, 16 },
        { "aes192-cbc", ssh2_cipher_aes192, 24, 16, 16 },
        { "aes256-cbc", ssh2_cipher_aes256, 32, 16, 16 },
#endif
#if LIBSSH2_3DES
        /* LIBSSH2_3DES is forced to 0 unless LIBSSH2_3DES_ENABLE is
           defined (for example -DLIBSSH2_3DES_ENABLE=ON with CMake), so
           this case only runs in builds that opt in. */
        { "3des-cbc", ssh2_cipher_3des, 24, 8, 8 },
#endif
        { NULL }
    };
    int rc = 0;
    size_t i;

    for(i = 0; cases[i].name; i++)
        rc |= cipher_roundtrip(&cases[i]);
    return rc;
}
#endif

#if LIBSSH2_AES_GCM
/* AES-GCM as driven by src/transport.c (blocksize 16, 16-byte tag, flags
   INTEGRATED_MAC | PKTLEN_AAD), for a packet of L = 4 + 16*k bytes
   (4-byte length, then k blocks) followed by a 16-byte tag slot:
   send: crypt() on every 16-byte slice of [0, L) at offset i, the last
         one only 4 bytes; FIRST_BLOCK for i == 0, else MIDDLE_BLOCK;
         then one crypt() of the 16 tag bytes at offset L, LAST_BLOCK.
         Bytes 0-3 are AAD (left in the clear), the tag is written.
   recv: the first 16 bytes with FIRST_BLOCK, then either of two shapes
         (transport_decrypt() in src/transport.c). Whole packet buffered
         (numdecrypt covers payload and tag, LAST_BLOCK): 16-byte
         MIDDLE_BLOCK slices while 32 or more bytes remain, then the rest
         (4 payload + tag = 20 bytes) as one LAST_BLOCK call. Tag not yet
         buffered (the MIDDLE_BLOCK numdecrypt is capped to leave one block
         for the tag): m 16-byte MIDDLE_BLOCK slices and a 4-byte
         MIDDLE_BLOCK one, and later a LAST_BLOCK call holding only the
         16 tag bytes. The last call is thus 20 or 16 bytes.
         Tag mismatch makes the LAST_BLOCK call fail.
   The IV is incremented after each packet, so a context pair is run
   through two packets. */
#define GCM_BS  16
#define GCM_TAG 16

static int gcm_send(ssh2_cipher_ctx *c, SSH2_CIPHER_T(algo),
                    unsigned char *pkt, size_t L)
{
    size_t i;

    for(i = 0; i < L; i += GCM_BS) {
        size_t n = L - i < GCM_BS ? L - i : GCM_BS;
        if(ssh2_cipher_crypt(c, algo, 1, pkt + i, n,
                             i == 0 ? FIRST_BLOCK : MIDDLE_BLOCK))
            return -1;
    }
    return ssh2_cipher_crypt(c, algo, 1, pkt + L, GCM_TAG, LAST_BLOCK);
}

/* tag_late selects the capped shape: the payload is fed first, the tag
   arrives in a LAST_BLOCK call of its own */
static int gcm_recv(ssh2_cipher_ctx *c, SSH2_CIPHER_T(algo),
                    unsigned char *pkt, size_t L, int tag_late)
{
    size_t len = L + GCM_TAG, off = 0;
    int first = 1;

    while(len > 0) {
        size_t n = len < GCM_BS ? len : GCM_BS;
        int fl;

        if(first)
            fl = FIRST_BLOCK;
        else if(tag_late) {
            if(len == GCM_TAG)
                fl = LAST_BLOCK;
            else {
                fl = MIDDLE_BLOCK;
                if(len - GCM_TAG < n)
                    n = len - GCM_TAG;
            }
        }
        else if(len < 2 * GCM_BS) {
            n = len;
            fl = LAST_BLOCK;
        }
        else
            fl = MIDDLE_BLOCK;

        if(ssh2_cipher_crypt(c, algo, 0, pkt + off, n, fl))
            return -1;
        first = 0;
        off += n;
        len -= n;
    }
    return 0;
}

#ifdef LIBSSH2_MBEDTLS
/* Expected ciphertext and tag from one-shot PSA, independent of the
   streaming code: catches IV byte order, carry and AAD placement errors
   that an encrypt-then-decrypt round trip would repeat on both sides. */
static int gcm_reference(const unsigned char *key, size_t keylen,
                         const unsigned char *iv, const unsigned char *plain,
                         size_t L, unsigned char *out)
{
    psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = PSA_KEY_ID_NULL;
    size_t olen = 0;
    psa_status_t st;

    psa_set_key_type(&at, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&at, keylen * 8);
    psa_set_key_algorithm(&at, PSA_ALG_GCM);
    psa_set_key_usage_flags(&at, PSA_KEY_USAGE_ENCRYPT);
    if(psa_import_key(&at, key, keylen, &id) != PSA_SUCCESS)
        return -1;
    st = psa_aead_encrypt(id, PSA_ALG_GCM, iv, 12, plain, 4,
                          plain + 4, L - 4, out, L - 4 + GCM_TAG, &olen);
    (void)psa_destroy_key(id);
    return (st == PSA_SUCCESS && olen == L - 4 + GCM_TAG) ? 0 : -1;
}
#endif

static int gcm_case(const struct cipher_case *cc)
{
    const char *name = cc->name;
    SSH2_CIPHER_T(algo) = cc->algo;
    size_t keylen = cc->keylen;
    static const size_t blocks[2] = { 2, 5 };
    unsigned char key[32], iv[12];
    unsigned char plain[2][4 + 16 * 5 + GCM_TAG];
    unsigned char wire[2][4 + 16 * 5 + GCM_TAG];
    unsigned char bad[4 + 16 * 5 + GCM_TAG];
    ssh2_cipher_ctx enc;
    ssh2_cipher_ctx enc2;
    ssh2_cipher_ctx dec;
    size_t L[2], i;
    int have_enc = 0, have_enc2 = 0, have_dec = 0, rc = 1;

    EXPECT(ssh2_random(key, keylen) == 0);
    EXPECT(ssh2_random(iv, sizeof(iv)) == 0);
    /* the first increment must carry into byte 10 */
    iv[11] = 0xFF;

    for(i = 0; i < 2; i++) {
        L[i] = 4 + 16 * blocks[i];
        EXPECT(ssh2_random(plain[i], L[i]) == 0);
        memcpy(wire[i], plain[i], L[i]);
    }

    if(ssh2_cipher_init(&enc, algo, iv, key, 1))
        FAIL(name);
    have_enc = 1;
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;

    for(i = 0; i < 2; i++) {
        if(gcm_send(&enc, algo, wire[i], L[i]))
            FAIL(name);
        /* AAD stays in the clear, payload does not */
        EXPECT(memcmp(wire[i], plain[i], 4) == 0);
        EXPECT(memcmp(wire[i] + 4, plain[i] + 4, L[i] - 4) != 0);
    }

#ifdef LIBSSH2_MBEDTLS
    {
        unsigned char nonce[12], ref[16 * 5 + GCM_TAG];
        int k;

        memcpy(nonce, iv, sizeof(nonce));
        for(i = 0; i < 2; i++) {
            if(i) {
                for(k = 11; k >= 4; k--)
                    if(++nonce[k])
                        break;
            }
            EXPECT(gcm_reference(key, keylen, nonce, plain[i], L[i],
                                 ref) == 0);
            EXPECT(memcmp(wire[i] + 4, ref, L[i] - 4) == 0);
            EXPECT(memcmp(wire[i] + L[i], ref + L[i] - 4, GCM_TAG) == 0);
        }
    }
#endif

    /* the second packet is only right if the IV was bumped in between */
    for(i = 0; i < 2; i++) {
        memcpy(bad, wire[i], L[i] + GCM_TAG);
        if(gcm_recv(&dec, algo, bad, L[i], 0))
            FAIL(name);
        EXPECT(memcmp(bad, plain[i], L[i]) == 0);
    }

    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* same packets with the tag arriving in a call of its own */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    for(i = 0; i < 2; i++) {
        memcpy(bad, wire[i], L[i] + GCM_TAG);
        if(gcm_recv(&dec, algo, bad, L[i], 1))
            FAIL(name);
        EXPECT(memcmp(bad, plain[i], L[i]) == 0);
    }
    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* a failed tag check still advances the IV, so the next packet on
       the same context pair decrypts */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    bad[L[0] + 3] ^= 0x01;
    EXPECT(gcm_recv(&dec, algo, bad, L[0], 0) != 0);
    memcpy(bad, wire[1], L[1] + GCM_TAG);
    if(gcm_recv(&dec, algo, bad, L[1], 0))
        FAIL(name);
    EXPECT(memcmp(bad, plain[1], L[1]) == 0);
    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* an oversized block aborts the open operation: the next small
       MIDDLE has nothing to continue, and a new FIRST starts clean */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    if(ssh2_cipher_init(&enc2, algo, iv, key, 1))
        FAIL(name);
    have_enc2 = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    EXPECT(ssh2_cipher_crypt(&enc2, algo, 1, bad, GCM_BS, FIRST_BLOCK) == 0);
    EXPECT(ssh2_cipher_crypt(&enc2, algo, 1, bad, 33, MIDDLE_BLOCK) != 0);
    EXPECT(ssh2_cipher_crypt(&enc2, algo, 1, bad, GCM_BS,
                             MIDDLE_BLOCK) != 0);
    memcpy(bad, plain[0], L[0]);
    if(gcm_send(&enc2, algo, bad, L[0]))
        FAIL(name);
    if(gcm_recv(&dec, algo, bad, L[0], 0))
        FAIL(name);
    EXPECT(memcmp(bad, plain[0], L[0]) == 0);
    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* MIDDLE or LAST with no FIRST before them */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    EXPECT(ssh2_cipher_crypt(&dec, algo, 0, bad, GCM_BS, MIDDLE_BLOCK) != 0);
    EXPECT(ssh2_cipher_crypt(&dec, algo, 0, bad, 2 * GCM_BS,
                             LAST_BLOCK) != 0);
    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* flipped tag byte */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    bad[L[0] + 3] ^= 0x01;
    EXPECT(gcm_recv(&dec, algo, bad, L[0], 0) != 0);
    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* flipped AAD byte */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    bad[3] ^= 0x01;
    EXPECT(gcm_recv(&dec, algo, bad, L[0], 0) != 0);
    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* flipped payload byte */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    bad[20] ^= 0x01;
    EXPECT(gcm_recv(&dec, algo, bad, L[0], 0) != 0);

    rc = 0;

fail:
    if(have_enc)
        ssh2_cipher_dtor(&enc);
    if(have_enc2)
        ssh2_cipher_dtor(&enc2);
    if(have_dec)
        ssh2_cipher_dtor(&dec);
    return rc;
}

static int test_aes_gcm(void)
{
    static const struct cipher_case cases[] = {
        { "aes128-gcm", ssh2_cipher_aes128gcm, 16, 12, 16 },
        { "aes256-gcm", ssh2_cipher_aes256gcm, 32, 12, 16 },
        { NULL }
    };
    int rc = 0;
    size_t i;

    for(i = 0; cases[i].name; i++)
        rc |= gcm_case(&cases[i]);
    return rc;
}
#endif

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
#if LIBSSH2_ECDSA
    rc |= test_ecdsa(session);
#endif
    rc |= test_hash_hmac();
#if LIBSSH2_AES_CTR
    rc |= test_aes_ctr_kat();
#endif
#if LIBSSH2_AES_CBC
    rc |= test_aes_cbc_kat();
#endif
#if LIBSSH2_AES_CTR || LIBSSH2_AES_CBC || LIBSSH2_3DES
    rc |= test_cipher_roundtrips();
#endif
#if LIBSSH2_AES_GCM
    rc |= test_aes_gcm();
#endif
    rc |= test_cipher_slots();

    libssh2_session_free(session);

    libssh2_exit();

    return rc;
}
