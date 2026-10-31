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
    ssh2_ec_key *a = NULL, *b = NULL;
    unsigned char *pub_a = NULL, *pub_b = NULL, *ka = NULL, *kb = NULL;
    size_t pub_a_len = 0, pub_b_len = 0, ka_len = 0, kb_len = 0;
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

    rc = 0;

fail:
    ssh2_zero_free(session, ka, ka_len);
    ssh2_zero_free(session, kb, kb_len);
    ssh2_bn_free(k_a);
    ssh2_bn_free(k_b);
    ssh2_ecdsa_free(a, session);
    ssh2_ecdsa_free(b, session);
    SSH2_FREE(session, pub_a);
    SSH2_FREE(session, pub_b);
    return rc;
}

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
        { "id_ecdsa_pkcs8", NULL, "ecdsa-sha2-nistp384", 384,
          SSH2_EC_CURVE_NISTP384 },
        { "id_ecdsa_openssh", NULL, "ecdsa-sha2-nistp384", 384,
          SSH2_EC_CURVE_NISTP384 },
        { "id_ecdsa_pem_encrypted", "libssh2", "ecdsa-sha2-nistp256", 256,
          SSH2_EC_CURVE_NISTP256 },
        { "id_ecdsa_pkcs8_encrypted", "libssh2", "ecdsa-sha2-nistp521", 521,
          SSH2_EC_CURVE_NISTP521 },
        { "id_ecdsa_openssh_encrypted", "libssh2", "ecdsa-sha2-nistp256", 256,
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
    unsigned char *name, *cname, *point, *r, *s;
    char *data = NULL;
    size_t blob_len = 0, sig_len = 0, name_len, cname_len, point_len;
    size_t r_len, s_len, data_len = 0, hash_len, i;
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
    EXPECT(!priv);

    /* ECDH on every curve */
    for(i = 0; i < sizeof(curves) / sizeof(curves[0]); i++)
        if(check_ecdh(session, curves[i], curve_bits[i]))
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
    if(ssh2_cipher_init(&c, algo, iv, (unsigned char *)nist_key, 1))
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
    if(ssh2_cipher_init(&c, algo, iv, (unsigned char *)nist_key, 0))
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
    unsigned char iv[16];

    memcpy(iv, ctr, sizeof(iv));
    return cipher_kat(ssh2_cipher_aes128ctr, iv, ct);
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
    unsigned char iv[16];
    int i;

    for(i = 0; i < 16; i++)
        iv[i] = (unsigned char)i;
    return cipher_kat(ssh2_cipher_aes128, iv, ct);
}
#endif

#if LIBSSH2_AES_CTR || LIBSSH2_AES_CBC || LIBSSH2_3DES
/* Random key and IV, four chunks of different multiples of the block
   size, in place; a second context decrypts chunk by chunk. */
static int cipher_roundtrip(const char *name, SSH2_CIPHER_T(algo),
                            size_t keylen, size_t ivlen, size_t bs)
{
    unsigned char key[32], iv[16], plain[512], buf[512];
    const size_t mult[4] = { 1, 3, 2, 5 };
    ssh2_cipher_ctx enc, dec;
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

    for(i = 0, off = 0; i < 4; i++) {
        if(ssh2_cipher_crypt(&enc, algo, 1, buf + off, mult[i] * bs,
                             MIDDLE_BLOCK))
            FAIL(name);
        off += mult[i] * bs;
    }
    EXPECT(memcmp(buf, plain, total) != 0);

    /* a flipped ciphertext byte must not decrypt to the original */
    buf[total / 2] ^= 0x01;
    for(i = 0, off = 0; i < 4; i++) {
        if(ssh2_cipher_crypt(&dec, algo, 0, buf + off, mult[i] * bs,
                             MIDDLE_BLOCK))
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
    for(i = 0, off = 0; i < 4; i++) {
        if(ssh2_cipher_crypt(&enc, algo, 1, buf + off, mult[i] * bs,
                             MIDDLE_BLOCK))
            FAIL(name);
        off += mult[i] * bs;
    }
    for(i = 0, off = 0; i < 4; i++) {
        if(ssh2_cipher_crypt(&dec, algo, 0, buf + off, mult[i] * bs,
                             MIDDLE_BLOCK))
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
    int rc = 0;
#if LIBSSH2_AES_CTR
    rc |= cipher_roundtrip("aes128-ctr", ssh2_cipher_aes128ctr, 16, 16, 16);
    rc |= cipher_roundtrip("aes192-ctr", ssh2_cipher_aes192ctr, 24, 16, 16);
    rc |= cipher_roundtrip("aes256-ctr", ssh2_cipher_aes256ctr, 32, 16, 16);
#endif
#if LIBSSH2_AES_CBC
    rc |= cipher_roundtrip("aes128-cbc", ssh2_cipher_aes128, 16, 16, 16);
    rc |= cipher_roundtrip("aes192-cbc", ssh2_cipher_aes192, 24, 16, 16);
    rc |= cipher_roundtrip("aes256-cbc", ssh2_cipher_aes256, 32, 16, 16);
#endif
#if LIBSSH2_3DES
    rc |= cipher_roundtrip("3des-cbc", ssh2_cipher_3des, 24, 8, 8);
#endif
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
   recv: crypt() of the first 16 bytes with FIRST_BLOCK; then 16-byte
         MIDDLE_BLOCK slices until fewer than 32 bytes remain; the rest
         (payload tail plus the tag, 16..31 bytes) in one LAST_BLOCK call.
         Tag mismatch makes that LAST_BLOCK call fail.
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

static int gcm_recv(ssh2_cipher_ctx *c, SSH2_CIPHER_T(algo),
                    unsigned char *pkt, size_t L)
{
    size_t len = L + GCM_TAG, off = 0;
    int first = 1;

    while(len > 0) {
        size_t n = len < GCM_BS ? len : GCM_BS;
        int fl;

        if(first)
            fl = FIRST_BLOCK;
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

static int gcm_case(const char *name, SSH2_CIPHER_T(algo), size_t keylen)
{
    static const size_t blocks[2] = { 2, 5 };
    unsigned char key[32], iv[12];
    unsigned char plain[2][4 + 16 * 5 + GCM_TAG];
    unsigned char wire[2][4 + 16 * 5 + GCM_TAG];
    unsigned char bad[4 + 16 * 5 + GCM_TAG];
    ssh2_cipher_ctx enc, dec;
    size_t L[2], i;
    int have_enc = 0, have_dec = 0, rc = 1;

    EXPECT(ssh2_random(key, keylen) == 0);
    EXPECT(ssh2_random(iv, sizeof(iv)) == 0);

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

    /* the second packet is only right if the IV was bumped in between */
    for(i = 0; i < 2; i++) {
        memcpy(bad, wire[i], L[i] + GCM_TAG);
        if(gcm_recv(&dec, algo, bad, L[i]))
            FAIL(name);
        EXPECT(memcmp(bad, plain[i], L[i]) == 0);
    }

    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* flipped tag byte */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    bad[L[0] + 3] ^= 0x01;
    EXPECT(gcm_recv(&dec, algo, bad, L[0]) != 0);
    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* flipped AAD byte */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    bad[3] ^= 0x01;
    EXPECT(gcm_recv(&dec, algo, bad, L[0]) != 0);
    ssh2_cipher_dtor(&dec);
    have_dec = 0;

    /* flipped payload byte */
    if(ssh2_cipher_init(&dec, algo, iv, key, 0))
        FAIL(name);
    have_dec = 1;
    memcpy(bad, wire[0], L[0] + GCM_TAG);
    bad[20] ^= 0x01;
    EXPECT(gcm_recv(&dec, algo, bad, L[0]) != 0);

    rc = 0;

fail:
    if(have_enc)
        ssh2_cipher_dtor(&enc);
    if(have_dec)
        ssh2_cipher_dtor(&dec);
    return rc;
}

static int test_aes_gcm(void)
{
    int rc = 0;
    rc |= gcm_case("aes128-gcm", ssh2_cipher_aes128gcm, 16);
    rc |= gcm_case("aes256-gcm", ssh2_cipher_aes256gcm, 32);
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

    libssh2_session_free(session);

    libssh2_exit();

    return rc;
}
