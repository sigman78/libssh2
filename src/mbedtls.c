/* Copyright (C) Art <https://github.com/wildart>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#ifdef LIBSSH2_MBEDTLS

#include <stdlib.h>

/* All randomness comes from the PSA generator. Mbed TLS 3.x legacy
   functions that still take an RNG callback get the PSA one. */
#if MBEDTLS_VERSION_NUMBER < 0x04000000
#define MBED_RNG mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE
#define mbed_pk_parse_key(pk, key, keylen, pwd, pwdlen) \
    mbedtls_pk_parse_key(pk, key, keylen, pwd, pwdlen, MBED_RNG)
#define mbed_pk_parse_keyfile(pk, path, pwd) \
    mbedtls_pk_parse_keyfile(pk, path, pwd, MBED_RNG)
#else
/* 4.x parsers take randomness from PSA themselves */
#define mbed_pk_parse_key(pk, key, keylen, pwd, pwdlen) \
    mbedtls_pk_parse_key(pk, key, keylen, pwd, pwdlen)
#define mbed_pk_parse_keyfile(pk, path, pwd) \
    mbedtls_pk_parse_keyfile(pk, path, pwd)
#endif

/*******************************************************************/
/*
 * mbedTLS backend: Generic functions
 */

void ssh2_crypto_init(void)
{
    (void)psa_crypto_init();
}

void ssh2_crypto_exit(void)
{
    mbedtls_psa_crypto_free();
}

int ssh2_random(unsigned char *buf, size_t len)
{
    return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
}

/* Cipher algorithm -> PSA key type, key size, algorithm and mode */
static int mbed_cipher_params(ssh2_mbed_cipher_type algo,
                              psa_key_type_t *type, size_t *bits,
                              psa_algorithm_t *alg, int *is_aead)
{
    *is_aead = 0;

    switch(algo) {
#if LIBSSH2_AES_CTR
    case MBED_CIPHER_AES128_CTR:
    case MBED_CIPHER_AES192_CTR:
    case MBED_CIPHER_AES256_CTR:
        *type = PSA_KEY_TYPE_AES;
        *alg = PSA_ALG_CTR;
        *bits = algo == MBED_CIPHER_AES128_CTR ? 128 :
                algo == MBED_CIPHER_AES192_CTR ? 192 : 256;
        return 0;
#endif
#if LIBSSH2_AES_CBC
    case MBED_CIPHER_AES128_CBC:
    case MBED_CIPHER_AES192_CBC:
    case MBED_CIPHER_AES256_CBC:
        /* libssh2 adds the SSH packet padding itself */
        *type = PSA_KEY_TYPE_AES;
        *alg = PSA_ALG_CBC_NO_PADDING;
        *bits = algo == MBED_CIPHER_AES128_CBC ? 128 :
                algo == MBED_CIPHER_AES192_CBC ? 192 : 256;
        return 0;
#endif
#if LIBSSH2_3DES
    case MBED_CIPHER_3DES_CBC:
        *type = PSA_KEY_TYPE_DES;
        *alg = PSA_ALG_CBC_NO_PADDING;
        *bits = 192;
        return 0;
#endif
#if LIBSSH2_AES_GCM
    case MBED_CIPHER_AES128_GCM:
    case MBED_CIPHER_AES256_GCM:
        *type = PSA_KEY_TYPE_AES;
        *alg = PSA_ALG_GCM;
        *bits = algo == MBED_CIPHER_AES128_GCM ? 128 : 256;
        *is_aead = 1;
        return 0;
#endif
    default:
        break;
    }
    return -1;
}

int ssh2_cipher_init(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_type_t type;
    psa_algorithm_t alg;
    size_t bits;
    int is_aead;

    if(!ctx)
        return -1;

    memset(ctx, 0, sizeof(*ctx));
    ctx->key = PSA_KEY_ID_NULL;

    if(mbed_cipher_params(algo, &type, &bits, &alg, &is_aead))
        return -1;

    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, bits);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_usage_flags(&attributes, encrypt ? PSA_KEY_USAGE_ENCRYPT :
                                                   PSA_KEY_USAGE_DECRYPT);

    if(psa_import_key(&attributes, secret, bits / 8, &ctx->key) !=
       PSA_SUCCESS) {
        ctx->key = PSA_KEY_ID_NULL;
        return -1;
    }

    ctx->alg = alg;
    ctx->is_aead = is_aead;

    if(is_aead) {
        /* The operation is set up per packet, the IV is bumped after each */
        memcpy(ctx->iv, iv, sizeof(ctx->iv));
        return 0;
    }

    /* This operation stays open: the CBC/CTR chaining state must carry
       across ssh2_cipher_crypt() calls, so it is never finished. */
    ctx->op.cipher = psa_cipher_operation_init();
    if((encrypt ? psa_cipher_encrypt_setup(&ctx->op.cipher, ctx->key, alg) :
                  psa_cipher_decrypt_setup(&ctx->op.cipher, ctx->key, alg))
       != PSA_SUCCESS ||
       psa_cipher_set_iv(&ctx->op.cipher, iv,
                         PSA_CIPHER_IV_LENGTH(type, alg)) != PSA_SUCCESS) {
        ssh2_cipher_dtor(ctx);
        return -1;
    }

    return 0;
}

/* Chunk size for the non-AEAD path. PSA is not specified for in-place
   operation, so data goes through a stack buffer a piece at a time; that
   needs no allocation (there is no session to allocate from here) and
   puts no limit on the length passed in. The extra 16 bytes are the
   output slack PSA requires from block ciphers. */
#define MBED_CIPHER_CHUNK 64

#if LIBSSH2_AES_GCM
/* Largest block the transport hands to an AEAD cipher: the last payload
   slice (up to 15 bytes) merged with the 16-byte tag */
#define MBED_AEAD_MAX_BLOCK 32
#define MBED_AEAD_TAG_LEN   16

static int mbed_aead_crypt(ssh2_cipher_ctx *ctx, int encrypt,
                           unsigned char *block, size_t blocksize,
                           int firstlast)
{
    unsigned char buf[PSA_AEAD_UPDATE_OUTPUT_SIZE(PSA_KEY_TYPE_AES,
                                                  PSA_ALG_GCM,
                                                  MBED_AEAD_MAX_BLOCK)];
    unsigned char tag[MBED_AEAD_TAG_LEN];
    const size_t aadlen = IS_FIRST(firstlast) ? 4 : 0;
    const size_t taglen = IS_LAST(firstlast) ? MBED_AEAD_TAG_LEN : 0;
    size_t cryptlen, olen;
    int ret = -1;

    if(blocksize > MBED_AEAD_MAX_BLOCK || blocksize < aadlen + taglen)
        return -1;

    cryptlen = blocksize - aadlen - taglen;

    /* First block: start the operation and feed the AAD */
    if(IS_FIRST(firstlast)) {
        (void)psa_aead_abort(&ctx->op.aead);
        ctx->op.aead = psa_aead_operation_init();
        ctx->aead_active = 0;

        if((encrypt ? psa_aead_encrypt_setup(&ctx->op.aead, ctx->key,
                                             ctx->alg) :
                      psa_aead_decrypt_setup(&ctx->op.aead, ctx->key,
                                             ctx->alg)) != PSA_SUCCESS)
            return -1;
        ctx->aead_active = 1;

        if(psa_aead_set_nonce(&ctx->op.aead, ctx->iv, sizeof(ctx->iv)) !=
           PSA_SUCCESS ||
           psa_aead_update_ad(&ctx->op.aead, block, aadlen) != PSA_SUCCESS)
            goto fail;
    }
    else if(!ctx->aead_active)
        return -1;

    /* The output must come back whole: libssh2 needs it in place and
       the same length. */
    if(cryptlen > 0) {
        olen = 0;
        if(psa_aead_update(&ctx->op.aead, block + aadlen, cryptlen,
                           buf, sizeof(buf), &olen) != PSA_SUCCESS ||
           olen != cryptlen)
            goto fail;
        memcpy(block + aadlen, buf, olen);
    }

    ret = 0;

    /* Last block: the tag is written on encrypt, checked on decrypt */
    if(IS_LAST(firstlast)) {
        size_t flen = 0, tlen = 0;
        int i;

        if(encrypt) {
            if(psa_aead_finish(&ctx->op.aead, buf, sizeof(buf), &flen,
                               tag, sizeof(tag), &tlen) != PSA_SUCCESS ||
               tlen != sizeof(tag) || flen)
                ret = -1;
            else
                memcpy(block + blocksize - sizeof(tag), tag, sizeof(tag));
        }
        else if(psa_aead_verify(&ctx->op.aead, buf, sizeof(buf), &flen,
                                block + blocksize - sizeof(tag),
                                sizeof(tag)) != PSA_SUCCESS || flen)
            ret = -1;

        ctx->aead_active = 0;
        (void)psa_aead_abort(&ctx->op.aead);

        /* Increment the invocation counter for the next packet */
        for(i = 11; i >= 4; i--)
            if(++ctx->iv[i])
                break;
    }

    ssh2_explicit_zero(buf, sizeof(buf));
    return ret;

fail:
    ctx->aead_active = 0;
    (void)psa_aead_abort(&ctx->op.aead);
    ssh2_explicit_zero(buf, sizeof(buf));
    return -1;
}
#endif /* LIBSSH2_AES_GCM */

int ssh2_cipher_crypt(ssh2_cipher_ctx *ctx, SSH2_CIPHER_T(algo),
                      int encrypt, unsigned char *block, size_t blocksize,
                      int firstlast)
{
    unsigned char buf[MBED_CIPHER_CHUNK + 16];
    size_t done = 0;
    int ret = 0;

    if(!ctx)
        return -1;

    (void)algo;

#if LIBSSH2_AES_GCM
    if(ctx->is_aead)
        return mbed_aead_crypt(ctx, encrypt, block, blocksize, firstlast);
#else
    (void)encrypt;
    (void)firstlast;
#endif

    while(!ret && done < blocksize) {
        size_t n = blocksize - done, olen = 0;

        if(n > MBED_CIPHER_CHUNK)
            n = MBED_CIPHER_CHUNK;

        if(psa_cipher_update(&ctx->op.cipher, block + done, n,
                             buf, sizeof(buf), &olen) != PSA_SUCCESS ||
           olen != n)
            ret = -1;
        else
            memcpy(block + done, buf, n);
        done += n;
    }

    ssh2_explicit_zero(buf, sizeof(buf));
    return ret;
}

void ssh2_cipher_dtor(ssh2_cipher_ctx *ctx)
{
    if(!ctx)
        return;

    if(ctx->is_aead)
        (void)psa_aead_abort(&ctx->op.aead);
    else if(ctx->key != PSA_KEY_ID_NULL)
        (void)psa_cipher_abort(&ctx->op.cipher);

    if(ctx->key != PSA_KEY_ID_NULL)
        psa_destroy_key(ctx->key);

    ssh2_explicit_zero(ctx, sizeof(*ctx));
}

int ssh2_hash_init(ssh2_hash_ctx *ctx, ssh2_hash_alg alg)
{
    *ctx = psa_hash_operation_init();
    return psa_hash_setup(ctx, alg) == PSA_SUCCESS;
}

int ssh2_hash_final(ssh2_hash_ctx *ctx, void *digest, size_t digest_len)
{
    size_t actual_len;
    return psa_hash_finish(ctx, digest, digest_len,
                           &actual_len) == PSA_SUCCESS;
}

int ssh2_hmac_ctx_init(ssh2_hmac_ctx *ctx)
{
    ctx->mac = psa_mac_operation_init();
    ctx->key_id = PSA_KEY_ID_NULL;
    return 1;
}

int ssh2_hmac_init(ssh2_hmac_ctx *ctx, ssh2_hmac_alg alg,
                   void *key, size_t key_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg_hmac = PSA_ALG_HMAC(alg);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, alg_hmac);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);

    if(psa_import_key(&attributes, key, key_len, &ctx->key_id) != PSA_SUCCESS)
        return 0;

    if(psa_mac_sign_setup(&ctx->mac, ctx->key_id, alg_hmac) != PSA_SUCCESS) {
        ssh2_hmac_cleanup(ctx);
        return 0;
    }

    return 1;
}

int ssh2_hmac_final(ssh2_hmac_ctx *ctx, void *mac, size_t mac_len)
{
    size_t actual_len;
    return psa_mac_sign_finish(&ctx->mac, mac, mac_len,
                               &actual_len) == PSA_SUCCESS;
}

void ssh2_hmac_cleanup(ssh2_hmac_ctx *ctx)
{
    (void)psa_mac_abort(&ctx->mac);
    psa_destroy_key(ctx->key_id);
    ctx->key_id = PSA_KEY_ID_NULL;
}

/*******************************************************************/
/*
 * mbedTLS backend: BigNumber functions
 */

ssh2_bn *ssh2_bn_init(void)
{
    ssh2_bn *bignum;

    bignum = mbedtls_calloc(1, sizeof(ssh2_bn));
    if(bignum)
        mbedtls_mpi_init(bignum);

    return bignum;
}

void ssh2_bn_free(ssh2_bn *bn)
{
    if(bn) {
        mbedtls_mpi_free(bn);
        mbedtls_free(bn);
    }
}

int ssh2_bn_from_bin(ssh2_bn **bn, const unsigned char *bin, size_t len)
{
    if(!bn || !bin || !len)
        return -1;

    if(!*bn) {
        *bn = ssh2_bn_init();
        if(!*bn)
            return -1;
    }

    return mbedtls_mpi_read_binary(*bn, bin, len);
}

static int mbed_bn_random(ssh2_bn *bn, int bits, int top, int bottom)
{
    unsigned char *buf;
    size_t len;
    size_t i;

    if(!bn || bits <= 0)
        return -1;

    len = (bits + 7) >> 3;
    buf = mbedtls_calloc(1, len);
    if(!buf)
        return -1;
    /* the buffer holds the DH private exponent */
    if(psa_generate_random(buf, len) != PSA_SUCCESS ||
       mbedtls_mpi_read_binary(bn, buf, len)) {
        mbedtls_platform_zeroize(buf, len);
        mbedtls_free(buf);
        return -1;
    }
    mbedtls_platform_zeroize(buf, len);
    mbedtls_free(buf);

    /* Zero unused bits above the most significant bit */
    for(i = (len * 8) - 1; (size_t)bits <= i; --i)
        if(mbedtls_mpi_set_bit(bn, i, 0))
            return -1;

    /* If `top` is -1, the most significant bit of the random number can be
       zero.  If top is 0, the most significant bit of the random number is
       set to 1, and if top is 1, the two most significant bits of the number
       is set to 1, so that the product of two such random numbers always
       have 2 * bits length. */
    if(top >= 0)
        for(i = 0; i <= (size_t)top; ++i)
            if(mbedtls_mpi_set_bit(bn, bits - i - 1, 1))
                return -1;

    /* make odd by setting first bit in least significant byte */
    if(bottom && mbedtls_mpi_set_bit(bn, 0, 1))
        return -1;

    return 0;
}

/*******************************************************************/
/*
 * mbedTLS backend: PSA key helpers
 */

/* Asymmetric keys live in the PSA key store; the context handed around
   libssh2 is a heap-held key identifier. */
static psa_key_id_t *mbed_key_alloc(LIBSSH2_SESSION *session)
{
    psa_key_id_t *key = SSH2_ALLOC(session, sizeof(*key));
    if(key)
        *key = PSA_KEY_ID_NULL;
    return key;
}

static void mbed_key_free(psa_key_id_t *key, LIBSSH2_SESSION *session)
{
    if(key) {
        psa_destroy_key(*key);
        SSH2_FREE(session, key);
    }
}

static int mbed_key_bits(psa_key_id_t key, size_t *bits)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    if(psa_get_key_attributes(key, &attr) != PSA_SUCCESS)
        return -1;
    *bits = psa_get_key_bits(&attr);
    psa_reset_key_attributes(&attr);
    return 0;
}

/* Parses a PEM/DER private key from a file or a blob with the mbedTLS
   pk parser. Returns the mbedTLS error code. */
static int mbed_pk_parse(mbedtls_pk_context *pk, LIBSSH2_SESSION *session,
                         const char *filename,
                         const char *blob, size_t blob_len,
                         const char *passphrase)
{
    unsigned char *data;
    int ret;

    if(filename)
        return mbed_pk_parse_keyfile(pk, filename, passphrase);

    /* the pk parser wants PEM input null-terminated */
    data = SSH2_ALLOC(session, blob_len + 1);
    if(!data)
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    memcpy(data, blob, blob_len);
    data[blob_len] = '\0';
    ret = mbed_pk_parse_key(pk, data, blob_len + 1,
                            (const unsigned char *)passphrase,
                            passphrase ? strlen(passphrase) : 0);
    ssh2_zero_free(session, data, blob_len + 1);
    return ret;
}

/* RSA modulus bits of a parsed key, 0 for other types. 4.x has no
   mbedtls_pk_get_type(), so the type is read from the PSA attributes. */
static size_t mbed_pk_rsa_bits(const mbedtls_pk_context *pk)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t bits = 0;

    if(mbedtls_pk_get_psa_attributes(pk, PSA_KEY_USAGE_SIGN_HASH,
                                     &attr) == 0 &&
       PSA_KEY_TYPE_IS_RSA(psa_get_key_type(&attr)))
        bits = mbedtls_pk_get_bitlen(pk);
    psa_reset_key_attributes(&attr);
    return bits;
}

/* Moves a parsed private key into PSA. `type` must match the parsed key,
   `alg` is the permitted algorithm (wildcard hash where applicable). */
static int mbed_pk_import(const mbedtls_pk_context *pk, psa_key_type_t type,
                          psa_algorithm_t alg, psa_key_id_t *key)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    int ret = -1;

    if(mbedtls_pk_get_psa_attributes(pk, PSA_KEY_USAGE_SIGN_HASH,
                                     &attr) == 0 &&
       psa_get_key_type(&attr) == type) {
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
                                       PSA_KEY_USAGE_SIGN_MESSAGE |
                                       PSA_KEY_USAGE_VERIFY_HASH |
                                       PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_algorithm(&attr, alg);
        if(mbedtls_pk_import_into_psa(pk, &attr, key) == 0)
            ret = 0;
    }
    psa_reset_key_attributes(&attr);
    return ret;
}

/*******************************************************************/
/*
 * mbedTLS backend: RSA functions
 */

#if LIBSSH2_RSA

#define MBED_RSA_ALG PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH)

/* A failed RSA import is blamed on the key size when PSA cannot take it:
   it caps moduli at PSA_VENDOR_RSA_MAX_KEY_BITS and wants whole bytes. */
static int mbed_rsa_size_err(LIBSSH2_SESSION *session, int errcode,
                             size_t bits)
{
    char msg[96];

    if(bits <= PSA_VENDOR_RSA_MAX_KEY_BITS && bits % 8 == 0)
        return -1;
    ssh2_snprintf(msg, sizeof(msg), "RSA keys larger than %d bits or of "
                  "non-byte-aligned size are not supported",
                  (int)PSA_VENDOR_RSA_MAX_KEY_BITS);
    return ssh2_err_flags(session, errcode, msg, SSH2_ERR_FLAG_DUP);
}

/* The bit length of a big-endian unsigned number */
static size_t mbed_uint_bits(const unsigned char *num, size_t len)
{
    unsigned int top;
    size_t bits;

    while(len && *num == 0) {
        num++;
        len--;
    }
    if(!len)
        return 0;
    bits = (len - 1) * 8;
    for(top = *num; top; top >>= 1)
        bits++;
    return bits;
}

/* The CRT parameters RSAPrivateKey wants but a bare (n, e, d, p, q) set
   lacks: dP = d mod (p-1), dQ = d mod (q-1), qInv = q^-1 mod p. The
   outputs are plen, qlen and plen bytes. */
static int mbed_rsa_crt(const unsigned char *d, size_t dlen,
                        const unsigned char *p, size_t plen,
                        const unsigned char *q, size_t qlen,
                        unsigned char *dp, unsigned char *dq,
                        unsigned char *qinv)
{
    mbedtls_mpi bd, bp, bq, t, r;
    int ret = -1;

    mbedtls_mpi_init(&bd);
    mbedtls_mpi_init(&bp);
    mbedtls_mpi_init(&bq);
    mbedtls_mpi_init(&t);
    mbedtls_mpi_init(&r);

    if(mbedtls_mpi_read_binary(&bd, d, dlen) ||
       mbedtls_mpi_read_binary(&bp, p, plen) ||
       mbedtls_mpi_read_binary(&bq, q, qlen) ||
       mbedtls_mpi_sub_int(&t, &bp, 1) ||
       mbedtls_mpi_mod_mpi(&r, &bd, &t) ||
       mbedtls_mpi_write_binary(&r, dp, plen) ||
       mbedtls_mpi_sub_int(&t, &bq, 1) ||
       mbedtls_mpi_mod_mpi(&r, &bd, &t) ||
       mbedtls_mpi_write_binary(&r, dq, qlen) ||
       mbedtls_mpi_inv_mod(&r, &bq, &bp) ||
       mbedtls_mpi_write_binary(&r, qinv, plen))
        goto cleanup;
    ret = 0;

cleanup:

    mbedtls_mpi_free(&bd);
    mbedtls_mpi_free(&bp);
    mbedtls_mpi_free(&bq);
    mbedtls_mpi_free(&t);
    mbedtls_mpi_free(&r);
    return ret;
}

/* Writes an unsigned big-endian number as a DER INTEGER, backwards like
   the rest of asn1write. */
static int mbed_asn1_write_uint(unsigned char **p, const unsigned char *start,
                                const unsigned char *num, size_t num_len)
{
    static const unsigned char zero = 0;
    int len;

    if(num_len == 0) {
        num = &zero;
        num_len = 1;
    }
    while(num_len > 1 && *num == 0) {
        num++;
        num_len--;
    }

    len = mbedtls_asn1_write_raw_buffer(p, start, num, num_len);
    if(len < 0)
        return -1;
    if(*num & 0x80) {  /* keep it positive */
        if(*p - start < 1)
            return -1;
        *--(*p) = 0;
        len++;
    }
    if(mbedtls_asn1_write_len(p, start, (size_t)len) < 0 ||
       mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_INTEGER) < 0)
        return -1;
    return 0;
}

int ssh2_rsa_new(ssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session,
                 const unsigned char *edata, size_t elen,
                 const unsigned char *ndata, size_t nlen,
                 const unsigned char *ddata, size_t dlen,
                 const unsigned char *pdata, size_t plen,
                 const unsigned char *qdata, size_t qlen,
                 const unsigned char *e1data, size_t e1len,
                 const unsigned char *e2data, size_t e2len,
                 const unsigned char *coeffdata, size_t coefflen)
{
    /* PSA imports RSA keys as PKCS#1 DER:
         RSAPublicKey  ::= SEQUENCE { n, e }
         RSAPrivateKey ::= SEQUENCE { 0, n, e, d, p, q, dP, dQ, qInv } */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    unsigned char *der, *ptr, *crt = NULL;
    size_t der_size, der_len;
    int ret = -1;

    *rsa = NULL;

    /* OpenSSH-format keys carry only n, e, d, p, q */
    if(ddata && pdata && qdata &&
       (!e1data || !e1len || !e2data || !e2len || !coeffdata || !coefflen)) {
        crt = SSH2_ALLOC(session, 2 * plen + qlen);
        if(!crt ||
           mbed_rsa_crt(ddata, dlen, pdata, plen, qdata, qlen,
                        crt, crt + plen, crt + plen + qlen)) {
            ssh2_zero_free(session, crt, 2 * plen + qlen);
            return -1;
        }
        e1data = crt;
        e1len = plen;
        e2data = crt + plen;
        e2len = qlen;
        coeffdata = crt + plen + qlen;
        coefflen = plen;
    }

    /* an INTEGER costs at most 6 bytes of framing, the SEQUENCE 4 */
    der_size = elen + nlen + 3 * 6;
    if(ddata)
        der_size += dlen + plen + qlen + e1len + e2len + coefflen + 7 * 6;

    der = SSH2_ALLOC(session, der_size);
    if(!der) {
        ssh2_zero_free(session, crt, 2 * plen + qlen);
        return -1;
    }
    ptr = der + der_size;

    if(ddata &&
       (mbed_asn1_write_uint(&ptr, der, coeffdata, coefflen) ||
        mbed_asn1_write_uint(&ptr, der, e2data, e2len) ||
        mbed_asn1_write_uint(&ptr, der, e1data, e1len) ||
        mbed_asn1_write_uint(&ptr, der, qdata, qlen) ||
        mbed_asn1_write_uint(&ptr, der, pdata, plen) ||
        mbed_asn1_write_uint(&ptr, der, ddata, dlen)))
        goto cleanup;

    if(mbed_asn1_write_uint(&ptr, der, edata, elen) ||
       mbed_asn1_write_uint(&ptr, der, ndata, nlen) ||
       (ddata && mbedtls_asn1_write_int(&ptr, der, 0) < 0))
        goto cleanup;

    der_len = (size_t)(der + der_size - ptr);
    if(mbedtls_asn1_write_len(&ptr, der, der_len) < 0 ||
       mbedtls_asn1_write_tag(&ptr, der, MBEDTLS_ASN1_CONSTRUCTED |
                                         MBEDTLS_ASN1_SEQUENCE) < 0)
        goto cleanup;
    der_len = (size_t)(der + der_size - ptr);

    *rsa = mbed_key_alloc(session);
    if(!*rsa)
        goto cleanup;

    psa_set_key_type(&attr, ddata ? PSA_KEY_TYPE_RSA_KEY_PAIR
                                  : PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH |
                                   PSA_KEY_USAGE_VERIFY_MESSAGE |
                                   (ddata ? PSA_KEY_USAGE_SIGN_HASH : 0));
    psa_set_key_algorithm(&attr, MBED_RSA_ALG);
    if(psa_import_key(&attr, ptr, der_len, *rsa) == PSA_SUCCESS)
        ret = 0;
    else
        ret = mbed_rsa_size_err(session, LIBSSH2_ERROR_INVAL,
                                mbed_uint_bits(ndata, nlen));

cleanup:

    ssh2_zero_free(session, der, der_size);
    ssh2_zero_free(session, crt, 2 * plen + qlen);
    if(ret) {
        mbed_key_free(*rsa, session);
        *rsa = NULL;
    }
    return ret;
}

int ssh2_rsa_new_priv(ssh2_rsa_ctx **rsa,
                      LIBSSH2_SESSION *session,
                      const char *filename,
                      const char *blob, size_t blob_len,
                      const char *passphrase)
{
    mbedtls_pk_context pk;
    size_t pk_bits;
    int ret = -1;

    *rsa = mbed_key_alloc(session);
    if(!*rsa)
        return -1;

    mbedtls_pk_init(&pk);
    if(mbed_pk_parse(&pk, session, filename, blob, blob_len,
                     passphrase) == 0) {
        if(mbed_pk_import(&pk, PSA_KEY_TYPE_RSA_KEY_PAIR, MBED_RSA_ALG,
                          *rsa) == 0)
            ret = 0;
        else {
            pk_bits = mbed_pk_rsa_bits(&pk);
            if(pk_bits)
                ret = mbed_rsa_size_err(session, LIBSSH2_ERROR_FILE,
                                        pk_bits);
        }
    }
    mbedtls_pk_free(&pk);

    if(ret) {
        mbed_key_free(*rsa, session);
        *rsa = NULL;
    }
    return ret;
}

static psa_algorithm_t mbed_rsa_hash_alg(size_t hash_len)
{
#if LIBSSH2_RSA_SHA1
    if(hash_len == SSH2_SHA1_DIG_LEN)
        return PSA_ALG_SHA_1;
#endif
    if(hash_len == SSH2_SHA256_DIG_LEN)
        return PSA_ALG_SHA_256;
    if(hash_len == SSH2_SHA512_DIG_LEN)
        return PSA_ALG_SHA_512;
    return PSA_ALG_NONE;
}

int ssh2_rsa_sha2_verify(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                         size_t hash_len,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    psa_algorithm_t hash_alg = mbed_rsa_hash_alg(hash_len);
    unsigned char *padded = NULL;
    size_t bits, n;
    psa_status_t status;

    if(hash_alg == PSA_ALG_NONE || mbed_key_bits(*rsa, &bits))
        return -1;
    n = PSA_BITS_TO_BYTES(bits);

    /* RFC 4253 sizes the signature to the modulus. PSA insists on that,
       some peers do not, so strip surplus leading zeros or pad them in. */
    while(sig_len > n && *sig == 0) {
        sig++;
        sig_len--;
    }
    if(sig_len > n)
        return -1;
    if(sig_len < n) {
        padded = SSH2_CALLOC(session, n);
        if(!padded)
            return -1;
        memcpy(padded + n - sig_len, sig, sig_len);
        sig = padded;
        sig_len = n;
    }

    status = psa_verify_message(*rsa, PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg),
                                m, m_len, sig, sig_len);

    if(padded)
        SSH2_FREE(session, padded);

    return status == PSA_SUCCESS ? 0 : -1;
}

int ssh2_rsa_sha2_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    psa_algorithm_t hash_alg = mbed_rsa_hash_alg(hash_len);
    unsigned char *sig;
    size_t bits, n;

    if(hash_alg == PSA_ALG_NONE)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                        "Unsupported hash digest length");
    if(mbed_key_bits(*rsa, &bits))
        return -1;

    /* PKCS#1 v1.5 signatures are exactly modulus-sized: wire format */
    n = PSA_BITS_TO_BYTES(bits);
    sig = SSH2_ALLOC(session, n);
    if(!sig)
        return -1;

    if(psa_sign_hash(*rsa, PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg),
                     hash, hash_len, sig, n, signature_len) != PSA_SUCCESS) {
        SSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    return 0;
}

#if LIBSSH2_RSA_SHA1
int ssh2_rsa_sha1_verify(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                         const unsigned char *sig, size_t sig_len,
                         const unsigned char *m, size_t m_len)
{
    return ssh2_rsa_sha2_verify(rsa, session, SSH2_SHA1_DIG_LEN,
                                sig, sig_len, m, m_len);
}

int ssh2_rsa_sha1_sign(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session,
                       const unsigned char *hash, size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    return ssh2_rsa_sha2_sign(rsa, session, hash, hash_len,
                              signature, signature_len);
}
#endif

void ssh2_rsa_free(ssh2_rsa_ctx *rsa, LIBSSH2_SESSION *session)
{
    mbed_key_free(rsa, session);
}

/* Builds the "ssh-rsa" || e || n public key blob of a PSA RSA key */
static int mbed_rsa_pubkey(LIBSSH2_SESSION *session, psa_key_id_t key,
                           unsigned char **pubkeydata, size_t *pubkeydata_len)
{
    static const char method_name[] = "ssh-rsa";
    unsigned char *der, *p, *end, *n, *e, *blob, *bp;
    size_t bits, der_size, der_len, n_len, e_len, len;
    int ret = -1;

    if(mbed_key_bits(key, &bits))
        return -1;

    der_size = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_PUBLIC_KEY,
                                                 bits);
    der = SSH2_ALLOC(session, der_size);
    if(!der)
        return -1;

    /* PSA exports RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER } and
       a DER INTEGER body is byte-for-byte an SSH mpint, so lift them out */
    if(psa_export_public_key(key, der, der_size, &der_len) != PSA_SUCCESS)
        goto cleanup;
    p = der;
    end = der + der_len;
    if(mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED |
                                          MBEDTLS_ASN1_SEQUENCE) ||
       mbedtls_asn1_get_tag(&p, end, &n_len, MBEDTLS_ASN1_INTEGER))
        goto cleanup;
    n = p;
    p += n_len;
    if(mbedtls_asn1_get_tag(&p, end, &e_len, MBEDTLS_ASN1_INTEGER))
        goto cleanup;
    e = p;

    len = 4 + sizeof(method_name) - 1 + 4 + e_len + 4 + n_len;
    blob = SSH2_ALLOC(session, len);
    if(!blob)
        goto cleanup;
    bp = blob;
    ssh2_store_str(&bp, method_name, sizeof(method_name) - 1);
    ssh2_store_str(&bp, e, e_len);
    ssh2_store_str(&bp, n, n_len);

    *pubkeydata = blob;
    *pubkeydata_len = len;
    ret = 0;

cleanup:

    SSH2_FREE(session, der);
    return ret;
}
#endif /* LIBSSH2_RSA */

/* Copies the method name for the caller, frees the blob on failure */
static int mbed_method_dup(LIBSSH2_SESSION *session, char **method,
                           const char *method_name,
                           unsigned char **pubkeydata,
                           size_t *pubkeydata_len)
{
    size_t method_len = strlen(method_name);

    *method = SSH2_ALLOC(session, method_len + 1);
    if(!*method) {
        SSH2_SAFEFREE(session, *pubkeydata);
        *pubkeydata_len = 0;
        return -1;
    }
    memcpy(*method, method_name, method_len + 1);
    return 0;
}

#if LIBSSH2_ECDSA

#define MBED_ECC_PAIR   PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)
#define MBED_ECC_PUBLIC PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)
#define MBED_ECDSA_ALG  PSA_ALG_ECDSA(PSA_ALG_ANY_HASH)

/* The hash is fixed by the curve, RFC 5656 section 6.2.1 */
static psa_algorithm_t mbed_ecdsa_curve_hash(size_t bits)
{
    if(bits == 256)
        return PSA_ALG_SHA_256;
    if(bits == 384)
        return PSA_ALG_SHA_384;
    if(bits == 521)
        return PSA_ALG_SHA_512;
    return PSA_ALG_NONE;
}

static psa_algorithm_t mbed_ecdsa_hash_alg(size_t hash_len)
{
    if(hash_len == SSH2_SHA256_DIG_LEN)
        return PSA_ALG_SHA_256;
    if(hash_len == SSH2_SHA384_DIG_LEN)
        return PSA_ALG_SHA_384;
    if(hash_len == SSH2_SHA512_DIG_LEN)
        return PSA_ALG_SHA_512;
    return PSA_ALG_NONE;
}

static int mbed_ecdsa_names(size_t bits, const char **method,
                            const char **curve)
{
    switch(bits) {
    case 256:
        *method = "ecdsa-sha2-nistp256";
        *curve = "nistp256";
        return 0;
    case 384:
        *method = "ecdsa-sha2-nistp384";
        *curve = "nistp384";
        return 0;
    case 521:
        *method = "ecdsa-sha2-nistp521";
        *curve = "nistp521";
        return 0;
    }
    return -1;
}

/* Builds the method || curve || point public key blob of a PSA ECC key.
   The PSA public key export is already the uncompressed SSH point. */
static int mbed_ecdsa_pubkey(LIBSSH2_SESSION *session, psa_key_id_t key,
                             const char *method, const char *curve,
                             unsigned char **pubkeydata,
                             size_t *pubkeydata_len)
{
    unsigned char point[EC_MAX_POINT_LEN], *blob, *bp;
    size_t point_len, method_len, curve_len, len;

    if(psa_export_public_key(key, point, sizeof(point),
                             &point_len) != PSA_SUCCESS)
        return -1;

    method_len = strlen(method);
    curve_len = strlen(curve);
    len = 4 + method_len + 4 + curve_len + 4 + point_len;
    blob = SSH2_ALLOC(session, len);
    if(!blob)
        return -1;
    bp = blob;
    ssh2_store_str(&bp, method, method_len);
    ssh2_store_str(&bp, curve, curve_len);
    ssh2_store_str(&bp, point, point_len);

    *pubkeydata = blob;
    *pubkeydata_len = len;
    return 0;
}

/* Right-aligns an unsigned big-endian number into n bytes. Fails if it
   does not fit; surplus leading zeros and short numbers are fine. */
static int mbed_uint_fixed(unsigned char *dst, size_t n,
                           const unsigned char *src, size_t len)
{
    while(len > n && *src == 0) {
        src++;
        len--;
    }
    if(len > n)
        return -1;
    memset(dst, 0, n - len);
    memcpy(dst + n - len, src, len);
    return 0;
}

/* OpenSSH private key format, which the pk parser does not read */
static int mbed_parse_openssh_key(psa_key_id_t *ctx,
                                  LIBSSH2_SESSION *session,
                                  const char *filename,
                                  const char *data, size_t data_len,
                                  const char *passphrase)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    struct string_buf *decrypted = NULL;
    char *name = NULL;
    unsigned char *curvebuf, *exponent, *pointbuf, *d = NULL;
    size_t name_len, curvebuf_len, exponent_len, pointbuf_len, n = 0;
    const char *method, *curve_name;
    ssh2_curve_type curve;
    int ret = -1;

    if(ssh2_openssh_pem_parse(session, filename, data, data_len,
                              passphrase, &decrypted))
        goto cleanup;

    if(ssh2_get_chars(decrypted, &name, &name_len) ||
       ssh2_pem_ecdsa_curve_type_from_name(name, name_len, &curve) ||
       ssh2_get_string(decrypted, &curvebuf, &curvebuf_len) ||
       ssh2_get_string(decrypted, &pointbuf, &pointbuf_len) ||
       ssh2_get_bignum_bytes(decrypted, &exponent, &exponent_len))
        goto cleanup;

    /* the stored curve name must agree with the key type; the stored
       point is ignored, the public key is derived from the scalar */
    if(mbed_ecdsa_names(curve, &method, &curve_name) ||
       curvebuf_len != strlen(curve_name) ||
       memcmp(curvebuf, curve_name, curvebuf_len))
        goto cleanup;

    /* PSA wants the private scalar exactly curve-sized, the mpint is not */
    n = PSA_BITS_TO_BYTES(curve);
    d = SSH2_ALLOC(session, n);
    if(!d || mbed_uint_fixed(d, n, exponent, exponent_len))
        goto cleanup;

    psa_set_key_type(&attr, MBED_ECC_PAIR);
    psa_set_key_bits(&attr, curve);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
                                   PSA_KEY_USAGE_SIGN_MESSAGE |
                                   PSA_KEY_USAGE_VERIFY_HASH |
                                   PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attr, MBED_ECDSA_ALG);
    if(psa_import_key(&attr, d, n, ctx) == PSA_SUCCESS)
        ret = 0;
    psa_reset_key_attributes(&attr);

cleanup:

    ssh2_zero_free(session, d, n);
    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

    return ret;
}

/* Public key blob and method of an OpenSSH-format ECDSA private key */
static int mbed_ecdsa_openssh_pub(LIBSSH2_SESSION *session, char **method,
                                  unsigned char **pubkeydata,
                                  size_t *pubkeydata_len,
                                  const char *filename,
                                  const char *blob, size_t blob_len,
                                  const char *passphrase)
{
    psa_key_id_t key = PSA_KEY_ID_NULL;
    const char *method_name, *curve_name;
    size_t bits;
    int ret = -1;

    if(mbed_parse_openssh_key(&key, session, filename, blob, blob_len,
                              passphrase))
        return -1;

    if(mbed_key_bits(key, &bits) == 0 &&
       mbed_ecdsa_names(bits, &method_name, &curve_name) == 0 &&
       mbed_ecdsa_pubkey(session, key, method_name, curve_name,
                         pubkeydata, pubkeydata_len) == 0) {
        ret = mbed_method_dup(session, method, method_name, pubkeydata,
                              pubkeydata_len);
    }

    psa_destroy_key(key);
    return ret;
}
#endif /* LIBSSH2_ECDSA */

static int mbed_pub_priv_key(LIBSSH2_SESSION *session, char **method,
                             unsigned char **pubkeydata,
                             size_t *pubkeydata_len,
                             const mbedtls_pk_context *pk)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_key_type_t type;
    const char *method_name = NULL;
#if LIBSSH2_ECDSA
    const char *curve_name;
#endif
    size_t bits;
    int ret;

    /* a public-only import reads pk->pub_raw, which the 4.x RSA parser does
       not fill, so the pair is imported and the public half exported */
    if(mbedtls_pk_get_psa_attributes(pk, PSA_KEY_USAGE_SIGN_HASH, &attr) ||
       mbedtls_pk_import_into_psa(pk, &attr, &key)) {
        size_t pk_bits = mbed_pk_rsa_bits(pk);
        psa_reset_key_attributes(&attr);
#if LIBSSH2_RSA
        if(pk_bits) {
            int err = mbed_rsa_size_err(session, LIBSSH2_ERROR_FILE, pk_bits);
            if(err != -1)
                return err;
        }
#endif
        return ssh2_err(session, LIBSSH2_ERROR_FILE, "Key type not supported");
    }
    type = psa_get_key_type(&attr);
    bits = psa_get_key_bits(&attr);
    psa_reset_key_attributes(&attr);

#if LIBSSH2_RSA
    if(type == PSA_KEY_TYPE_RSA_KEY_PAIR) {
        method_name = "ssh-rsa";
        ret = mbed_rsa_pubkey(session, key, pubkeydata, pubkeydata_len);
    }
    else
#endif
#if LIBSSH2_ECDSA
    if(PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type) &&
       PSA_KEY_TYPE_ECC_GET_FAMILY(type) == PSA_ECC_FAMILY_SECP_R1 &&
       mbed_ecdsa_names(bits, &method_name, &curve_name) == 0) {
        ret = mbed_ecdsa_pubkey(session, key, method_name, curve_name,
                                pubkeydata, pubkeydata_len);
    }
    else
#endif
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE, "Key type not supported");

    if(ret == 0)
        ret = mbed_method_dup(session, method, method_name, pubkeydata,
                              pubkeydata_len);

    psa_destroy_key(key);
    return ret;
}

int ssh2_pub_privkey(LIBSSH2_SESSION *session, char **method,
                     unsigned char **pubkeydata, size_t *pubkeydata_len,
                     const char *privkeyfile,
                     const char *privkeyblob, size_t privkeyblob_len,
                     const char *passphrase)
{
    mbedtls_pk_context pk;
    char buf[1024];
    int ret;

    mbedtls_pk_init(&pk);
    ret = mbed_pk_parse(&pk, session, privkeyfile,
                        privkeyblob, privkeyblob_len, passphrase);
    if(ret) {
#if LIBSSH2_ECDSA
        if(mbed_ecdsa_openssh_pub(session, method, pubkeydata, pubkeydata_len,
                                  privkeyfile, privkeyblob, privkeyblob_len,
                                  passphrase) == 0) {
            mbedtls_pk_free(&pk);
            return 0;
        }
#endif
        mbedtls_strerror(ret, buf, sizeof(buf));
        mbedtls_pk_free(&pk);
        return ssh2_err_flags(session, LIBSSH2_ERROR_FILE, buf,
                              SSH2_ERR_FLAG_DUP);
    }

    ret = mbed_pub_priv_key(session, method,
                            pubkeydata, pubkeydata_len, &pk);

    mbedtls_pk_free(&pk);

    return ret;
}

/*******************************************************************/
/*
 * mbedTLS backend: Diffie-Hellman functions
 */

void ssh2_dh_init(ssh2_dh_ctx *dhctx)
{
    *dhctx = ssh2_bn_init(); /* Random from client */
}

int ssh2_dh_key_pair(ssh2_dh_ctx *dhctx, ssh2_bn *pub, const ssh2_bn *g,
                     const ssh2_bn *p, int group_order, ssh2_bn_ctx *bnctx)
{
    (void)bnctx;

    if(group_order <= 0)
        return -1;

    /* Generate x and e */
    if(mbed_bn_random(*dhctx, (group_order * 8) - 1, 0, -1) ||
       mbedtls_mpi_exp_mod(pub, g, *dhctx, p, NULL))
        return -1;
    return 0;
}

int ssh2_dh_validate(const ssh2_bn *f, const ssh2_bn *p)
{
    mbedtls_mpi one, tmp;
    size_t n, i, bits_set;

    /* Verify if valid */
    mbedtls_mpi_init(&one);
    if(mbedtls_mpi_lset(&one, 1)) {
        mbedtls_mpi_free(&one);
        return -4;
    }
    if(mbedtls_mpi_cmp_mpi(f, &one) != 1) {
        mbedtls_mpi_free(&one);
        return -1;  /* f <= 1 */
    }

    mbedtls_mpi_init(&tmp);
    if(mbedtls_mpi_copy(&tmp, p) ||  /* tmp = p */
       mbedtls_mpi_sub_int(&tmp, &tmp, 2)) {  /* tmp -= 2 */
        mbedtls_mpi_free(&tmp);
        mbedtls_mpi_free(&one);
        return -5;
    }
    if(mbedtls_mpi_cmp_mpi(f, &tmp) == 1) {
        mbedtls_mpi_free(&tmp);
        mbedtls_mpi_free(&one);
        return -2;  /* f >= p - 1 (== f > p - 2) */
    }

    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&one);

    for(i = 0, n = mbedtls_mpi_bitlen(f), bits_set = 0; i < n; ++i)
        if(mbedtls_mpi_get_bit(f, i))
            ++bits_set;

    if(bits_set < 4)
        return -3;

    return 0;
}

int ssh2_dh_secret(ssh2_dh_ctx *dhctx, ssh2_bn *secret,
                   const ssh2_bn *f, const ssh2_bn *p, ssh2_bn_ctx *bnctx)
{
    (void)bnctx;

    if(ssh2_dh_validate(f, p))  /* Verify if parameters are valid */
        return -1;

    /* Compute the shared secret */
    if(mbedtls_mpi_exp_mod(secret, f, *dhctx, p, NULL))
        return -1;
    return 0;
}

void ssh2_dh_dtor(ssh2_dh_ctx *dhctx)
{
    ssh2_bn_free(*dhctx);
    *dhctx = NULL;
}

#if LIBSSH2_ECDSA

/*******************************************************************/
/*
 * mbedTLS backend: ECDSA functions
 */

/* Only the three NIST curves SSH knows are usable */
static int mbed_ecdsa_key_ok(psa_key_id_t key)
{
    size_t bits;

    return mbed_key_bits(key, &bits) == 0 &&
           mbed_ecdsa_curve_hash(bits) != PSA_ALG_NONE;
}

/*
 * Creates a local private key based on input curve
 * and returns octal value and octal length
 */
int ssh2_ecdsa_create_key(ssh2_ec_key **ec_ctx, LIBSSH2_SESSION *session,
                          unsigned char **out_public_key_octal,
                          size_t *out_public_key_octal_len,
                          ssh2_curve_type curve)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t size = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(MBED_ECC_PUBLIC, curve);
    unsigned char *pub = NULL;
    int ret = -1;

    if(out_public_key_octal)
        *out_public_key_octal = NULL;
    *ec_ctx = mbed_key_alloc(session);
    if(!*ec_ctx)
        return -1;

    /* the caller may only want the key, not its point */
    if(out_public_key_octal) {
        pub = SSH2_ALLOC(session, size);
        if(!pub)
            goto cleanup;
    }

    psa_set_key_type(&attr, MBED_ECC_PAIR);
    psa_set_key_bits(&attr, curve);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    if(psa_generate_key(&attr, *ec_ctx) == PSA_SUCCESS &&
       (!pub || psa_export_public_key(**ec_ctx, pub, size,
                                      out_public_key_octal_len) ==
        PSA_SUCCESS)) {
        if(pub)
            *out_public_key_octal = pub;
        ret = 0;
    }
    psa_reset_key_attributes(&attr);

cleanup:

    if(ret) {
        if(pub)
            SSH2_FREE(session, pub);
        mbed_key_free(*ec_ctx, session);
        *ec_ctx = NULL;
    }
    return ret;
}

/*
 * Creates a new public key given an octal string, length and type
 */
int ssh2_ecdsa_curve_name_with_octal_new(
    ssh2_ecdsa_ctx **ec_ctx, LIBSSH2_SESSION *session,
    const unsigned char *publickey_encoded, size_t publickey_encoded_len,
    ssh2_curve_type curve)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    int ret = -1;

    *ec_ctx = NULL;
    if(publickey_encoded_len != 1 + 2 * PSA_BITS_TO_BYTES(curve))
        return -1;

    *ec_ctx = mbed_key_alloc(session);
    if(!*ec_ctx)
        return -1;

    psa_set_key_type(&attr, MBED_ECC_PUBLIC);
    psa_set_key_bits(&attr, curve);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH |
                                   PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attr, MBED_ECDSA_ALG);
    /* PSA rejects points that are not on the curve */
    if(psa_import_key(&attr, publickey_encoded, publickey_encoded_len,
                      *ec_ctx) == PSA_SUCCESS)
        ret = 0;
    psa_reset_key_attributes(&attr);

    if(ret) {
        mbed_key_free(*ec_ctx, session);
        *ec_ctx = NULL;
    }
    return ret;
}

/*
 * Computes the shared secret K given a local private key,
 * remote public key and length
 */
int ssh2_ecdh_gen_k(ssh2_bn **k, LIBSSH2_SESSION *session,
                    ssh2_ec_key *private_key,
                    const unsigned char *server_public_key,
                    size_t server_public_key_len)
{
    size_t size = PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(MBED_ECC_PAIR, 521);
    size_t secret_len = 0;
    unsigned char *secret;
    int ret = -1;

    if(!*k)
        return -1;

    secret = SSH2_ALLOC(session, size);
    if(!secret)
        return -1;

    if(psa_raw_key_agreement(PSA_ALG_ECDH, *private_key,
                             server_public_key, server_public_key_len,
                             secret, size, &secret_len) == PSA_SUCCESS &&
       mbedtls_mpi_read_binary(*k, secret, secret_len) == 0)
        ret = 0;

    ssh2_zero_free(session, secret, size);
    return ret;
}

/*
 * Verifies the ECDSA signature of a hashed message
 */
int ssh2_ecdsa_verify(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session,
                      const unsigned char *r, size_t r_len,
                      const unsigned char *s, size_t s_len,
                      const unsigned char *m, size_t m_len)
{
    unsigned char sig[2 * PSA_BITS_TO_BYTES(521)];
    psa_algorithm_t hash_alg;
    size_t bits, n;

    (void)session;

    if(mbed_key_bits(*ec_ctx, &bits))
        return -1;
    hash_alg = mbed_ecdsa_curve_hash(bits);
    if(hash_alg == PSA_ALG_NONE)
        return -1;

    /* the wire has r and s as mpints, PSA wants fixed-width r || s */
    n = PSA_BITS_TO_BYTES(bits);
    if(mbed_uint_fixed(sig, n, r, r_len) ||
       mbed_uint_fixed(sig + n, n, s, s_len))
        return -1;

    return psa_verify_message(*ec_ctx, PSA_ALG_ECDSA(hash_alg), m, m_len,
                              sig, 2 * n) == PSA_SUCCESS ? 0 : -1;
}

/*
 * returns key curve type that maps to ssh2_curve_type
 */
ssh2_curve_type ssh2_ecdsa_get_curve_type(const ssh2_ecdsa_ctx *ec_ctx)
{
    size_t bits = 0;

    mbed_key_bits(*ec_ctx, &bits);
    return (ssh2_curve_type)bits;
}

/*
 * Creates a new private key given a file/blob and password
 */
int ssh2_ecdsa_new_priv(ssh2_ecdsa_ctx **ec_ctx,
                        LIBSSH2_SESSION *session,
                        const char *filename,
                        const char *blob, size_t blob_len,
                        const char *passphrase)
{
    mbedtls_pk_context pk;
    int ret = -1;

    *ec_ctx = mbed_key_alloc(session);
    if(!*ec_ctx)
        return -1;

    /* try mbedTLS parser */

    mbedtls_pk_init(&pk);
    if(mbed_pk_parse(&pk, session, filename, blob, blob_len,
                     passphrase) == 0 &&
       mbed_pk_import(&pk, MBED_ECC_PAIR, MBED_ECDSA_ALG, *ec_ctx) == 0 &&
       mbed_ecdsa_key_ok(**ec_ctx))
        ret = 0;
    mbedtls_pk_free(&pk);

    /* try local parser */

    if(ret) {
        psa_destroy_key(**ec_ctx);
        **ec_ctx = PSA_KEY_ID_NULL;
        if(mbed_parse_openssh_key(*ec_ctx, session, filename, blob, blob_len,
                                  passphrase) == 0)
            ret = 0;
    }

    if(ret) {
        mbed_key_free(*ec_ctx, session);
        *ec_ctx = NULL;
    }
    return ret;
}

/*
 * Computes the ECDSA signature of a previously-hashed message
 */
int ssh2_ecdsa_sign(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char **signature, size_t *signature_len)
{
    psa_algorithm_t hash_alg = mbed_ecdsa_hash_alg(hash_len);
    unsigned char raw[2 * PSA_BITS_TO_BYTES(521)], *sig, *sp;
    size_t bits, n, raw_len;

    /* the digest must be the one the curve calls for */
    if(hash_alg == PSA_ALG_NONE || mbed_key_bits(*ec_ctx, &bits) ||
       mbed_ecdsa_curve_hash(bits) != hash_alg)
        return -1;

    n = PSA_BITS_TO_BYTES(bits);
    if(psa_sign_hash(*ec_ctx, PSA_ALG_ECDSA(hash_alg), hash, hash_len,
                     raw, sizeof(raw), &raw_len) != PSA_SUCCESS ||
       raw_len != 2 * n)
        return -1;

    /* r and s as mpints: length prefix and a sign byte each at worst */
    sig = SSH2_ALLOC(session, 2 * (4 + n + 1));
    if(!sig)
        return -1;
    sp = sig;
    ssh2_store_bignum_bytes(&sp, raw, n);
    ssh2_store_bignum_bytes(&sp, raw + n, n);

    *signature = sig;
    *signature_len = (size_t)(sp - sig);
    return 0;
}

void ssh2_ecdsa_free(ssh2_ecdsa_ctx *ec_ctx, LIBSSH2_SESSION *session)
{
    mbed_key_free(ec_ctx, session);
}
#endif /* LIBSSH2_ECDSA */

#endif /* LIBSSH2_MBEDTLS */
