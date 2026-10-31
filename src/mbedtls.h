#ifndef LIBSSH2_MBEDTLS_H
#define LIBSSH2_MBEDTLS_H
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

#define SSH2_CRYPTO_ENGINE libssh2_mbedtls
#define SSH2_CRYPTO_ENGINE_NAME "mbedTLS"

/* 4.x hides mpi behind this, 3.x ignores it */
#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER < 0x03060000
#  error "mbedTLS 3.6.0 or greater required"
#endif
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>
#if !(defined(PSA_WANT_ALG_ECDSA) && PSA_WANT_ALG_ECDSA && \
      defined(PSA_WANT_ALG_ECDH) && PSA_WANT_ALG_ECDH && \
      defined(PSA_WANT_ECC_SECP_R1_256) && PSA_WANT_ECC_SECP_R1_256 && \
      defined(PSA_WANT_ECC_SECP_R1_384) && PSA_WANT_ECC_SECP_R1_384 && \
      defined(PSA_WANT_ECC_SECP_R1_521) && PSA_WANT_ECC_SECP_R1_521)
#  error "ECDH/ECDSA with nistp256, nistp384, nistp521 curves is required"
#endif
#if MBEDTLS_VERSION_NUMBER < 0x04000000
#include <mbedtls/bignum.h>
#include <mbedtls/psa_util.h>  /* mbedtls_psa_get_random() */
#else
/* mpi is kept for DH and bignum marshaling, PSA has no general bignum */
#include <mbedtls/private/bignum.h>
#endif
#include <mbedtls/pk.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>

/* Define which features are supported. */
#if defined(PSA_WANT_ALG_MD5) && PSA_WANT_ALG_MD5
#define LIBSSH2_MD5 1
#else
#define LIBSSH2_MD5 0
#endif

#if defined(PSA_WANT_ALG_RIPEMD160) && PSA_WANT_ALG_RIPEMD160
#define LIBSSH2_HMAC_RIPEMD 1
#else
#define LIBSSH2_HMAC_RIPEMD 0
#endif
#define LIBSSH2_HMAC_SHA256 1
#define LIBSSH2_HMAC_SHA512 1

#if defined(PSA_WANT_KEY_TYPE_AES) && PSA_WANT_KEY_TYPE_AES && \
    defined(PSA_WANT_ALG_CBC_NO_PADDING) && PSA_WANT_ALG_CBC_NO_PADDING
#define LIBSSH2_AES_CBC 1
#else
#define LIBSSH2_AES_CBC 0
#endif
#if defined(PSA_WANT_KEY_TYPE_AES) && PSA_WANT_KEY_TYPE_AES && \
    defined(PSA_WANT_ALG_CTR) && PSA_WANT_ALG_CTR
#define LIBSSH2_AES_CTR 1
#else
#define LIBSSH2_AES_CTR 0
#endif
#if defined(PSA_WANT_KEY_TYPE_AES) && PSA_WANT_KEY_TYPE_AES && \
    defined(PSA_WANT_ALG_GCM) && PSA_WANT_ALG_GCM
#define LIBSSH2_AES_GCM 1
#else
#define LIBSSH2_AES_GCM 0
#endif
#define LIBSSH2_BLOWFISH 0
#define LIBSSH2_RC4 0
#define LIBSSH2_CAST 0
#if defined(PSA_WANT_KEY_TYPE_DES) && PSA_WANT_KEY_TYPE_DES && \
    defined(PSA_WANT_ALG_CBC_NO_PADDING) && PSA_WANT_ALG_CBC_NO_PADDING
#define LIBSSH2_3DES 1
#else
#define LIBSSH2_3DES 0
#endif

#define LIBSSH2_RSA 1
#define LIBSSH2_RSA_SHA1 1
#define LIBSSH2_RSA_SHA2 1
#define LIBSSH2_DSA 0
#define LIBSSH2_ECDSA 1  /* guaranteed by the #error above */
/* Monocypher provides ED25519 and X25519, independent of Mbed TLS */
#define LIBSSH2_ED25519 1
#define LIBSSH2_MLKEM 0

#include "crypto_config.h"

/*******************************************************************/
/*
 * mbedTLS backend: HMAC functions
 */

struct mbed_hash_ctx {
    psa_mac_operation_t mac;
    psa_key_id_t key_id;
};

#define ssh2_hmac_ctx          struct mbed_hash_ctx

#define ssh2_hmac_update(ctx, d, l) \
    (psa_mac_update(&((ctx)->mac), (const uint8_t *)(d), l) == PSA_SUCCESS)

#if LIBSSH2_HMAC_RIPEMD
#define SSH2_RIPEMD160_HMAC    PSA_ALG_RIPEMD160
#endif

/*******************************************************************/
/*
 * mbedTLS backend: hash functions
 */

#define ssh2_hash_ctx          psa_hash_operation_t
#define ssh2_hash_alg          psa_algorithm_t
#define ssh2_hash_update(ctx, d, l) \
    (psa_hash_update(ctx, (const uint8_t *)(d), l) == PSA_SUCCESS)

#define SSH2_SHA1_ALG          PSA_ALG_SHA_1
#define SSH2_SHA256_ALG        PSA_ALG_SHA_256
#define SSH2_SHA384_ALG        PSA_ALG_SHA_384
#define SSH2_SHA512_ALG        PSA_ALG_SHA_512
#if LIBSSH2_MD5 || LIBSSH2_MD5_PEM
#define SSH2_MD5_ALG           PSA_ALG_MD5
#endif

/*******************************************************************/
/*
 * mbedTLS backend: RSA functions
 */

/* Keys live in the PSA key store; a context is a heap-held key id. */
#define ssh2_rsa_ctx           psa_key_id_t

/*******************************************************************/
/*
 * mbedTLS backend: ECDSA structures
 */

#if LIBSSH2_ECDSA
typedef enum {
    /* the value is the PSA key size in bits */
    SSH2_EC_CURVE_NISTP256 = 256,
    SSH2_EC_CURVE_NISTP384 = 384,
    SSH2_EC_CURVE_NISTP521 = 521
} ssh2_curve_type;

/* Keys live in the PSA key store; a context is a heap-held key id. */
#define ssh2_ecdsa_ctx         psa_key_id_t
#define ssh2_ec_key            psa_key_id_t
#endif /* LIBSSH2_ECDSA */

/*******************************************************************/
/*
 * mbedTLS backend: ED25519 structures
 */

#if LIBSSH2_ED25519
struct mbed_ed25519_ctx {
    uint8_t public_key[32];
    uint8_t private_key[64];  /* seed || public key, valid if has_private */
    int has_private;
};
#define ssh2_ed25519_ctx       struct mbed_ed25519_ctx
#endif /* LIBSSH2_ED25519 */

/*******************************************************************/
/*
 * mbedTLS backend: Cipher Context structure
 */

typedef enum {
    MBED_CIPHER_AES128_CTR,
    MBED_CIPHER_AES192_CTR,
    MBED_CIPHER_AES256_CTR,
    MBED_CIPHER_AES128_CBC,
    MBED_CIPHER_AES192_CBC,
    MBED_CIPHER_AES256_CBC,
    MBED_CIPHER_3DES_CBC,
    MBED_CIPHER_AES128_GCM,
    MBED_CIPHER_AES256_GCM,
    MBED_CIPHER_CHACHA20_POLY1305  /* placeholder, never implemented */
} ssh2_mbed_cipher_type;

/* The key lives in the PSA key store. A plain cipher keeps one PSA
   operation open for the life of the context; an AEAD cipher sets up an
   operation per packet and keeps the IV (bumped after each packet). */
struct ssh2_mbed_cipher_ctx {
    psa_key_id_t key;
    psa_algorithm_t alg;
    int is_aead;
    int aead_active;  /* an operation is open between FIRST and LAST */
    union {
        psa_cipher_operation_t cipher;
        psa_aead_operation_t aead;
    } op;
    unsigned char iv[12];
};

#define ssh2_cipher_ctx        struct ssh2_mbed_cipher_ctx

#define SSH2_CIPHER_T(algo)    ssh2_mbed_cipher_type algo

#define ssh2_cipher_aes256ctr  MBED_CIPHER_AES256_CTR
#define ssh2_cipher_aes192ctr  MBED_CIPHER_AES192_CTR
#define ssh2_cipher_aes128ctr  MBED_CIPHER_AES128_CTR
#define ssh2_cipher_aes256     MBED_CIPHER_AES256_CBC
#define ssh2_cipher_aes192     MBED_CIPHER_AES192_CBC
#define ssh2_cipher_aes128     MBED_CIPHER_AES128_CBC
#if LIBSSH2_3DES
#define ssh2_cipher_3des       MBED_CIPHER_3DES_CBC
#endif
#define ssh2_cipher_aes128gcm  MBED_CIPHER_AES128_GCM
#define ssh2_cipher_aes256gcm  MBED_CIPHER_AES256_GCM
#define ssh2_cipher_chacha20   MBED_CIPHER_CHACHA20_POLY1305

/*******************************************************************/
/*
 * mbedTLS backend: BigNumber Support
 */

#define ssh2_bn                        mbedtls_mpi
#define ssh2_bn_set_word(bn, word)     mbedtls_mpi_lset(bn, (long long)(word))
#define ssh2_bn_to_bin(bn, bin) \
    mbedtls_mpi_write_binary(bn, bin, mbedtls_mpi_size(bn))
#define ssh2_bn_bytes(bn)              mbedtls_mpi_size(bn)
#define ssh2_bn_bits(bn)               mbedtls_mpi_bitlen(bn)

/*******************************************************************/
/*
 * mbedTLS backend: Diffie-Hellman support.
 */

#define ssh2_dh_ctx            mbedtls_mpi *

/* Default generate and safe prime sizes for
   diffie-hellman-group-exchange-sha1 */
#define SSH2_DH_GEX_MINGROUP     2048
#define SSH2_DH_GEX_OPTGROUP     4096
#define SSH2_DH_GEX_MAXGROUP     8192

#define SSH2_DH_MAX_MODULUS_BITS 16384

#endif /* LIBSSH2_MBEDTLS_H */
