#ifndef _CRYPTO_OPENSSL_COMPAT_H_
#define _CRYPTO_OPENSSL_COMPAT_H_

/*
 * OpenSSL 1.1.0 makes RSA an opaque structure and provides accessor
 * functions.  The solution given on:
 *   https://wiki.openssl.org/index.php/1.1_API
 * for code wanting to support 1.0.x is to backport these accessor functions.
 *
 * The function prototypes should be the same as:
 *   https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_key.html
 *   https://github.com/openssl/openssl/blob/OpenSSL_1_1_0-stable/include/openssl/rsa.h
 * (other than formatting)
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/rsa.h>

int RSA_set0_key(RSA * r, BIGNUM * n, BIGNUM * e, BIGNUM * d);
int RSA_set0_factors(RSA * r, BIGNUM * p, BIGNUM * q);
int RSA_set0_crt_params(RSA * r, BIGNUM * dmp1, BIGNUM * dmq1, BIGNUM * iqmp);
void RSA_get0_key(const RSA * r, const BIGNUM ** n, const BIGNUM ** e,
    const BIGNUM ** d);
void RSA_get0_factors(const RSA * r, const BIGNUM ** p, const BIGNUM ** q);
void RSA_get0_crt_params(const RSA * r, const BIGNUM ** dmp1,
    const BIGNUM ** dmq1, const BIGNUM ** iqmp);
#endif
#endif
