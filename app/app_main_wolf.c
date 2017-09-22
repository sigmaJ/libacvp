/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
* All rights reserved.

* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
/*
 * This module is not part of libacvp.  Rather, it's a simple app that
 * demonstrates how to use libacvp. Software that use libacvp
 * will need to implement a similar module.
 *
 * It will default to 127.0.0.1 port 443 if no arguments are given.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "acvp.h"
#ifdef USE_MURL
#include <murl/murl.h>
#else
#include <curl/curl.h>
#endif
#include <wolfssl/wolfcrypt/sha256.h>
#if 0
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef ACVP_NO_RUNTIME
#include "app_lcl.h"
#include <openssl/fips_rand.h>
#include <openssl/fips.h>
extern int fips_selftest_fail;
extern int fips_mode;
int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
    const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
    unsigned char *seed_out,
    int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
int dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
    const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
    int idx, unsigned char *seed_out,
    int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
#endif

static ACVP_RESULT app_sha_handler(ACVP_TEST_CASE *test_case);

#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_PORT 443
#define DEFAULT_CA_CHAIN "certs/acvp-private-root-ca.crt.pem"
#define DEFAULT_CERT "certs/sto-labsrv2-client-cert.pem"
#define DEFAULT_KEY "certs/sto-labsrv2-client-key.pem"

#define TLS_MD_MASTER_SECRET_CONST              "master secret"
#define TLS_MD_MASTER_SECRET_CONST_SIZE         13
#define TLS_MD_KEY_EXPANSION_CONST              "key expansion"
#define TLS_MD_KEY_EXPANSION_CONST_SIZE         13

char *server;
int port;
char *ca_chain_file;
char *cert_file;
char *key_file;
char *path_segment;
//static EVP_CIPHER_CTX cipher_ctx;  /* need to maintain across calls for MCT */ we don't understand this so we're leaving it commented out

#define CHECK_ENABLE_CAP_RV(rv) \
    if (rv != ACVP_SUCCESS) { \
        printf("Failed to register capability with libacvp (rv=%d)\n", rv); \
        exit(1); \
    }


/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void setup_session_parameters()
{
    char *tmp;

    server = getenv("ACV_SERVER");
    if (!server) server = DEFAULT_SERVER;

    tmp = getenv("ACV_PORT");
    if (tmp) port = atoi(tmp);
    if (!port) port = DEFAULT_PORT;

    path_segment = getenv("ACV_URI_PREFIX");
    if (!path_segment) path_segment = "";

    ca_chain_file = getenv("ACV_CA_FILE");
    if (!ca_chain_file) ca_chain_file = DEFAULT_CA_CHAIN;

    cert_file = getenv("ACV_CERT_FILE");
    if (!cert_file) cert_file = DEFAULT_CERT;

    key_file = getenv("ACV_KEY_FILE");
    if (!key_file) key_file = DEFAULT_KEY;

    printf("Using the following parameters:\n\n");
    printf("    ACV_SERVER:     %s\n", server);
    printf("    ACV_PORT:       %d\n", port);
    printf("    ACV_URI_PREFIX: %s\n", path_segment);
    printf("    ACV_CA_FILE:    %s\n", ca_chain_file);
    printf("    ACV_CERT_FILE:  %s\n", cert_file);
    printf("    ACV_KEY_FILE:   %s\n\n", key_file);
}

/*
 * This is a minimal and rudimentary logging handler.
 * libacvp calls this function to for debugs, warnings,
 * and errors.
 */
ACVP_RESULT progress(char *msg)
{
    printf("%s", msg);
    return ACVP_SUCCESS;
}

static void print_usage(void)
{
    printf("\nInvalid usage...\n");
    printf("acvp_app does not require any argument, however logging level can be\n");
    printf("controlled using:\n");
    printf("      -none\n");
    printf("      -error\n");
    printf("      -warn\n");
    printf("      -status(default)\n");
    printf("      -info\n");
    printf("      -verbose\n");
    printf("\n");
    printf("In addition some options are passed to acvp_app using\n");
    printf("environment variables.  The following variables can be set:\n\n");
    printf("    ACV_SERVER (when not set, defaults to %s)\n", DEFAULT_SERVER);
    printf("    ACV_PORT (when not set, defaults to %d)\n", DEFAULT_PORT);
    printf("    ACV_URI_PREFIX (when not set, defaults to null)\n");
    printf("    ACV_CA_FILE (when not set, defaults to %s)\n", DEFAULT_CA_CHAIN);
    printf("    ACV_CERT_FILE (when not set, defaults to %s)\n", DEFAULT_CERT);
    printf("    ACV_KEY_FILE (when not set, defaults to %s)\n\n", DEFAULT_KEY);
    printf("The CA certificates, cert and key should be PEM encoded. There should be no\n");
    printf("password on the key file.\n");
}

int main(int argc, char **argv)
{
    ACVP_RESULT rv;
    ACVP_CTX *ctx;
    char ssl_version[10];
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    char value[] = "same";

    if (argc > 2) {
        print_usage();
        return 1;
    }

    argv++;
    argc--;
    while (argc >= 1) {
        if (strcmp(*argv, "-info") == 0) {
            level = ACVP_LOG_LVL_INFO;
        }
        if (strcmp(*argv, "-status") == 0) {
            level = ACVP_LOG_LVL_STATUS;
        }
        if (strcmp(*argv, "-warn") == 0) {
            level = ACVP_LOG_LVL_WARN;
        }
        if (strcmp(*argv, "-error") == 0) {
            level = ACVP_LOG_LVL_ERR;
        }
        if (strcmp(*argv, "-none") == 0) {
            level = ACVP_LOG_LVL_NONE;
        }
        if (strcmp(*argv, "-verbose") == 0) {
            level = ACVP_LOG_LVL_VERBOSE;
        }
        if (strcmp(*argv, "-help") == 0) {
            print_usage();
            return 1;
        }
    argv++;
    argc--;
    }

#ifdef ACVP_NO_RUNTIME
    fips_selftest_fail = 0;
    fips_mode = 0;
    fips_algtest_init_nofips();
#endif

//  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    setup_session_parameters();

    /*
     * We begin the libacvp usage flow here.
     * First, we create a test session context.
     */
    rv = acvp_create_test_session(&ctx, &progress, level);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to create ACVP context\n");
        exit(1);
    }

    /*
     * Next we specify the ACVP server address
     */
    rv = acvp_set_server(ctx, server, port);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set server/port\n");
        exit(1);
    }

    /*
     * Setup the vendor attributes
     */
    rv = acvp_set_vendor_info(ctx, "Cisco Systems", "www.cisco.com", "Barry Fussell", "bfussell@cisco.com");
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set vendor info\n");
        exit(1);
    }

    /*
     * Setup the crypto module attributes
     */
    snprintf(ssl_version, 10, "%08x", (unsigned int)SSLeay());
    rv = acvp_set_module_info(ctx, "OpenSSL", "software", ssl_version, "FOM 6.2a");
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set module info\n");
        exit(1);
    }

    /*
     * Set the path segment prefix if needed
     */
     if (strnlen(path_segment, 255) > 0) {
        rv = acvp_set_path_segment(ctx, path_segment);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set URI prefix\n");
            exit(1);
        }
     }

    /*
     * Next we provide the CA certs to be used by libacvp
     * to verify the ACVP TLS certificate.
     */
    rv = acvp_set_cacerts(ctx, ca_chain_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set CA certs\n");
        exit(1);
    }

    /*
     * Specify the certificate and private key the client should used
     * for TLS client auth.
     */
    rv = acvp_set_certkey(ctx, cert_file, key_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set TLS cert/key\n");
        exit(1);
    }

    /*
     * We need to register all the crypto module capabilities that will be
     * validated.
     */

   /*
    * Enable SHA-1 and SHA-2
    */
/*
   rv = acvp_enable_hash_cap(ctx, ACVP_SHA1, &app_sha_handler);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA1, ACVP_HASH_IN_BIT, 0);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA1, ACVP_HASH_IN_EMPTY, 1);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap(ctx, ACVP_SHA224, &app_sha_handler);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA224, ACVP_HASH_IN_BIT, 0);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA224, ACVP_HASH_IN_EMPTY, 1);
   CHECK_ENABLE_CAP_RV(rv);

*/
   rv = acvp_enable_hash_cap(ctx, ACVP_SHA256, &app_sha_handler);
   CHECK_ENABLE_CAP_RV(rv);
/*
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA256, ACVP_HASH_IN_BIT, 0);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA256, ACVP_HASH_IN_EMPTY, 1);
   CHECK_ENABLE_CAP_RV(rv);

   rv = acvp_enable_hash_cap(ctx, ACVP_SHA384, &app_sha_handler);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA384, ACVP_HASH_IN_BIT, 0);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA384, ACVP_HASH_IN_EMPTY, 1);
   CHECK_ENABLE_CAP_RV(rv);

   rv = acvp_enable_hash_cap(ctx, ACVP_SHA512, &app_sha_handler);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA512, ACVP_HASH_IN_BIT, 0);
   CHECK_ENABLE_CAP_RV(rv);
   rv = acvp_enable_hash_cap_parm(ctx, ACVP_SHA512, ACVP_HASH_IN_EMPTY, 1);
   CHECK_ENABLE_CAP_RV(rv);
*/

    /*
     * Now that we have a test session, we register with
     * the server to advertise our capabilities and receive
     * the KAT vector sets the server demands that we process.
     */
    rv = acvp_register(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to register with ACVP server (rv=%d)\n", rv);
        exit(1);
    }

    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = acvp_process_tests(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to process vectors (%d)\n", rv);
        exit(1);
    }

    printf("\nTests complete, checking results...\n");
    rv = acvp_check_test_results(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Unable to retrieve test results (%d)\n", rv);
        exit(1);
    }
    /*
     * Finally, we free the test session context and cleanup
     */
    rv = acvp_free_test_session(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to free ACVP context\n");
        exit(1);
    }
    acvp_cleanup();

    // BN_free(expo); /* needed when passing bignum arg to rsa keygen from app */

    return (0);
}

static ACVP_RESULT app_sha_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_HASH_TC    *tc;
    Sha256 sha[1];

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.hash;

    switch (tc->cipher) {
        case ACVP_SHA256:
            // algorithm currently supported by this client
            break;
        default:
            printf("Error: Unsupported hash algorithm requested by ACVP server\n");
            return ACVP_NO_CAP;
            break;
    }
    
    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {
        if (wc_InitSha256(sha)) {
            printf("\nCrypto module error, wc_InitSha failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Update(sha, tc->m1, tc->msg_len)) {
            printf("\nCrypto module error, wc_ShaUpdate failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Update(sha, tc->m2, tc->msg_len)) {
            printf("\nCrypto module error, wc_ShaUpdate failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Update(sha, tc->m3, tc->msg_len)) {
            printf("\nCrypto module error, wc_ShaUpdate failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Final(sha, tc->md)) {
            printf("\nCrypto module error, wc_ShaFinal failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        printf("MCShaMsg1: %s\n", tc->m1);
        printf("MCShaMsg2: %s\n", tc->m2);
        printf("MCShaMsg3: %s\n", tc->m3);
    } else {
        if (wc_InitSha256(sha)) {
            printf("\nCrypto module error, wc_InitSha failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Update(sha, tc->msg, tc->msg_len)) {
            printf("\nCrypto module error, wc_ShaUpdate failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Final(sha, tc->md)) {
            printf("\nCrypto module error, wc_ShaFinal failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        printf("ShaMsg: %s\n", tc->msg);
    }
    
    printf("Digest size: %zu\n", tc->msg_len);
    printf(tc->md);
    printf("\n");

    wc_ShaFree(sha);

    return ACVP_SUCCESS;
}

#if 0
static ACVP_RESULT app_sha_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_HASH_TC    *tc;
    const WOLFSSL_EVP_MD    *md;
    WOLFSSL_EVP_MD_CTX          md_ctx;

    if (!test_case) {
        return ACVP_INVALID_ARG;
    }

    tc = test_case->tc.hash;

    switch (tc->cipher) {
    case ACVP_SHA1:
  md = wolfSSL_EVP_sha1();
  break;
    case ACVP_SHA224:
  md = wolfSSL_EVP_sha224();
  break;
    case ACVP_SHA256:
  md = wolfSSL_EVP_sha256();
  break;
    case ACVP_SHA384:
  md = wolfSSL_EVP_sha384();
  break;
    case ACVP_SHA512:
  md = wolfSSL_EVP_sha512();
  break;
    default:
  printf("Error: Unsupported hash algorithm requested by ACVP server\n");
  return ACVP_NO_CAP;
  break;
    }

    WOLFSSL_EVP_MD_CTX_init(&md_ctx);

    /* If Monte Carlo we need to be able to init and then update
     * one thousand times before we complete each iteration.
     */
    if (tc->test_type == ACVP_HASH_TEST_TYPE_MCT) {

        if (!wolfSSL_EVP_DigestInit_ex(&md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (!wolfSSL_EVP_DigestUpdate(&md_ctx, tc->m1, tc->msg_len)) {
      printf("\nCrypto module error, EVP_DigestUpdate failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  if (!wolfSSL_EVP_DigestUpdate(&md_ctx, tc->m2, tc->msg_len)) {
      printf("\nCrypto module error, EVP_DigestUpdate failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  if (!wolfSSL_EVP_DigestUpdate(&md_ctx, tc->m3, tc->msg_len)) {
      printf("\nCrypto module error, EVP_DigestUpdate failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  if (!wolfSSL_EVP_DigestFinal(&md_ctx, tc->md, &tc->md_len)) {
      printf("\nCrypto module error, EVP_DigestFinal failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }

   } else {
        if (!wolfSSL_EVP_DigestInit_ex(&md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }

  if (!wolfSSL_EVP_DigestUpdate(&md_ctx, tc->msg, tc->msg_len)) {
      printf("\nCrypto module error, EVP_DigestUpdate failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  if (!wolfSSL_EVP_DigestFinal(&md_ctx, tc->md, &tc->md_len)) {
      printf("\nCrypto module error, EVP_DigestFinal failed\n");
      return ACVP_CRYPTO_MODULE_FAIL;
        }
  wolfSSL_EVP_MD_CTX_cleanup(&md_ctx);
   }

    return ACVP_SUCCESS;
}
#endif
