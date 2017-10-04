#include "app_main_wolf.h"

/*
 * Read the operational parameters from the various environment
 * variables.
 */
void setup_session_parameters()
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

void print_usage(void)
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

ACVP_RESULT wolf_acvp_parseargs(int argc, char **argv, ACVP_LOG_LVL* level)
{
    *level = ACVP_LOG_LVL_STATUS;
    
     if (argc > 2) {
        print_usage();
        return 1;
    }

    argv++;
    argc--;
    while (argc >= 1) {
        if (strcmp(*argv, "-info") == 0) {
            *level = ACVP_LOG_LVL_INFO;
        }
        if (strcmp(*argv, "-status") == 0) {
            *level = ACVP_LOG_LVL_STATUS;
        }
        if (strcmp(*argv, "-warn") == 0) {
            *level = ACVP_LOG_LVL_WARN;
        }
        if (strcmp(*argv, "-error") == 0) {
            *level = ACVP_LOG_LVL_ERR;
        }
        if (strcmp(*argv, "-none") == 0) {
            *level = ACVP_LOG_LVL_NONE;
        }
        if (strcmp(*argv, "-verbose") == 0) {
            *level = ACVP_LOG_LVL_VERBOSE;
        }
        if (strcmp(*argv, "-help") == 0) {
            print_usage();
            return 1;
        }
    argv++;
    argc--;
    }
    
    return ACVP_SUCCESS;
}

ACVP_RESULT wolf_acvp_register(ACVP_CTX** ctxp, char* ssl_version, ACVP_LOG_LVL level)
{
#ifdef ACVP_NO_RUNTIME
    fips_selftest_fail = 0;
    fips_mode = 0;
    fips_algtest_init_nofips();
#endif

    // store result values
    ACVP_RESULT rv;
    
//  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    setup_session_parameters();

    /*
     * We begin the libacvp usage flow here.
     * First, we create a test session context.
     */
    rv = acvp_create_test_session(ctxp, &progress, level);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to create ACVP context\n");
        return rv;
    }
    
    ACVP_CTX* ctx = *ctxp;

    /*
     * Next we specify the ACVP server address
     */
    rv = acvp_set_server(ctx, server, port);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set server/port\n");
        return rv;
    }

    /*
     * Setup the vendor attributes
     */
    rv = acvp_set_vendor_info(ctx, "Cisco Systems", "www.cisco.com", "Barry Fussell", "bfussell@cisco.com");
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set vendor info\n");
        return rv;
    }

    /*
     * Setup the crypto module attributes
     */
    snprintf(ssl_version, 10, "%08x", (unsigned int)SSLeay());
    rv = acvp_set_module_info(ctx, "OpenSSL", "software", ssl_version, "FOM 6.2a");
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set module info\n");
        return rv;
    }

    /*
     * Set the path segment prefix if needed
     */
     if (strnlen(path_segment, 255) > 0) {
        rv = acvp_set_path_segment(ctx, path_segment);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set URI prefix\n");
            return rv;
        }
     }

    /*
     * Next we provide the CA certs to be used by libacvp
     * to verify the ACVP TLS certificate.
     */
    rv = acvp_set_cacerts(ctx, ca_chain_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set CA certs\n");
        return rv;
    }

    /*
     * Specify the certificate and private key the client should used
     * for TLS client auth.
     */
    rv = acvp_set_certkey(ctx, cert_file, key_file);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set TLS cert/key\n");
        return rv;
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
        return rv;
    }
    
    return ACVP_SUCCESS;
}

ACVP_RESULT wolf_acvp_run(ACVP_CTX* ctx)
{
    ACVP_RESULT rv;
    
    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = acvp_process_tests(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to process vectors (%d)\n", rv);
        return rv;
    }

    printf("\nTests complete, checking results...\n");
    rv = acvp_check_test_results(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Unable to retrieve test results (%d)\n", rv);
        return rv;
    }
    /*
     * Finally, we free the test session context and cleanup
     */
    rv = acvp_free_test_session(ctx);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to free ACVP context\n");
        return rv;
    }
    acvp_cleanup();

    // BN_free(expo); /* needed when passing bignum arg to rsa keygen from app */
    
    return ACVP_SUCCESS;
}

ACVP_RESULT app_sha_handler(ACVP_TEST_CASE *test_case)
{
    ACVP_HASH_TC    *tc;
    Sha256 sha;

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
        if (wc_InitSha256(&sha)) {
            printf("\nCrypto module error, wc_InitSha failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Update(&sha, tc->m1, tc->msg_len)) {
            printf("\nCrypto module error, wc_ShaUpdate failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Update(&sha, tc->m2, tc->msg_len)) {
            printf("\nCrypto module error, wc_ShaUpdate failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Update(&sha, tc->m3, tc->msg_len)) {
            printf("\nCrypto module error, wc_ShaUpdate failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Final(&sha, tc->md)) {
            printf("\nCrypto module error, wc_ShaFinal failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
    } else {
        if (wc_InitSha256(&sha)) {
            printf("\nCrypto module error, wc_InitSha failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Update(&sha, tc->msg, tc->msg_len)) {
            printf("\nCrypto module error, wc_ShaUpdate failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
        if (wc_Sha256Final(&sha, tc->md)) {
            printf("\nCrypto module error, wc_ShaFinal failed\n");
            return ACVP_CRYPTO_MODULE_FAIL;
        }
    }
    
    tc->md_len = SHA256_DIGEST_SIZE;

    wc_Sha256Free(&sha);

    return ACVP_SUCCESS;
}
