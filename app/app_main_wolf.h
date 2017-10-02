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


void setup_session_parameters();
ACVP_RESULT progress(char *msg);
void print_usage(void);

ACVP_RESULT wolf_acvp_parseargs(int argc, char **argv, ACVP_LOG_LVL* level);
ACVP_RESULT wolf_acvp_register(ACVP_CTX** ctxp, char* ssl_version, ACVP_LOG_LVL level);
ACVP_RESULT wolf_acvp_run(ACVP_CTX* ctx);

ACVP_RESULT app_sha_handler(ACVP_TEST_CASE *test_case);
