#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "acvp.h"
#include "app/app_main_wolf.h"
#include "app/tests/wolf_app/wolf_app_tests_main.h"

#include <wolfssl/wolfcrypt/sha256.h>


void test_sha256_hash_mct(void** state){
    ACVP_HASH_TC *hash_tc = malloc(sizeof(ACVP_HASH_TC));
    hash_tc->cipher = ACVP_SHA256;
    hash_tc->tc_id = 0;
    hash_tc->test_type = ACVP_HASH_TEST_TYPE_MCT;
    hash_tc->msg = "message";
    hash_tc->m1 = "message1";
    hash_tc->m2 = "message2";
    hash_tc->m3 = "message3";
    // Assuming that m2 and m3 are the same length as m1
    hash_tc->msg_len = strlen(hash_tc->m1);
    hash_tc->md = malloc(SHA256_DIGEST_SIZE);
    
    ACVP_TEST_CASE *tc = malloc(sizeof(ACVP_TEST_CASE));
    tc->tc.hash = hash_tc;
    assert_int_equal(app_sha_handler(tc), ACVP_SUCCESS);
    
    char* expected = "7476E5CD17621C7856FE38305E954AC3F9D3090497957DCAB969735DD89D1F56";
    char* pos = expected;
    char bytes[32];
    for(int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sscanf(pos, "%2hhx", &bytes[i]);
        pos += 2;
    }
    assert_memory_equal(bytes, hash_tc->md, SHA256_DIGEST_SIZE);    
    
} 

void test_sha256_hash_kat(void** state){
    ACVP_HASH_TC *hash_tc = malloc(sizeof(ACVP_HASH_TC));
    hash_tc->cipher = ACVP_SHA256;
    hash_tc->tc_id = 0;
    // type is not MCT
    hash_tc->test_type = ACVP_HASH_TEST_TYPE_MCT+1;
    hash_tc->msg = "message";
    hash_tc->m1 = "message1";
    hash_tc->m2 = "message2";
    hash_tc->m3 = "message3";
    hash_tc->msg_len = strlen(hash_tc->msg);
    hash_tc->md = malloc(SHA256_DIGEST_SIZE);
    
    ACVP_TEST_CASE *tc = malloc(sizeof(ACVP_TEST_CASE));
    tc->tc.hash = hash_tc;
    assert_int_equal(app_sha_handler(tc), ACVP_SUCCESS);
    
    char* expected = "AB530A13E45914982B79F9B7E3FBA994CFD1F3FB22F71CEA1AFBF02B460C6D1D";
    char* pos = expected;
    char bytes[32];
    for(int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        sscanf(pos, "%2hhx", &bytes[i]);
        pos += 2;
    }
    assert_memory_equal(bytes, hash_tc->md, SHA256_DIGEST_SIZE);
    
}






