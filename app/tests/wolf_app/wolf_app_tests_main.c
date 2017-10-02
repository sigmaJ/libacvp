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


ACVP_RESULT __wrap_acvp_create_test_session(ACVP_CTX** ctxp, ACVP_RESULT (*progress)(char *), ACVP_LOG_LVL level) {
    return mock_type(ACVP_RESULT);
}

ACVP_RESULT __wrap_acvp_set_server(ACVP_CTX* ctx, char* server, int port) {
    return mock_type(ACVP_RESULT);
}

ACVP_RESULT __wrap_acvp_set_vendor_info(ACVP_CTX* ctx, char* org, char* site, char* name, char* email) {
    return mock_type(ACVP_RESULT);
}

ACVP_RESULT __wrap_acvp_set_module_info(ACVP_CTX* ctx, char* name, char* type, char* ssl_version, char* fom) {
    return mock_type(ACVP_RESULT);
}

ACVP_RESULT __wrap_acvp_set_path_segment(ACVP_CTX* ctx, char* path_segment) {
    return mock_type(ACVP_RESULT);
}

ACVP_RESULT __wrap_acvp_set_cacerts(ACVP_CTX* ctx, char* ca_chain_file) {
    return mock_type(ACVP_RESULT);
}

ACVP_RESULT __wrap_acvp_set_certkey(ACVP_CTX* ctx, char* cert_file, char* key_file) {
    return mock_type(ACVP_RESULT);
}

ACVP_RESULT __wrap_acvp_enable_hash_cap(ACVP_CTX* ctx, ACVP_CIPHER cipher, ACVP_RESULT (*handler)(ACVP_TEST_CASE*)) {
    return mock_type(ACVP_RESULT);
}

ACVP_RESULT __wrap_acvp_register(ACVP_CTX* ctx) {
    return mock_type(ACVP_RESULT);
}

static void test_fail_create_test_session(void** state) {
    will_return(__wrap_acvp_create_test_session, ACVP_SUCCESS + 1);
    
    ACVP_LOG_LVL level = ACVP_LOG_LVL_STATUS;
    ACVP_CTX *ctx;
    char ssl_version[10];
    
    ACVP_RESULT rv = wolf_acvp_register(&ctx, ssl_version, level);
    assert_int_not_equal(rv, ACVP_SUCCESS);
    
}

int main() {
    
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fail_create_test_session)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}
