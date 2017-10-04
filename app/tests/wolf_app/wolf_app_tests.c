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
#include "app/tests/wolf_app/wolf_app_tests_sha.h"
#include "app/tests/wolf_app/wolf_app_tests_main.h"

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fail_create_test_session),
        cmocka_unit_test(test_fail_set_server),
        cmocka_unit_test(test_fail_set_vendor_info),
        cmocka_unit_test(test_fail_set_module_info),
        cmocka_unit_test(test_fail_set_path_segment),
        cmocka_unit_test(test_fail_set_cacerts),
        cmocka_unit_test(test_fail_set_certkey),
        cmocka_unit_test(test_fail_enable_hash_cap),
        cmocka_unit_test(test_fail_register),
        cmocka_unit_test(test_succeed_main_flow)
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
 
