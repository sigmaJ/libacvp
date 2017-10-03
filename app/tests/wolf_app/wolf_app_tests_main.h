ACVP_RESULT __wrap_acvp_create_test_session(ACVP_CTX** ctxp, ACVP_RESULT (*progress)(char *), ACVP_LOG_LVL level);

ACVP_RESULT __wrap_acvp_set_server(ACVP_CTX* ctx, char* server, int port);

ACVP_RESULT __wrap_acvp_set_vendor_info(ACVP_CTX* ctx, char* org, char* site, char* name, char* email);

ACVP_RESULT __wrap_acvp_set_module_info(ACVP_CTX* ctx, char* name, char* type, char* ssl_version, char* fom);

ACVP_RESULT __wrap_acvp_set_path_segment(ACVP_CTX* ctx, char* path_segment);

ACVP_RESULT __wrap_acvp_set_cacerts(ACVP_CTX* ctx, char* ca_chain_file);

ACVP_RESULT __wrap_acvp_set_certkey(ACVP_CTX* ctx, char* cert_file, char* key_file);

ACVP_RESULT __wrap_acvp_enable_hash_cap(ACVP_CTX* ctx, ACVP_CIPHER cipher, ACVP_RESULT (*handler)(ACVP_TEST_CASE*));

ACVP_RESULT __wrap_acvp_register(ACVP_CTX* ctx);

void test_fail_create_test_session(void** state);

void test_fail_set_server(void** state);

void test_fail_set_vendor_info(void** state);
