#ifndef TEST_SERVER_H
#define TEST_SERVER_H

#include "test_common.h"

void test_server_init(UNUSED void **state);
void test_server_init_null_base(UNUSED void **state);
void test_server_init_null_client(UNUSED void **state);
void test_server_init_null_local(UNUSED void **state);
void test_server_calloc_fail(UNUSED void **state);
void test_server_cleanup(UNUSED void **state);

#endif // TEST_SERVER_H