#ifndef TEST_CLIENT_H
#define TEST_CLIENT_H

#include "test_common.h"

void test_client_init_with_nameserver(UNUSED void **state);
void test_client_init_without_nameserver(UNUSED void **state);
void test_client_cleanup(UNUSED void **state);
void test_client_cleanup_null_client(UNUSED void **state);

#endif // TEST_CLIENT_H