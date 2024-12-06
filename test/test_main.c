#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "logging.h"
#include "test_common.h"
#include "test_client.h"
#include "test_server.h"

bool bind_failed = false;
bool calloc_failed = false;

int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    (void)sockfd;
    (void)addr;
    (void)addrlen;

    log_info("Mocked bind and %s", bind_failed ? "failing" : "succeeding");

    if (bind_failed)
    {
        return -1;
    }

    return 1;
}
void *__real_calloc(size_t nmemb, size_t size);
void *__wrap_calloc(size_t nmemb, size_t size)
{
    log_info("Mocked calloc and %s", calloc_failed ? "failing" : "succeeding");

    if (calloc_failed)
    {
        return NULL;
    }

    return __real_calloc(nmemb, size);
}

static int suite_setup(UNUSED void **state)
{
    logging_init("test", LOG_DEBUG);
    return 0;
}

static int suite_teardown(UNUSED void **state)
{
    logging_cleanup();
    return 0;
}

int test_setup(UNUSED void **state)
{
    bind_failed = false;
    calloc_failed = false;
    return 0;
}

int test_teardown(UNUSED void **state)
{
    bind_failed = false;
    calloc_failed = false;
    return 0;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_client_init_with_nameserver),
        cmocka_unit_test(test_client_init_without_nameserver),
        cmocka_unit_test(test_client_cleanup),
        cmocka_unit_test(test_client_cleanup_null_client),
        cmocka_unit_test(test_server_init),
        cmocka_unit_test(test_server_init_null_base),
        cmocka_unit_test(test_server_init_null_client),
        cmocka_unit_test(test_server_init_null_local),
        cmocka_unit_test_setup_teardown(test_server_calloc_fail, test_setup, test_teardown),
        cmocka_unit_test(test_server_cleanup),
    };
    return cmocka_run_group_tests(tests, suite_setup, suite_teardown);
}