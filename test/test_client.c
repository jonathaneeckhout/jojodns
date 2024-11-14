#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <parson.h>

#include "client.h"
#include "logging.h"

#define UNUSED __attribute__((unused))

static int suite_setup(UNUSED void **state)
{
    logging_init("test_client", LOG_DEBUG);
    return 0;
}

static int suite_teardown(UNUSED void **state)
{
    logging_cleanup();
    return 0;
}

static void test_client_init_with_nameserver(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    assert_non_null(base);

    JSON_Value *root_value = json_value_init_object();

    JSON_Array *nameservers = json_value_get_array(root_value);
    json_array_append_string(nameservers, "8.8.8.8");

    client_t *client = client_init(base, nameservers);

    assert_non_null(client);
    assert_non_null(client->dns_base);

    client_cleanup(&client);
    assert_null(client);

    json_value_free(root_value);
    event_base_free(base);
}

static void test_client_init_without_nameserver(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    assert_non_null(base);

    client_t *client = client_init(base, NULL);

    assert_non_null(client);
    assert_non_null(client->dns_base);

    client_cleanup(&client);
    assert_null(client);

    event_base_free(base);
}

static void test_client_cleanup(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    assert_non_null(base);

    client_t *client = client_init(base, NULL);
    client_cleanup(&client);
    assert_null(client);

    event_base_free(base);
}

static void test_client_cleanup_null_client(UNUSED void **state)
{
    client_t *client = NULL;
    client_cleanup(&client);
    assert_null(client);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_client_init_with_nameserver),
        cmocka_unit_test(test_client_init_without_nameserver),
        cmocka_unit_test(test_client_cleanup),
        cmocka_unit_test(test_client_cleanup_null_client),
    };
    return cmocka_run_group_tests(tests, suite_setup, suite_teardown);
}
