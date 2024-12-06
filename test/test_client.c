#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <event2/event.h>
#include <event2/dns.h>

#include "client.h"
#include "test_common.h"

void test_client_init_with_nameserver(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    assert_non_null(base);

    char *nameservers[] = {"8.8.8.8"};
    size_t nameserver_count = 1;

    client_t *client = client_init(base, nameservers, nameserver_count);

    assert_non_null(client);
    assert_non_null(client->dns_base);

    client_cleanup(&client);
    assert_null(client);

    event_base_free(base);
}

void test_client_init_without_nameserver(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    assert_non_null(base);

    client_t *client = client_init(base, NULL, 0);

    assert_non_null(client);
    assert_non_null(client->dns_base);

    client_cleanup(&client);
    assert_null(client);

    event_base_free(base);
}

void test_client_cleanup(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    assert_non_null(base);

    client_t *client = client_init(base, NULL, 0);
    client_cleanup(&client);
    assert_null(client);

    event_base_free(base);
}

void test_client_cleanup_null_client(UNUSED void **state)
{
    client_t *client = NULL;
    client_cleanup(&client);
    assert_null(client);
}
