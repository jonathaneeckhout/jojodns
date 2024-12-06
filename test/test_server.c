#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <event2/event.h>
#include <event2/dns.h>

#include "server.h"
#include "client.h"
#include "test_common.h"

void test_server_init(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    char *nameservers[] = {"8.8.8.8"};
    client_t *client = client_init(base, nameservers, 1);
    local_host_t *hosts[] = {NULL};
    local_t *local = local_init(hosts, 0);

    server_t *server = server_init(base, client, local, NULL, "127.0.0.1", 53);

    assert_non_null(server);

    server_cleanup(&server);
    client_cleanup(&client);
    local_cleanup(&local);
    event_base_free(base);
}

void test_server_init_null_base(UNUSED void **state)
{
    client_t *client = NULL;
    local_t *local = NULL;

    server_t *server = server_init(NULL, client, local, NULL, "127.0.0.1", 53);

    assert_null(server);
}

void test_server_init_null_client(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    local_host_t *hosts[] = {NULL};
    local_t *local = local_init(hosts, 0);

    server_t *server = server_init(base, NULL, local, NULL, "127.0.0.1", 53);

    assert_null(server);

    local_cleanup(&local);
    event_base_free(base);
}

void test_server_init_null_local(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    char *nameservers[] = {"8.8.8.8"};
    client_t *client = client_init(base, nameservers, 1);

    server_t *server = server_init(base, client, NULL, NULL, "127.0.0.1", 53);

    assert_null(server);
    client_cleanup(&client);
    event_base_free(base);
}

void test_server_calloc_fail(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    char *nameservers[] = {"8.8.8.8"};
    client_t *client = client_init(base, nameservers, 1);
    local_host_t *hosts[] = {NULL};
    local_t *local = local_init(hosts, 0);

    calloc_failed = true;

    server_t *server = server_init(base, client, local, NULL, "127.0.0.1", 53);

    assert_null(server);

    client_cleanup(&client);
    local_cleanup(&local);
    event_base_free(base);
}

void test_server_cleanup(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    char *nameservers[] = {"8.8.8.8"};
    client_t *client = client_init(base, nameservers, 1);
    local_host_t *hosts[] = {NULL};
    local_t *local = local_init(hosts, 0);

    server_t *server = server_init(base, client, local, NULL, "127.0.0.1", 53);

    assert_non_null(server);

    server_cleanup(&server);

    assert_null(server);

    client_cleanup(&client);
    local_cleanup(&local);
    event_base_free(base);
}