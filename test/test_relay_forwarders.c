#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <event2/event.h>
#include <event2/dns.h>

#include "relay_forwarders.h"

#define UNUSED __attribute__((unused))

void test_relay_forwarders_init(UNUSED void **state)
{
    struct event_base *base = event_base_new();

    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    assert_non_null(relay_forwarders);

    relay_forwarders_cleanup(&relay_forwarders);
    event_base_free(base);
}

void test_relays_forwarders_init_null_base(UNUSED void **state)
{
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(NULL);

    assert_null(relay_forwarders);
}

void test_relays_forwarders_cleanup(UNUSED void **state)
{
    struct event_base *base = event_base_new();

    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    relay_forwarders_cleanup(&relay_forwarders);

    assert_null(relay_forwarders);

    event_base_free(base);
}

void test_relay_forwarders_add(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    relay_forwarder_data_t *data = relay_forwarder_data_init("test_alias", (char *[]){"8.8.8.8"}, 1);
    assert_non_null(data);

    bool result = relay_forwarders_add(relay_forwarders, data);
    assert_true(result);

    const relay_forwarder_t *forwarder = hashmap_get(relay_forwarders->forwarders, &(relay_forwarder_t){.data = data});
    assert_string_equal(forwarder->data->alias, data->alias);

    relay_forwarders_cleanup(&relay_forwarders);
    event_base_free(base);
}

void test_relay_forwarders_add_null_data(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    bool result = relay_forwarders_add(relay_forwarders, NULL);
    assert_false(result);

    relay_forwarders_cleanup(&relay_forwarders);
    event_base_free(base);
}

void test_relay_forwarders_add_duplicate(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    relay_forwarder_data_t *data = relay_forwarder_data_init("test_alias", (char *[]){"8.8.8.8"}, 1);
    assert_non_null(data);

    bool result = relay_forwarders_add(relay_forwarders, data);
    assert_true(result);

    relay_forwarder_data_t *duplicate_data = relay_forwarder_data_init("test_alias", (char *[]){"8.8.4.4"}, 1);
    assert_non_null(duplicate_data);

    result = relay_forwarders_add(relay_forwarders, duplicate_data);
    assert_false(result);

    relay_forwarder_data_cleanup(&duplicate_data);
    relay_forwarders_cleanup(&relay_forwarders);
    event_base_free(base);
}
void test_relay_forwarders_load_config(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    const char *config_json = "{\"Relay\":{\"Forwarding\":[{\"Alias\":\"test_alias\",\"DNSServers\":[\"8.8.8.8\"]}]}}";
    JSON_Value *config_data = json_parse_string(config_json);
    assert_non_null(config_data);

    bool result = relay_forwarders_load_config(relay_forwarders, config_data);
    assert_true(result);

    relay_forwarder_data_t *data = relay_forwarder_data_init("test_alias", (char *[]){"8.8.8.8"}, 1);
    const relay_forwarder_t *forwarder = hashmap_get(relay_forwarders->forwarders, &(relay_forwarder_t){.data = data});
    assert_string_equal(forwarder->data->alias, data->alias);

    relay_forwarder_data_cleanup(&data);
    relay_forwarders_cleanup(&relay_forwarders);
    json_value_free(config_data);
    event_base_free(base);
}

void test_relay_forwarders_load_config_no_forwarders(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    const char *config_json = "{\"Relay\":{}}";
    JSON_Value *config_data = json_parse_string(config_json);
    assert_non_null(config_data);

    bool result = relay_forwarders_load_config(relay_forwarders, config_data);
    assert_true(result);

    assert_int_equal(hashmap_count(relay_forwarders->forwarders), 0);

    relay_forwarders_cleanup(&relay_forwarders);
    json_value_free(config_data);
    event_base_free(base);
}

void test_relay_forwarders_load_config_no_alias(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    const char *config_json = "{\"Relay\":{\"Forwarding\":[{\"DNSServers\":[]}]}}";
    JSON_Value *config_data = json_parse_string(config_json);
    assert_non_null(config_data);

    bool result = relay_forwarders_load_config(relay_forwarders, config_data);
    assert_false(result);

    relay_forwarders_cleanup(&relay_forwarders);
    json_value_free(config_data);
    event_base_free(base);
}

void test_relay_forwarders_load_config_no_dnsservers(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    const char *config_json = "{\"Relay\":{\"Forwarding\":[{\"Alias\":\"test_alias\"}]}}";
    JSON_Value *config_data = json_parse_string(config_json);
    assert_non_null(config_data);

    bool result = relay_forwarders_load_config(relay_forwarders, config_data);
    assert_false(result);

    relay_forwarders_cleanup(&relay_forwarders);
    json_value_free(config_data);
    event_base_free(base);
}

void test_relay_forwarders_load_config_null_data(UNUSED void **state)
{
    struct event_base *base = event_base_new();
    relay_forwarders_t *relay_forwarders = relay_forwarders_init(base);

    bool result = relay_forwarders_load_config(relay_forwarders, NULL);
    assert_false(result);

    relay_forwarders_cleanup(&relay_forwarders);
    event_base_free(base);
}

