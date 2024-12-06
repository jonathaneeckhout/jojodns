#ifndef TEST_RELAY_FORWARDERS_H
#define TEST_RELAY_FORWARDERS_H

#include "test_common.h"

void test_relay_forwarders_init(UNUSED void **state);
void test_relays_forwarders_init_null_base(UNUSED void **state);
void test_relays_forwarders_cleanup(UNUSED void **state);
void test_relay_forwarders_add(UNUSED void **state);
void test_relay_forwarders_add_null_data(UNUSED void **state);
void test_relay_forwarders_add_duplicate(UNUSED void **state);
void test_relay_forwarders_load_config(UNUSED void **state);
void test_relay_forwarders_load_config_no_forwarders(UNUSED void **state);
void test_relay_forwarders_load_config_no_alias(UNUSED void **state);
void test_relay_forwarders_load_config_no_dnsservers(UNUSED void **state);
void test_relay_forwarders_load_config_null_data(UNUSED void **state);

#endif // TEST_RELAY_FORWARDERS_H