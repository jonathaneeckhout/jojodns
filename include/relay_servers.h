#ifndef RELAY_SERVERS_H
#define RELAY_SERVERS_H

#include <hashmap.h>
#include <parson.h>
#include <event2/dns.h>

struct hashmap *relay_servers_init(struct event_base *base, JSON_Value *config_data, struct hashmap *relay_forwarders);
void relay_servers_cleanup(struct hashmap *relay_forwarders);

#endif