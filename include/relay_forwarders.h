#ifndef RELAY_FORWARDERS_H
#define RELAY_FORWARDERS_H

#include <hashmap.h>
#include <parson.h>
#include <event2/dns.h>


struct hashmap *relay_forwarders_init(struct event_base *base, JSON_Value *config_data);
void relay_forwarders_cleanup(struct hashmap *relay_forwarders);

#endif