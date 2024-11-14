#ifndef RELAY_FORWARDERS_H
#define RELAY_FORWARDERS_H

#include <hashmap.h>
#include <parson.h>
#include <event2/dns.h>

#include "client.h"

typedef struct _relay_forwarder_t
{
    char *name;
    client_t *client;
} relay_forwarder_t;

typedef struct _relay_forwarders_t
{
    struct event_base *base;
    struct hashmap *forwarders;
} relay_forwarders_t;

relay_forwarders_t *relay_forwarders_init(struct event_base *base, JSON_Value *config_data);
void relay_forwarders_cleanup(relay_forwarders_t **relay_forwarders);
bool relay_forwarders_add(relay_forwarders_t *relay_forwarders, const char *alias, JSON_Array *nameservers);

#endif