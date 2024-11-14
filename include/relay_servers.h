#ifndef RELAY_SERVERS_H
#define RELAY_SERVERS_H

#include <hashmap.h>
#include <parson.h>
#include <event2/dns.h>

#include "server.h"
#include "relay_forwarders.h"

typedef struct _relay_server_t
{
    bool enable;
    char *alias;
    char *interface;
    char *address;
    int port;
    size_t cache_size;
    int cache_min_ttl;
    int cache_max_ttl;
    server_t *server;
} relay_server_t;

typedef struct _relay_servers_t
{
    struct event_base *base;
    relay_forwarders_t *relay_forwarders;
    struct hashmap *servers;
} relay_servers_t;

relay_servers_t *relay_servers_init(struct event_base *base, relay_forwarders_t *relay_forwarders, JSON_Value *config_data);
void relay_servers_cleanup(relay_servers_t **relay_servers);

#endif