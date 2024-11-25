#ifndef RELAY_SERVERS_H
#define RELAY_SERVERS_H

#include <hashmap.h>
#include <parson.h>
#include <event2/dns.h>

#include "server.h"
#include "relay_forwarders.h"

typedef struct _relay_server_data_t
{
    bool enable;
    char *alias;
    char *interface;
    char *address;
    int port;
    size_t cache_size;
    int cache_min_ttl;
    int cache_max_ttl;
    // Currently only support 1 forwarder per relay server
    char *forwarder_name;
} relay_server_data_t;

typedef struct _relay_server_t
{
    relay_server_data_t *data;
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

relay_server_data_t *relay_server_data_init(bool enable, const char *alias, const char *interface, const char *address, int port, size_t cache_size, int cache_min_ttl, int cache_max_ttl, const char *forwarder_name);
void relay_server_data_cleanup(relay_server_data_t **relay_server_data);

#endif