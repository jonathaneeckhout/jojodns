#ifndef SERVER
#define SERVER

#include <stdbool.h>

#include "client.h"
#include "local.h"
#include "cache.h"

typedef struct _server_t
{
    struct evdns_server_port *dns_server;
    client_t *client;
    local_t *local;
    cache_t *cache;
} server_t;

server_t *server_init(struct event_base *base, client_t *client, const char *interface, const char *address, int port);
void server_cleanup(server_t **server);

#endif