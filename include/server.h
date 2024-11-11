#ifndef SERVER
#define SERVER

#include <stdbool.h>

#include "client.h"
#include "cache.h"

typedef struct _server_t
{
    char *name;
    struct evdns_server_port *dns_server;
    client_t *client;
    cache_t *cache;
} server_t;

server_t *server_init(struct event_base *base, const char *name, client_t *client, const char *interface, const char *address, int port);
void server_cleanup(server_t **server);
void server_cleanup_content(server_t *server);

#endif