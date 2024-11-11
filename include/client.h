#ifndef CLIENT
#define CLIENT

#include <stdbool.h>

#include <event2/dns.h>

typedef struct _client_t
{
    char *name;
    struct evdns_base *dns_base;
} client_t;

client_t *client_init(struct event_base *base, const char *name, const char *nameserver);
void client_cleanup(client_t **client);
void client_cleanup_content(client_t *client);

#endif