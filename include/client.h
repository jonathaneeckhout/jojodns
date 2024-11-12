#ifndef CLIENT
#define CLIENT

#include <stdbool.h>

#include <event2/dns.h>

typedef struct _client_t
{
    struct evdns_base *dns_base;
} client_t;

client_t *client_init(struct event_base *base, const char *nameserver);
void client_cleanup(client_t **client);

#endif