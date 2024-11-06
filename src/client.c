#include <stdlib.h>
#include <stdbool.h>

#include "logging.h"
#include "client.h"

client_t *client_init(struct event_base *base)
{
    client_t *client = (client_t *)calloc(1, sizeof(client_t));
    if (client == NULL)
    {
        log_error("Failed to allocate memory for client_t");
        goto exit_0;
    }

    client->dns_base = evdns_base_new(base, 1);
    if (client->dns_base == NULL)
    {
        log_error("Failed to init client base");
        goto exit_1;
    }

    return client;

exit_1:
    free(client);
exit_0:
    return NULL;
}

void client_cleanup(client_t **client)
{
    if (client == NULL || *client == NULL)
    {
        return;
    }

    if ((*client)->dns_base != NULL)
    {
        evdns_base_free((*client)->dns_base, 0);
    }

    free(*client);
    *client = NULL;
}
