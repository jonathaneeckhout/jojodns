#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <event2/dns.h>

#include "logging.h"
#include "client.h"

client_t *client_init(struct event_base *base, const char *name, const char *nameserver)
{
    client_t *client = (client_t *)malloc(sizeof(client_t));
    if (client == NULL)
    {
        log_error("Failed to allocate memory for client_t");
        goto exit_0;
    }

    if (name == NULL || strlen(name) == 0)
    {
        log_error("Client's name is NULL or empty. This is not allowed");
        goto exit_1;
    }

    client->name = strdup(name);
    if (!client->name)
    {
        log_error("Failed to allocate memory for name");
        goto exit_1;
    }

    if (nameserver != NULL && strlen(nameserver) > 0)
    {
        client->dns_base = evdns_base_new(base, 0x0);
    }
    else
    {
        log_info("Starting DNS client and resolving /etc/resolv.conf");
        client->dns_base = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
    }

    if (client->dns_base == NULL)
    {
        log_error("Failed to init client base");
        goto exit_2;
    }

    if (nameserver != NULL && strlen(nameserver) > 0)
    {
        if (evdns_base_nameserver_ip_add(client->dns_base, nameserver) != 0)
        {
            log_error("Failed to add nameserver=[%s]", nameserver);
            goto exit_3;
        }
    }

    log_info("Added client=[%s]", name);

    return client;

exit_3:
    evdns_base_free(client->dns_base, 0);
exit_2:
    free(client->name);
exit_1:
    free(client);
exit_0:
    return NULL;
}

void client_cleanup_content(client_t *client)
{
    if (client->dns_base != NULL)
    {
        evdns_base_free(client->dns_base, 0);
    }

    if (client->name != NULL)
    {
        free(client->name);
    }
}

void client_cleanup(client_t **client)
{
    if (client == NULL || *client == NULL)
    {
        return;
    }

    client_cleanup_content(*client);

    free(*client);
    *client = NULL;
}
