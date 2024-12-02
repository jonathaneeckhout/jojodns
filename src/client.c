#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <event2/dns.h>

#include "logging.h"
#include "client.h"

client_t *client_init(struct event_base *base, char **nameservers, size_t nameserver_count)
{
    client_t *client = (client_t *)malloc(sizeof(client_t));
    if (client == NULL)
    {
        log_error("Failed to allocate memory for client_t");
        goto exit_0;
    }

    if (nameservers != NULL && nameserver_count > 0)
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
        goto exit_1;
    }

    log_debug("Created a new DNS client");

    if (nameservers != NULL && nameserver_count > 0)
    {
        for (size_t i = 0; i < nameserver_count; i++)
        {
            const char *nameserver = nameservers[i];

            if (evdns_base_nameserver_ip_add(client->dns_base, nameserver) != 0)
            {
                log_warning("Failed to add nameserver=[%s]", nameserver);
                continue;
            }

            log_debug("Added nameserver %s", nameserver);
        }
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
