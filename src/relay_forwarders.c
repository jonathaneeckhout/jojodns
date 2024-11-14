
#include <stdlib.h>
#include <hashmap.h>
#include <parson.h>
#include <string.h>

#include "logging.h"
#include "relay_forwarders.h"

#define UNUSED __attribute__((unused))

static uint64_t relay_forwarders_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const relay_forwarder_t *enrty = item;
    return hashmap_sip(enrty->name, strlen(enrty->name), seed0, seed1);
}

static int relay_forwarders_compare(const void *a, const void *b, UNUSED void *udata)
{
    const relay_forwarder_t *entry_a = a;
    const relay_forwarder_t *entry_b = b;
    return strcmp(entry_a->name, entry_b->name);
}

static void relay_forwarders_free(void *item)
{
    relay_forwarder_t *forwarder = item;
    free(forwarder->name);
    client_cleanup(&forwarder->client);
}

bool relay_forwarders_add(relay_forwarders_t *relay_forwarders, const char *alias, JSON_Array *nameservers)
{
    client_t *client = client_init(relay_forwarders->base, nameservers);
    if (client == NULL)
    {
        log_error("Failed to init forwarder=[%s]", alias);
        goto exit_0;
    }

    if (hashmap_set(relay_forwarders->forwarders, &(relay_forwarder_t){.name = strdup(alias), .client = client}) != NULL)
    {
        log_error("failed to add client=[%s]", alias);
        goto exit_1;
    }

    log_info("Added relay forwarder=[%s]", alias);

    return true;

exit_1:
    client_cleanup(&client);
exit_0:
    return false;
}

static void add_config_forwarder(relay_forwarders_t *relay_forwarders, JSON_Object *forwarder)
{
    const char *alias = json_object_get_string(forwarder, "Alias");
    JSON_Array *nameservers = json_object_get_array(forwarder, "DNSServers");

    relay_forwarders_add(relay_forwarders, alias, nameservers);
}

relay_forwarders_t *relay_forwarders_init(struct event_base *base, JSON_Value *config_data)
{
    relay_forwarders_t *relay_forwarders = NULL;

    if (base == NULL)
    {
        log_error("Base is NULL");
        goto exit_0;
    }

    relay_forwarders = (relay_forwarders_t *)calloc(1, sizeof(relay_forwarders_t));
    if (relay_forwarders == NULL)
    {
        log_error("Failed to allocate memory for relay_forwarders_t");
        goto exit_0;
    }

    relay_forwarders->base = base;

    relay_forwarders->forwarders = hashmap_new(sizeof(relay_forwarder_t), 0, 0, 0, relay_forwarders_hash, relay_forwarders_compare, relay_forwarders_free, NULL);
    if (relay_forwarders->forwarders == NULL)
    {
        log_error("Failed to init new forwarders hashmap");
        goto exit_1;
    }

    if (config_data != NULL)
    {
        JSON_Array *forwarders = json_object_dotget_array(json_object(config_data), "Relay.Forwarding");
        if (forwarders != NULL)
        {
            size_t forwarders_count = json_array_get_count(forwarders);
            for (size_t i = 0; i < forwarders_count; i++)
            {
                JSON_Object *forwarder = json_array_get_object(forwarders, i);
                add_config_forwarder(relay_forwarders, forwarder);
            }
        }
    }

    return relay_forwarders;

exit_1:
    free(relay_forwarders);
exit_0:
    return NULL;
}

void relay_forwarders_cleanup(relay_forwarders_t **relay_forwarders)
{
    if ((*relay_forwarders)->forwarders != NULL)
    {
        hashmap_clear((*relay_forwarders)->forwarders, true);
        hashmap_free((*relay_forwarders)->forwarders);
    }

    free(*relay_forwarders);
    relay_forwarders = NULL;
}