
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

static void add_config_client(struct event_base *base, JSON_Object *forwarder, struct hashmap *relay_forwarders)
{
    const char *name = json_object_get_string(forwarder, "Alias");
    const char *nameserver = json_object_get_string(forwarder, "DNSServer");

    client_t *client = client_init(base, nameserver);
    if (client == NULL)
    {
        log_error("Failed to init client=[%s]", name);
    }

    if (hashmap_set(relay_forwarders, &(relay_forwarder_t){.name = strdup(name), .client = client}) != NULL)
    {
        log_error("failed to add client=[%s]", name);
        client_cleanup(&client);
    }
}

struct hashmap *relay_forwarders_init(struct event_base *base, JSON_Value *config_data)
{
    JSON_Array *forwarders = NULL;
    size_t forwarders_count = 0;

    struct hashmap *relay_forwarders = hashmap_new(sizeof(relay_forwarder_t), 0, 0, 0, relay_forwarders_hash, relay_forwarders_compare, relay_forwarders_free, NULL);
    if (relay_forwarders == NULL)
    {
        log_error("Failed to init new hashmap");
        goto exit_0;
    }

    forwarders = json_object_dotget_array(json_object(config_data), "Relay.Forwarding");
    if (forwarders == NULL)
    {
        log_warning("No Relay Forwarding config section found");
        goto exit_1;
    }

    forwarders_count = json_array_get_count(forwarders);
    for (size_t i = 0; i < forwarders_count; i++)
    {
        JSON_Object *forwarder = json_array_get_object(forwarders, i);
        add_config_client(base, forwarder, relay_forwarders);
    }

    return relay_forwarders;

exit_1:
    hashmap_clear(relay_forwarders, true);
    hashmap_free(relay_forwarders);
exit_0:
    return NULL;
}

void relay_forwarders_cleanup(struct hashmap *relay_forwarders)
{
    if (relay_forwarders != NULL)
    {
        hashmap_clear(relay_forwarders, true);
        hashmap_free(relay_forwarders);
    }
}