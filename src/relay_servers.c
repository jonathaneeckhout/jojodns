#include <hashmap.h>
#include <parson.h>
#include <string.h>

#include "logging.h"
#include "server.h"

#define UNUSED __attribute__((unused))

static uint64_t relay_servers_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const server_t *enrty = item;
    return hashmap_sip(enrty->name, strlen(enrty->name), seed0, seed1);
}

static int relay_servers_compare(const void *a, const void *b, UNUSED void *udata)
{
    const server_t *entry_a = a;
    const server_t *entry_b = b;
    return strcmp(entry_a->name, entry_b->name);
}

static void relay_servers_free(void *item)
{
    server_cleanup_content((server_t *)item);
}

struct hashmap *relay_servers_init(struct event_base *base, JSON_Value *config_data)
{
    (void)base;
    (void)config_data;

    struct hashmap *relay_servers = hashmap_new(sizeof(server_t), 0, 0, 0, relay_servers_hash, relay_servers_compare, relay_servers_free, NULL);
    if (relay_servers == NULL)
    {
        log_error("Failed to init new hashmap");
        goto exit_0;
    }

    return relay_servers;

exit_0:
    return NULL;
}

void relay_servers_cleanup(struct hashmap *relay_servers)
{
    if (relay_servers != NULL)
    {
        hashmap_clear(relay_servers, true);
        hashmap_free(relay_servers);
    }
}