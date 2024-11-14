#include <stdlib.h>
#include <hashmap.h>
#include <parson.h>
#include <string.h>

#include "logging.h"
#include "server.h"
#include "relay_forwarders.h"
#include "relay_servers.h"

#define UNUSED __attribute__((unused))

static uint64_t relay_servers_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const relay_server_t *enrty = item;
    return hashmap_sip(enrty->alias, strlen(enrty->alias), seed0, seed1);
}

static int relay_servers_compare(const void *a, const void *b, UNUSED void *udata)
{
    const relay_server_t *entry_a = a;
    const relay_server_t *entry_b = b;
    return strcmp(entry_a->alias, entry_b->alias);
}

static void relay_servers_free(void *item)
{
    relay_server_t *server = item;
    free(server->alias);
    free(server->interface);
    free(server->address);
    server_cleanup(&server->server);
}

static void add_config_server(relay_servers_t *relay_servers, JSON_Object *server_obj)
{
    const relay_forwarder_t *forwarder = NULL;
    server_t *server = NULL;

    const char *alias = json_object_get_string(server_obj, "Alias");
    // Currently only support 1 client per server
    const char *forwarder_name = json_object_get_string(server_obj, "Forwarders");
    const char *interface = json_object_get_string(server_obj, "Interface");
    const char *address = json_object_get_string(server_obj, "Address");
    int port = json_object_get_number(server_obj, "Port");
    size_t cache_size = json_object_get_number(server_obj, "CacheSize");
    int cache_min_ttl = json_object_get_number(server_obj, "CacheMinTTL");
    int cache_max_ttl = json_object_get_number(server_obj, "CacheMaxTTL");

    if (forwarder_name == NULL || strlen(forwarder_name) == 0)
    {
        log_error("Could not get a valid forwarder's name");
        return;
    }

    forwarder = hashmap_get(relay_servers->relay_forwarders->forwarders, &(relay_forwarder_t){.name = (char *)forwarder_name});
    if (forwarder == NULL)
    {
        log_warning("Could not find client with name=[%s]", forwarder_name);
        return;
    }

    server = server_init(relay_servers->base, forwarder->client, interface, address, port);
    if (server == NULL)
    {
        log_error("Failed to init server=[%s]", alias);
        return;
    }

    if (cache_size > 0)
    {
        server->cache->size = cache_size;
    }

    if (cache_min_ttl > 0)
    {
        server->cache->min_ttl = cache_min_ttl;
    }

    if (cache_max_ttl > 0)
    {
        server->cache->max_ttl = cache_max_ttl;
    }

    if (hashmap_set(relay_servers->servers, &(relay_server_t){.alias = strdup(alias), .server = server}) != NULL)
    {
        log_error("failed to add server=[%s]", alias);
        server_cleanup(&server);
    }
}

relay_servers_t *relay_servers_init(struct event_base *base, relay_forwarders_t *relay_forwarders, JSON_Value *config_data)
{
    JSON_Array *servers = NULL;
    size_t servers_count = 0;
    relay_servers_t *relay_servers = NULL;

    if (base == NULL || relay_forwarders == NULL)
    {
        log_error("Invalid input");
        goto exit_0;
    }

    relay_servers = (relay_servers_t *)calloc(1, sizeof(relay_servers_t));
    if (relay_servers == NULL)
    {
        log_error("Failed to allocate memory for relay_servers_t");
        goto exit_0;
    }

    relay_servers->base = base;
    relay_servers->relay_forwarders = relay_forwarders;

    relay_servers->servers = hashmap_new(sizeof(relay_server_t), 0, 0, 0, relay_servers_hash, relay_servers_compare, relay_servers_free, NULL);
    if (relay_servers->servers == NULL)
    {
        log_error("Failed to init new hashmap");
        goto exit_1;
    }

    servers = json_object_dotget_array(json_object(config_data), "Relay.Config");
    if (servers == NULL)
    {
        log_warning("No Relay Config config section found");
        goto exit_2;
    }

    servers_count = json_array_get_count(servers);
    for (size_t i = 0; i < servers_count; i++)
    {
        JSON_Object *server = json_array_get_object(servers, i);
        add_config_server(relay_servers, server);
    }

    return relay_servers;

exit_2:
    hashmap_clear(relay_servers->servers, true);
    hashmap_free(relay_servers->servers);
exit_1:
    free(relay_servers);
exit_0:
    return NULL;
}

void relay_servers_cleanup(relay_servers_t **relay_servers)
{
    if ((*relay_servers)->servers != NULL)
    {
        hashmap_clear((*relay_servers)->servers, true);
        hashmap_free((*relay_servers)->servers);
    }

    free(*relay_servers);
    relay_servers = NULL;
}