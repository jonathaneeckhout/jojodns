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
    return hashmap_sip(enrty->data->alias, strlen(enrty->data->alias), seed0, seed1);
}

static int relay_servers_compare(const void *a, const void *b, UNUSED void *udata)
{
    const relay_server_t *entry_a = a;
    const relay_server_t *entry_b = b;
    return strcmp(entry_a->data->alias, entry_b->data->alias);
}

static void relay_servers_free(void *item)
{
    relay_server_t *server = item;
    relay_server_data_cleanup(&server->data);
    server_cleanup(&server->server);
}

bool relay_server_add(relay_servers_t *relay_servers, relay_server_data_t *data)
{

    server_t *server = NULL;
    const relay_forwarder_t *forwarder = NULL;
    relay_forwarder_data_t relay_data;
    relay_server_data_t *copy_of_data = NULL;

    if (data->alias == NULL || strlen(data->alias) == 0)
    {
        log_warning("Failed to add relay server, invalid alias");
        goto exit_0;
    }

    if (hashmap_get(relay_servers->servers, &(relay_server_t){.data = data}) != NULL)
    {
        log_warning("Relay server=[%s] already exists", data->alias);
        goto exit_0;
    }

    if (data->forwarder_name == NULL || strlen(data->forwarder_name) == 0)
    {
        log_warning("Failed to add relay server, invalid forwarder name");
        goto exit_0;
    }

    memset(&relay_data, 0, sizeof(relay_forwarder_data_t));
    relay_data.alias = data->forwarder_name;

    forwarder = hashmap_get(relay_servers->relay_forwarders->forwarders, &(relay_forwarder_t){.data = &relay_data});
    if (forwarder == NULL)
    {
        log_warning("Could not find client with name=[%s]", data->forwarder_name);
        goto exit_0;
    }

    server = server_init(relay_servers->base, forwarder->client, data->interface, data->address, data->port);
    if (server == NULL)
    {
        log_error("Failed to init server=[%s]", data->alias);
        goto exit_0;
    }

    if (data->cache_size > 0)
    {
        server->cache->size = data->cache_size * 1000;
    }
    else
    {
        data->cache_size = server->cache->size / 1000;
    }

    if (data->cache_min_ttl > 0)
    {
        server->cache->min_ttl = data->cache_min_ttl;
    }
    else
    {
        data->cache_min_ttl = server->cache->min_ttl;
    }

    if (data->cache_max_ttl > 0)
    {
        server->cache->max_ttl = data->cache_max_ttl;
    }
    else
    {
        data->cache_max_ttl = server->cache->max_ttl;
    }

    copy_of_data = relay_server_data_copy(data);
    if (copy_of_data == NULL)
    {
        log_error("Failed to copy server data");
        goto exit_1;
    }

    if (hashmap_set(relay_servers->servers, &(relay_server_t){.data = copy_of_data, .server = server}) != NULL)
    {
        log_error("failed to add server=[%s]", data->alias);
        goto exit_2;
    }

    return true;

exit_2:
    relay_server_data_cleanup(&copy_of_data);
exit_1:
    server_cleanup(&server);
exit_0:
    return false;
}

static void add_config_server(relay_servers_t *relay_servers, JSON_Object *server_obj)
{

    relay_server_data_t *data = NULL;

    const char *alias = json_object_get_string(server_obj, "Alias");
    // Currently only support 1 client per server
    const char *forwarder_name = json_object_get_string(server_obj, "Forwarders");
    const char *interface = json_object_get_string(server_obj, "Interface");
    const char *address = json_object_get_string(server_obj, "Address");
    int port = json_object_get_number(server_obj, "Port");
    size_t cache_size = json_object_get_number(server_obj, "CacheSize");
    int cache_min_ttl = json_object_get_number(server_obj, "CacheMinTTL");
    int cache_max_ttl = json_object_get_number(server_obj, "CacheMaxTTL");

    data = relay_server_data_init(true, alias, forwarder_name, interface, address, port, cache_size, cache_min_ttl, cache_max_ttl);
    if (data == NULL)
    {
        log_error("Failed to init relay server data");
        return;
    }

    relay_server_add(relay_servers, data);

    relay_server_data_cleanup(&data);
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

relay_server_data_t *relay_server_data_init(bool enable, const char *alias, const char *forwarder_name, const char *interface, const char *address, int port, size_t cache_size, int cache_min_ttl, int cache_max_ttl)
{
    relay_server_data_t *relay_server_data = (relay_server_data_t *)calloc(1, sizeof(relay_server_data_t));
    if (relay_server_data == NULL)
    {
        log_error("Failed to allocate memory for relay_server_data_t");
        goto exit_0;
    }

    relay_server_data->enable = enable;
    relay_server_data->alias = strdup(alias);
    relay_server_data->forwarder_name = strdup(forwarder_name);
    relay_server_data->interface = strdup(interface);
    relay_server_data->address = strdup(address);
    relay_server_data->port = port;
    relay_server_data->cache_size = cache_size;
    relay_server_data->cache_min_ttl = cache_min_ttl;
    relay_server_data->cache_max_ttl = cache_max_ttl;

    return relay_server_data;

exit_0:
    return NULL;
}

void relay_server_data_cleanup(relay_server_data_t **relay_server_data)
{
    free((*relay_server_data)->alias);
    free((*relay_server_data)->forwarder_name);
    free((*relay_server_data)->interface);
    free((*relay_server_data)->address);

    free(*relay_server_data);
    relay_server_data = NULL;
}

relay_server_data_t *relay_server_data_copy(relay_server_data_t *data)
{
    return relay_server_data_init(data->enable, data->alias, data->forwarder_name, data->interface, data->address, data->port, data->cache_size, data->cache_min_ttl, data->cache_max_ttl);
}