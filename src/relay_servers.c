#include <stdlib.h>
#include <hashmap.h>
#include <parson.h>
#include <string.h>

#include "logging.h"
#include "server.h"
#include "relay_forwarders.h"

#define UNUSED __attribute__((unused))

typedef struct _relay_server_t
{
    char *name;
    server_t *server;
} relay_server_t;

static uint64_t relay_servers_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const relay_server_t *enrty = item;
    return hashmap_sip(enrty->name, strlen(enrty->name), seed0, seed1);
}

static int relay_servers_compare(const void *a, const void *b, UNUSED void *udata)
{
    const relay_server_t *entry_a = a;
    const relay_server_t *entry_b = b;
    return strcmp(entry_a->name, entry_b->name);
}

static void relay_servers_free(void *item)
{

    relay_server_t *server = item;
    free(server->name);
    server_cleanup(&server->server);
}

static void add_config_server(struct event_base *base, JSON_Object *server_obj, struct hashmap *relay_servers, struct hashmap *relay_forwarders)
{
    const relay_forwarder_t *forwarder = NULL;
    server_t *server = NULL;

    const char *name = json_object_get_string(server_obj, "Alias");
    // Currently only support 1 client per server
    const char *forwarder_name = json_object_get_string(server_obj, "Forwarders");
    const char *interface = json_object_get_string(server_obj, "Interface");
    const char *address = json_object_get_string(server_obj, "Address");
    int port = json_object_get_number(server_obj, "Port");

    if (forwarder_name == NULL || strlen(forwarder_name) == 0)
    {
        log_error("Could not get a valid forwarder's name");
        return;
    }

    forwarder = hashmap_get(relay_forwarders, &(relay_forwarder_t){.name = (char *)forwarder_name});
    if (forwarder == NULL)
    {
        log_warning("Could not find client with name=[%s]", forwarder_name);
        return;
    }

    server = server_init(base, forwarder->client, interface, address, port);
    if (server == NULL)
    {
        log_error("Failed to init server=[%s]", name);
        return;
    }

    if (hashmap_set(relay_servers, &(relay_server_t){.name = strdup(name), .server = server}) != NULL)
    {
        log_error("failed to add server=[%s]", name);
        server_cleanup(&server);
    }
}

struct hashmap *relay_servers_init(struct event_base *base, JSON_Value *config_data, struct hashmap *relay_forwarders)
{
    JSON_Array *servers = NULL;
    size_t servers_count = 0;

    struct hashmap *relay_servers = hashmap_new(sizeof(relay_server_t), 0, 0, 0, relay_servers_hash, relay_servers_compare, relay_servers_free, NULL);
    if (relay_servers == NULL)
    {
        log_error("Failed to init new hashmap");
        goto exit_0;
    }

    servers = json_object_dotget_array(json_object(config_data), "Relay.Config");
    if (servers == NULL)
    {
        log_warning("No Relay Config config section found");
        goto exit_1;
    }

    servers_count = json_array_get_count(servers);
    for (size_t i = 0; i < servers_count; i++)
    {
        JSON_Object *server = json_array_get_object(servers, i);
        add_config_server(base, server, relay_servers, relay_forwarders);
    }

    return relay_servers;

exit_1:
    hashmap_clear(relay_servers, true);
    hashmap_free(relay_servers);

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