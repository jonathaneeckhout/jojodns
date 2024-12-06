
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
    return hashmap_sip(enrty->data->alias, strlen(enrty->data->alias), seed0, seed1);
}

static int relay_forwarders_compare(const void *a, const void *b, UNUSED void *udata)
{
    const relay_forwarder_t *entry_a = a;
    const relay_forwarder_t *entry_b = b;
    return strcmp(entry_a->data->alias, entry_b->data->alias);
}

static void relay_forwarders_free(void *item)
{
    relay_forwarder_t *forwarder = item;
    relay_forwarder_data_cleanup(&forwarder->data);
    client_cleanup(&forwarder->client);
}

bool relay_forwarders_add(relay_forwarders_t *relay_forwarders, relay_forwarder_data_t *data)
{
    client_t *client = NULL;

    if (relay_forwarders == NULL || data == NULL)
    {
        log_error("Invalid arguments: relay_forwarders or data is NULL");
        goto exit_0;
    }

    if (data->alias == NULL || strlen(data->alias) == 0)
    {
        log_warning("Failed to add forwarder, invalid alias");
        goto exit_0;
    }

    if (hashmap_get(relay_forwarders->forwarders, &(relay_forwarder_t){.data = data}) != NULL)
    {
        log_warning("Relay forwarder=[%s] already exists", data->alias);
        goto exit_0;
    }

    client = client_init(relay_forwarders->base, data->nameservers, data->nameserver_count);
    if (client == NULL)
    {
        log_error("Failed to init forwarder=[%s]", data->alias);
        goto exit_0;
    }

    if (hashmap_set(relay_forwarders->forwarders, &(relay_forwarder_t){.data = data, .client = client}) != NULL)
    {
        log_error("failed to add client=[%s]", data->alias);
        goto exit_1;
    }

    log_info("Added relay forwarder=[%s]", data->alias);

    return true;

exit_1:
    relay_forwarder_data_cleanup(&data);
    client_cleanup(&client);
exit_0:
    return false;
}

static bool add_config_forwarder(relay_forwarders_t *relay_forwarders, JSON_Object *forwarder)
{
    const char *alias = NULL;
    JSON_Array *json_nameservers = NULL;
    size_t json_nameservers_count = 0;
    const char **nameservers = NULL;
    size_t i = 0;
    relay_forwarder_data_t *data = NULL;

    if (relay_forwarders == NULL || forwarder == NULL)
    {
        log_error("Invalid arguments: relay_forwarders or forwarder is NULL");
        return false;
    }

    alias = json_object_get_string(forwarder, "Alias");
    if (alias == NULL || strlen(alias) == 0)
    {
        log_warning("Skipping forwarder: Invalid or missing alias");
        return false;
    }

    json_nameservers = json_object_get_array(forwarder, "DNSServers");
    if (json_nameservers == NULL)
    {
        log_warning("Skipping forwarder: Invalid or missing DNSServers");
        return false;
    }

    json_nameservers_count = json_array_get_count(json_nameservers);
    if (json_nameservers_count > 0)
    {
        nameservers = calloc(json_nameservers_count, sizeof(char *));
        if (nameservers == NULL)
        {
            log_error("Failed to allocate memory for nameservers");
            return false;
        }

        for (i = 0; i < json_nameservers_count; i++)
        {
            const char *nameserver = json_array_get_string(json_nameservers, i);
            if (nameserver == NULL || strlen(nameserver) == 0)
            {
                log_warning("Skipping invalid nameserver at index %zu", i);
                continue;
            }
            nameservers[i] = nameserver;
        }

        data = relay_forwarder_data_init(alias, (char **)nameservers, json_nameservers_count);
        if (data == NULL)
        {
            log_error("Failed to initialize relay forwarder data for alias [%s]", alias);
            free(nameservers);
            return false;
        }

        if (!relay_forwarders_add(relay_forwarders, data))
        {
            log_error("Failed to add forwarder for alias [%s]", alias);
            relay_forwarder_data_cleanup(&data);
            free(nameservers);
            return false;
        }

        free(nameservers);
    }

    return true;
}

bool relay_forwarders_load_config(relay_forwarders_t *relay_forwarders, JSON_Value *config_data)
{
    JSON_Array *forwarders = NULL;
    size_t forwarders_count = 0;

    if (relay_forwarders == NULL || config_data == NULL)
    {
        log_error("Invalid arguments: relay_forwarders or config_data is NULL");
        return false;
    }

    forwarders = json_object_dotget_array(json_object(config_data), "Relay.Forwarding");
    if (forwarders == NULL)
    {
        log_warning("No forwarders found in config");
        return true;
    }

    forwarders_count = json_array_get_count(forwarders);
    for (size_t i = 0; i < forwarders_count; i++)
    {
        JSON_Object *forwarder = json_array_get_object(forwarders, i);
        if (!add_config_forwarder(relay_forwarders, forwarder))
        {
            log_error("Failed to add forwarder at index %zu", i);
            return false;
        }
    }

    return true;
}

relay_forwarders_t *relay_forwarders_init(struct event_base *base)
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
    *relay_forwarders = NULL;
}

relay_forwarder_data_t *relay_forwarder_data_init(const char *alias, char **nameservers, size_t nameserver_count)
{
    size_t nameserver_count_copy = 0;
    relay_forwarder_data_t *relay_forwarder_data = (relay_forwarder_data_t *)calloc(1, sizeof(relay_forwarder_data_t));
    if (relay_forwarder_data == NULL)
    {
        log_error("Failed to allocate memory for relay_forwarder_data_t");
        goto exit_0;
    }

    relay_forwarder_data->alias = strdup(alias);
    if (relay_forwarder_data->alias == NULL)
    {
        log_error("Failed to allocate memory for alias");
        goto exit_1;
    }

    relay_forwarder_data->nameservers = (char **)calloc(nameserver_count, sizeof(char *));
    if (relay_forwarder_data->nameservers == NULL)
    {
        log_error("Failed to allocate memory for nameservers array");
        goto exit_2;
    }

    for (size_t i = 0; i < nameserver_count; i++)
    {
        relay_forwarder_data->nameservers[i] = strdup(nameservers[i]);
        if (relay_forwarder_data->nameservers[i] == NULL)
        {
            log_error("Failed to allocate memory for nameserver[%zu]", i);
            nameserver_count_copy = i;
            goto exit_3;
        }
    }

    relay_forwarder_data->nameserver_count = nameserver_count;
    return relay_forwarder_data;

exit_3:
    for (size_t i = 0; i < nameserver_count_copy; i++)
    {
        free(relay_forwarder_data->nameservers[i]);
    }
    free(relay_forwarder_data->nameservers);
exit_2:
    free(relay_forwarder_data->alias);
exit_1:
    free(relay_forwarder_data);
exit_0:
    return NULL;
}

void relay_forwarder_data_cleanup(relay_forwarder_data_t **relay_forwarder_data)
{
    free((*relay_forwarder_data)->alias);
    for (size_t i = 0; i < (*relay_forwarder_data)->nameserver_count; i++)
    {
        free((*relay_forwarder_data)->nameservers[i]);
    }
    free((*relay_forwarder_data)->nameservers);
    free(*relay_forwarder_data);
    relay_forwarder_data = NULL;
}