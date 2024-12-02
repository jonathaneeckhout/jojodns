#include <stdlib.h>
#include <hashmap.h>
#include <parson.h>
#include <string.h>
#include <arpa/inet.h>

#include "logging.h"
#include "zones.h"

#define UNUSED __attribute__((unused))

static uint64_t zones_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const zone_t *enrty = item;
    return hashmap_sip(enrty->data->alias, strlen(enrty->data->alias), seed0, seed1);
}

static int zones_compare(const void *a, const void *b, UNUSED void *udata)
{
    const zone_t *entry_a = a;
    const zone_t *entry_b = b;
    return strcmp(entry_a->data->alias, entry_b->data->alias);
}

static void zones_free(void *item)
{
    zone_t *zone = item;
    zone_data_cleanup(&zone->data);
    local_cleanup(&zone->local);
}

bool zones_add(zones_t *zones, zone_data_t *data)
{
    local_t *local = NULL;
    zone_data_t *copy_of_data = NULL;

    if (data->alias == NULL || strlen(data->alias) == 0)
    {
        log_warning("Failed to add zone, invalid alias");
        goto exit_0;
    }

    if (hashmap_get(zones->zones, &(zone_t){.data = data}) != NULL)
    {
        log_warning("Zone=[%s] already exists", data->alias);
        goto exit_0;
    }

    local = local_init(data->hosts, data->hosts_count);
    if (local == NULL)
    {
        log_error("Failed to init local=[%s]", data->alias);
        goto exit_0;
    }

    copy_of_data = zone_data_copy(data);
    if (copy_of_data == NULL)
    {
        log_error("Failed to copy zone data");
        goto exit_1;
    }

    if (hashmap_set(zones->zones, &(zone_t){.data = copy_of_data, .local = local}) != NULL)
    {
        log_error("failed to add zone=[%s]", data->alias);
        goto exit_2;
    }

    log_info("Added zone=[%s]", data->alias);

    return true;

exit_2:
    zone_data_cleanup(&copy_of_data);
exit_1:
    local_cleanup(&local);

exit_0:
    return false;
}

static void add_config_zones(zones_t *zones, JSON_Object *zone)
{
    const char *zone_alias = NULL;
    JSON_Array *json_hosts = NULL;
    size_t json_hosts_count = 0;
    local_host_t **hosts = NULL;
    size_t hosts_count = 0;
    size_t i = 0;
    zone_data_t *data = NULL;

    zone_alias = json_object_get_string(zone, "Alias");
    json_hosts = json_object_get_array(zone, "Hosts");
    json_hosts_count = json_array_get_count(json_hosts);

    hosts = (local_host_t **)malloc(sizeof(local_host_t *) * json_hosts_count);
    if (hosts == NULL)
    {
        log_error("Failed to allocate memory for hosts");
        return;
    }

    for (i = 0; i < json_hosts_count; i++)
    {
        local_host_t *local_host = NULL;
        JSON_Object *host = NULL;
        const char *host_name = NULL;
        JSON_Array *ip_addresses = NULL;
        size_t ip_count = 0;
        struct in_addr *a_addr_list = NULL;
        size_t j = 0;

        host = json_array_get_object(json_hosts, i);
        host_name = json_object_get_string(host, "Name");
        ip_addresses = json_object_get_array(host, "IPAddresses");
        ip_count = json_array_get_count(ip_addresses);

        a_addr_list = (struct in_addr *)malloc(sizeof(struct in_addr) * ip_count);
        if (a_addr_list == NULL)
        {
            log_error("Failed to allocate memory for addr_list");
            continue;
        }

        for (j = 0; j < ip_count; j++)
        {
            const char *ip_address = json_array_get_string(ip_addresses, j);
            inet_pton(AF_INET, ip_address, &a_addr_list[j]);
            log_debug("Adding zone=[%s] host=[%s] ip=[%s]", zone_alias, host_name, ip_address);
        }

        local_host = local_host_init(host_name, ip_count, a_addr_list);
        if (local_host != NULL)
        {
            hosts[hosts_count++] = local_host;
        }

        free(a_addr_list);
    }

    data = zone_data_init(zone_alias, hosts, hosts_count);
    if (data != NULL)
    {
        zones_add(zones, data);
        zone_data_cleanup(&data);
    }

    for (i = 0; i < hosts_count; i++)
    {
        local_host_cleanup(&hosts[i]);
    }
    free(hosts);
}

zones_t *zones_init(JSON_Value *config_data)
{
    JSON_Array *json_zones = NULL;
    size_t zones_count = 0;

    zones_t *zones = (zones_t *)calloc(1, sizeof(zones_t));
    if (zones == NULL)
    {
        log_error("Failed to allocate memory for zones_t");
        goto exit_0;
    }

    zones->zones = hashmap_new(sizeof(zone_t), 0, 0, 0, zones_hash, zones_compare, zones_free, NULL);
    if (zones->zones == NULL)
    {
        log_error("Failed to init new hashmap");
        goto exit_1;
    }

    json_zones = json_object_dotget_array(json_object(config_data), "Relay.Zone");
    if (json_zones == NULL)
    {
        log_warning("No Zones config section found");
        goto exit_2;
    }

    zones_count = json_array_get_count(json_zones);
    for (size_t i = 0; i < zones_count; i++)
    {
        JSON_Object *zone = json_array_get_object(json_zones, i);
        add_config_zones(zones, zone);
    }

    return zones;

exit_2:
    hashmap_clear(zones->zones, true);
    hashmap_free(zones->zones);
exit_1:
    free(zones);
exit_0:
    return NULL;
}

void zones_cleanup(zones_t **zones)
{
    if ((*zones)->zones != NULL)
    {
        hashmap_clear((*zones)->zones, true);
        hashmap_free((*zones)->zones);
    }

    free(*zones);
    zones = NULL;
}

zone_data_t *zone_data_init(const char *alias, local_host_t **hosts, size_t hosts_count)
{
    zone_data_t *zone_data = (zone_data_t *)calloc(1, sizeof(zone_data_t));
    if (zone_data == NULL)
    {
        log_error("Failed to allocate memory for zone_data_t");
        goto exit_0;
    }

    zone_data->alias = strdup(alias);
    if (zone_data->alias == NULL)
    {
        log_error("Failed to allocate memory for alias");
        goto exit_1;
    }

    zone_data->hosts = (local_host_t **)calloc(hosts_count, sizeof(local_host_t *));
    if (zone_data->hosts == NULL)
    {
        log_error("Failed to allocate memory for hosts array");
        goto exit_2;
    }

    for (size_t i = 0; i < hosts_count; i++)
    {
        zone_data->hosts[i] = local_host_copy(hosts[i]);
    }
    zone_data->hosts_count = hosts_count;

    return zone_data;

exit_2:
    free(zone_data->alias);
exit_1:
    free(zone_data);
exit_0:
    return NULL;
}

void zone_data_cleanup(zone_data_t **zone_data)
{
    free((*zone_data)->alias);

    for (size_t i = 0; i < (*zone_data)->hosts_count; i++)
    {
        local_host_cleanup(&(*zone_data)->hosts[i]);
    }
    free((*zone_data)->hosts);

    free(*zone_data);
    zone_data = NULL;
}

zone_data_t *zone_data_copy(zone_data_t *data)
{
    return zone_data_init(data->alias, data->hosts, data->hosts_count);
}