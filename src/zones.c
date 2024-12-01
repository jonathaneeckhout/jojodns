#include <stdlib.h>
#include <hashmap.h>
#include <parson.h>
#include <string.h>

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

    local = local_init(json_value_get_array(data->hosts));
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
    const char *alias = json_object_get_string(zone, "Alias");
    JSON_Array *hosts = json_object_get_array(zone, "Hosts");
    zone_data_t *data = zone_data_init(alias, hosts);

    zones_add(zones, data);

    zone_data_cleanup(&data);
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

zone_data_t *zone_data_init(const char *alias, JSON_Array *hosts)
{
    size_t hosts_count = 0;
    JSON_Array *json_hosts = NULL;
    zone_data_t *zone_data = (zone_data_t *)calloc(1, sizeof(zone_data_t));
    if (zone_data == NULL)
    {
        log_error("Failed to allocate memory for zone_data_t");
        goto exit_0;
    }

    zone_data->alias = strdup(alias);
    zone_data->hosts = json_value_init_array();
    json_hosts = json_value_get_array(zone_data->hosts);

    hosts_count = json_array_get_count(hosts);
    for (size_t i = 0; i < hosts_count; i++)
    {
        JSON_Value *host_value = json_value_deep_copy(json_array_get_value(hosts, i));
        json_array_append_value(json_hosts, host_value);
    }

    return zone_data;

exit_0:
    return NULL;
}

void zone_data_cleanup(zone_data_t **zone_data)
{
    free((*zone_data)->alias);
    json_value_free((*zone_data)->hosts);

    free(*zone_data);
    zone_data = NULL;
}

zone_data_t *zone_data_copy(zone_data_t *data)
{
    return zone_data_init(data->alias, json_value_get_array(data->hosts));
}