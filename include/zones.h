#ifndef ZONES_H
#define ZONES_H

#include <parson.h>
#include <hashmap.h>

#include "local.h"

typedef struct _zone_data_t
{
    char *alias;
    local_host_t **hosts;
    size_t hosts_count;
} zone_data_t;

typedef struct _zone_t
{
    zone_data_t *data;
    local_t *local;
} zone_t;

typedef struct _zones_t
{
    struct hashmap *zones;
} zones_t;

zones_t *zones_init(JSON_Value *config_data);
void zones_cleanup(zones_t **zones);
bool zones_add(zones_t *s, zone_data_t *data);

zone_data_t *zone_data_init(const char *alias, local_host_t **hosts, size_t hosts_count);
void zone_data_cleanup(zone_data_t **zone_data);
zone_data_t *zone_data_copy(zone_data_t *data);

#endif