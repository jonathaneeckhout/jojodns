#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <parson.h>

#include "logging.h"
#include "local.h"

#define UNUSED __attribute__((unused))

typedef struct _local_host_entry_t
{
    char *name;
    char type;
    int count;
    struct in_addr *a_addr_list;
    struct in6_addr *aaaa_addr_list;
} local_host_entry_t;

const local_host_entry_t *local_get_entry(local_t *local, const char *name)
{
    const void *data = hashmap_get(local->hosts, &(local_host_entry_t){.name = (char *)name});
    if (data == NULL)
    {
        return NULL;
    }

    return (const local_host_entry_t *)data;
}

static local_host_entry_t *local_host_entry_init(JSON_Object *host)
{
    local_host_entry_t *entry = (local_host_entry_t *)malloc(sizeof(local_host_entry_t));
    if (!entry)
    {
        log_error("Failed to allocate memory for local_host_entry_t");
        goto exit_0;
    }

    entry->name = strdup(json_object_get_string(host, "Name"));

    entry->type = 0;
    entry->count = 0;
    entry->a_addr_list = NULL;
    entry->aaaa_addr_list = NULL;

    return entry;

exit_0:
    return NULL;
}

static void local_host_entry_cleanup_content(local_host_entry_t *entry)
{
    free(entry->name);
    free(entry->a_addr_list);
    free(entry->aaaa_addr_list);
}

void local_host_entry_cleanup(local_host_entry_t **entry)
{
    if (entry == NULL || *entry == NULL)
    {
        return;
    }

    local_host_entry_cleanup_content(*entry);

    free(*entry);
    *entry = NULL;
}

static void local_free(void *item)
{
    local_host_entry_t *entry = item;
    local_host_entry_cleanup_content(entry);
}

static int local_compare(const void *a, const void *b, UNUSED void *udata)
{
    const local_host_entry_t *entry_a = a;
    const local_host_entry_t *entry_b = b;
    return strcmp(entry_a->name, entry_b->name);
}

static uint64_t local_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const local_host_entry_t *enrty = item;
    return hashmap_sip(enrty->name, strlen(enrty->name), seed0, seed1);
}

void local_add_host(local_t *local, JSON_Object *host)
{
    local_host_entry_t *entry = local_host_entry_init(host);

    hashmap_set(local->hosts, entry);

    // Only the pointer should be freed as the rest will be cleaned up with the custom free
    free(entry);
}

local_t *local_init(JSON_Array *hosts)
{
    local_t *local = (local_t *)calloc(1, sizeof(local_t));
    if (local == NULL)
    {
        log_error("Failed to allocate memory for local_t");
        goto exit_0;
    }

    local->hosts = hashmap_new(sizeof(local_host_entry_t), 0, 0, 0, local_hash, local_compare, local_free, NULL);
    if (local->hosts == NULL)
    {
        log_error("Failed to init new hashmap");
        goto exit_1;
    }

    for (size_t i = 0; i < json_array_get_count(hosts); i++)
    {
        local_add_host(local, json_array_get_object(hosts, i));
    }

    log_debug("Created a new DNS local host");

    return local;

exit_1:
    free(local);
exit_0:
    return NULL;
}

void local_cleanup(local_t **local)
{

    if (local == NULL || *local == NULL)
    {
        return;
    }

    if ((*local)->hosts != NULL)
    {
        hashmap_clear((*local)->hosts, true);
        hashmap_free((*local)->hosts);
    }

    free(*local);
    *local = NULL;
}