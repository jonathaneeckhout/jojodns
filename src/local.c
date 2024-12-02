#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>

#include "logging.h"
#include "local.h"

#define UNUSED __attribute__((unused))

local_host_t *local_host_init(const char *name, size_t count, struct in_addr *a_addr_list)
{
    local_host_t *host = (local_host_t *)malloc(sizeof(local_host_t));
    if (!host)
    {
        log_error("Failed to allocate memory for local_host_t");
        goto exit_0;
    }

    host->name = strdup(name);
    if (!host->name)
    {
        log_error("Failed to allocate memory for name");
        goto exit_1;
    }

    host->count = count;
    host->a_addr_list = (struct in_addr *)malloc(sizeof(struct in_addr) * count);
    if (!host->a_addr_list)
    {
        log_error("Failed to allocate memory for addr_list");
        goto exit_1;
    }

    memcpy(host->a_addr_list, a_addr_list, sizeof(struct in_addr) * count);

    return host;

exit_1:
    free(host->name);
    free(host);
exit_0:
    return NULL;
}

void local_host_cleanup(local_host_t **host)
{
    free((*host)->name);
    free((*host)->a_addr_list);
    free(*host);
    *host = NULL;
}

local_host_t *local_host_copy(const local_host_t *host)
{
    return local_host_init(host->name, host->count, host->a_addr_list);
}

const local_host_entry_t *local_get_entry(local_t *local, const char *name)
{
    const void *data = hashmap_get(local->hosts, &(local_host_entry_t){.name = (char *)name});
    if (data == NULL)
    {
        return NULL;
    }

    return (const local_host_entry_t *)data;
}

static local_host_entry_t *local_host_entry_init(local_host_t *host)
{
    local_host_entry_t *entry = (local_host_entry_t *)malloc(sizeof(local_host_entry_t));
    if (!entry)
    {
        log_error("Failed to allocate memory for local_host_entry_t");
        goto exit_0;
    }

    entry->name = strdup(host->name);
    if (!entry->name)
    {
        log_error("Failed to allocate memory for name");
        goto exit_1;
    }

    entry->count = host->count;
    entry->a_addr_list = (struct in_addr *)malloc(sizeof(struct in_addr) * host->count);
    if (!entry->a_addr_list)
    {
        log_error("Failed to allocate memory for addr_list");
        goto exit_1;
    }

    memcpy(entry->a_addr_list, host->a_addr_list, sizeof(struct in_addr) * host->count);

    return entry;

exit_1:
    free(entry);
exit_0:
    return NULL;
}

static void local_host_entry_cleanup_content(local_host_entry_t *entry)
{
    free(entry->name);
    free(entry->a_addr_list);
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

bool local_add_host(local_t *local, local_host_t *host)
{
    local_host_entry_t *entry = local_host_entry_init(host);
    if (!entry)
    {
        return false;
    }

    hashmap_set(local->hosts, entry);

    // Only the pointer should be freed as the rest will be cleaned up with the custom free
    free(entry);

    return true;
}

local_t *local_init(local_host_t **hosts, size_t hosts_count)
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

    for (size_t i = 0; i < hosts_count; i++)
    {
        if (!local_add_host(local, hosts[i]))
        {
            log_error("Failed to add host");
            goto exit_2;
        }
    }

    log_debug("Created a new DNS local host");

    return local;

exit_2:
    hashmap_clear(local->hosts, true);
    hashmap_free(local->hosts);
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