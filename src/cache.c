#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "logging.h"
#include "cache.h"

#define UNUSED __attribute__((unused))

cache_entry_t *cache_entry_init(const char *name, char type, int count, int ttl, struct in_addr *a_addr_list, struct in6_addr *aaaa_addr_list)
{
    cache_entry_t *entry = (cache_entry_t *)malloc(sizeof(cache_entry_t));
    if (!entry)
    {
        log_error("Failed to allocate memory for cache_entry_t");
        goto exit_0;
    }

    entry->name = strdup(name);
    if (!entry->name)
    {
        log_error("Failed to allocate memory for name");
        goto exit_1;
    }

    entry->type = type;
    entry->count = count;
    entry->ttl = ttl;

    if (a_addr_list != NULL)
    {
        entry->a_addr_list = (struct in_addr *)malloc(sizeof(struct in_addr) * count);
        if (!entry->a_addr_list)
        {
            log_error("Failed to allocate memory for addr_list");
            goto exit_2;
        }

        memcpy(entry->a_addr_list, a_addr_list, sizeof(struct in_addr) * count);
    }
    else
    {
        entry->a_addr_list = NULL;
    }

    if (aaaa_addr_list != NULL)
    {
        entry->aaaa_addr_list = (struct in6_addr *)malloc(sizeof(struct in6_addr) * count);
        if (!entry->aaaa_addr_list)
        {
            log_error("Failed to allocate memory for addr_list");
            goto exit_3;
        }

        memcpy(entry->aaaa_addr_list, aaaa_addr_list, sizeof(struct in6_addr) * count);
    }
    else
    {
        entry->aaaa_addr_list = NULL;
    }

    return entry;

exit_3:
    free(entry->a_addr_list);
exit_2:
    free(entry->name);
exit_1:
    free(entry);
exit_0:
    return NULL;
}

void cache_entry_cleanup(cache_entry_t **entry)
{
    if (entry == NULL || *entry == NULL)
    {
        return;
    }

    free((*entry)->name);
    free((*entry)->a_addr_list);
    free((*entry)->aaaa_addr_list);

    free(*entry);
    *entry = NULL;
}

static void cache_free(void *item)
{
    cache_entry_t *entry = item;

    free(entry->name);
    free(entry->a_addr_list);
    free(entry->aaaa_addr_list);
}

void cache_add_entry(cache_t *cache, char *name, char type, int count, int ttl, struct in_addr *a_addr_list, struct in6_addr *aaaa_addr_list)
{
    cache_entry_t *entry = cache_entry_init(name, type, count, ttl, a_addr_list, aaaa_addr_list);

    const cache_entry_t *old_entry = hashmap_delete(cache->hmap, entry);
    if (old_entry != NULL)
    {
        cache_free((cache_entry_t *)old_entry);
    }

    hashmap_set(cache->hmap, entry);

    // Only the pointer should be freed as the rest will be cleaned up with the custom free
    free(entry);
}

const cache_entry_t *cache_get_entry(cache_t *cache, const char *name)
{
    const void *data = hashmap_get(cache->hmap, &(cache_entry_t){.name = (char *)name});
    if (data == NULL)
    {
        return NULL;
    }

    return (const cache_entry_t *)data;
}

static int cache_compare(const void *a, const void *b, UNUSED void *udata)
{
    const cache_entry_t *entry_a = a;
    const cache_entry_t *entry_b = b;
    return strcmp(entry_a->name, entry_b->name);
}

static uint64_t cache_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const cache_entry_t *enrty = item;
    return hashmap_sip(enrty->name, strlen(enrty->name), seed0, seed1);
}

cache_t *cache_init()
{
    cache_t *cache = (cache_t *)calloc(1, sizeof(cache_t));
    if (cache == NULL)
    {
        log_error("Failed to allocate memory for cache_t");
        goto exit_0;
    }

    cache->hmap = hashmap_new(sizeof(cache_entry_t), 0, 0, 0, cache_hash, cache_compare, cache_free, NULL);
    if (cache->hmap == NULL)
    {
        log_error("Failed to init new hashmap");
        goto exit_1;
    }

    return cache;

exit_1:
    free(cache);
exit_0:
    return NULL;
}

void cache_cleanup(cache_t **cache)
{
    if (cache == NULL || *cache == NULL)
    {
        return;
    }

    if ((*cache)->hmap != NULL)
    {
        hashmap_clear((*cache)->hmap, true);
        hashmap_free((*cache)->hmap);
    }

    free(*cache);
    *cache = NULL;
}
