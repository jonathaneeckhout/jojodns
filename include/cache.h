#ifndef SERVER_CACHE_H
#define SERVER_CACHE_H

#include <hashmap.h>

typedef struct _cache_t
{
    struct hashmap *hmap;
} cache_t;

typedef struct _cache_entry_t
{
    char *name;
    char type;
    int count;
    int ttl;
    struct in_addr *addr_list;
} cache_entry_t;

cache_t *cache_init();
void cache_cleanup(cache_t **cache);

cache_entry_t *cache_entry_init(const char *name, char type, int count, int ttl, struct in_addr *addr_list);
void cache_entry_cleanup(cache_entry_t **entry);
void cache_add_entry(cache_t *cache, char *name, char type, int count, int ttl, struct in_addr *addr_list);
const cache_entry_t *cache_get_entry(cache_t *cache, const char *name);

#endif