#ifndef SERVER_CACHE_H
#define SERVER_CACHE_H

#include <hashmap.h>
#include <event2/event.h>

typedef struct _cache_t
{
    struct hashmap *hmap;
    uint size;
    int max_ttl;
    int min_ttl;
    struct event *expiration_timer;
    struct timeval expiration_timer_interval;
} cache_t;

typedef struct _cache_entry_t
{
    char *name;
    char type;
    int count;
    int ttl;
    struct in_addr *a_addr_list;
    struct in6_addr *aaaa_addr_list;
    time_t expiration_time;
} cache_entry_t;

cache_t *cache_init(struct event_base *base);
void cache_cleanup(cache_t **cache);

cache_entry_t *cache_entry_init(const char *name, char type, int count, int ttl, struct in_addr *a_addr_list, struct in6_addr *aaaa_addr_list, time_t expiration_time);
void cache_entry_cleanup(cache_entry_t **entry);
void cache_add_entry(cache_t *cache, char *name, char type, int count, int ttl, struct in_addr *a_addr_list, struct in6_addr *aaaa_addr_list);
const cache_entry_t *cache_get_entry(cache_t *cache, const char *name);

#endif