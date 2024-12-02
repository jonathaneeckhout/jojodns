#ifndef LOCAL_H
#define LOCAL_H

#include "hashmap.h"

typedef struct _local_t
{
    struct hashmap *hosts;
} local_t;

typedef struct _local_host_t
{
    char *name;
    size_t count;
    struct in_addr *a_addr_list;
} local_host_t;

typedef struct _local_host_entry_t
{
    char *name;
    size_t count;
    struct in_addr *a_addr_list;
} local_host_entry_t;

local_t *local_init(local_host_t **hosts, size_t hosts_count);
void local_cleanup(local_t **local);

const local_host_entry_t *local_get_entry(local_t *local, const char *name);

local_host_t *local_host_init(const char *name, size_t count, struct in_addr *a_addr_list);
void local_host_cleanup(local_host_t **host);
local_host_t *local_host_copy(const local_host_t *host);

#endif