#ifndef LOCAL_H
#define LOCAL_H

#include "hashmap.h"

typedef struct _local_t
{
    struct hashmap *hosts;
} local_t;

local_t *local_init();
void local_cleanup(local_t **local);

#endif