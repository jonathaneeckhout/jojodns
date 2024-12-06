#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <event2/dns_struct.h>

#include "logging.h"

#define UNUSED __attribute__((unused))

extern bool bind_failed;
extern bool calloc_failed;

#endif // TEST_COMMON_H