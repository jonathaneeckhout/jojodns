#ifndef UBUS_H
#define UBUS_H

#include <libubus.h>
#include <event2/event.h>

#include "relay_forwarders.h"
#include "relay_servers.h"
#include "zones.h"

bool mod_ubus_init(struct event_base *base, relay_forwarders_t *relay_forwarders, relay_servers_t *relay_servers, zones_t *zones);
void mod_ubus_cleanup();

#endif