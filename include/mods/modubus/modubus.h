#ifndef UBUS_H
#define UBUS_H

#include <libubus.h>
#include <event2/event.h>

#include "relay_forwarders.h"
#include "relay_servers.h"

bool mod_ubus_init(struct event_base *base, relay_forwarders_t *relay_forwarders, relay_servers_t* relay_servers);
void mod_ubus_cleanup();

#endif