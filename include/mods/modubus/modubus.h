#ifndef UBUS_H
#define UBUS_H

#include <libubus.h>
#include <event2/event.h>

typedef struct _mod_ubus_t
{
    struct ubus_context *ctx;
    struct event *ubus_event;

} mod_ubus_t;

mod_ubus_t *mod_ubus_init(struct event_base *base);
void mod_ubus_cleanup(mod_ubus_t **mod_ubus);

#endif