#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <event2/event.h>
#include <event2/dns.h>

#include "mods/modubus/modubus.h"
#include "logging.h"

#define UNUSED __attribute__((unused))

static struct blob_buf b;

static int getconfig_method(UNUSED struct ubus_context *ctx, UNUSED struct ubus_object *obj, UNUSED struct ubus_request_data *req, UNUSED const char *method, UNUSED struct blob_attr *msg)
{
    blob_buf_init(&b, 0);

    blobmsg_add_string(&b, "response", "Hello from JojoDNS!");

    ubus_send_reply(ctx, req, b.head);

    blob_buf_free(&b);
    return 0;
}

static struct ubus_method jojodns_methods[] = {
    UBUS_METHOD_NOARG("getconfig", getconfig_method),
};

static struct ubus_object_type jojodns_object_type =
    UBUS_OBJECT_TYPE("jojodns", jojodns_methods);

static struct ubus_object jojodns_object = {
    .name = "jojodns",
    .type = &jojodns_object_type,
    .methods = jojodns_methods,
    .n_methods = ARRAY_SIZE(jojodns_methods),
};

static void ubus_event_handler(UNUSED evutil_socket_t fd, short events, void *arg)
{
    mod_ubus_t *mod_ubus = arg;

    if (events & EV_READ)
    {
        ubus_handle_event(mod_ubus->ctx);
    }
}

mod_ubus_t *mod_ubus_init(struct event_base *base)
{
    mod_ubus_t *mod_ubus = (mod_ubus_t *)calloc(1, sizeof(mod_ubus_t));
    if (mod_ubus == NULL)
    {
        log_error("Failed to allocate memory for mod_ubus_t");
        goto exit_0;
    }

    mod_ubus->ctx = ubus_connect(NULL);
    if (!mod_ubus->ctx)
    {
        log_error("Failed to connect to UBUS");
        goto exit_1;
    }

    if (ubus_add_object(mod_ubus->ctx, &jojodns_object) < 0)
    {
        log_error("Failed to add UBUS object");
        goto exit_2;
    }

    mod_ubus->ubus_event = event_new(base, mod_ubus->ctx->sock.fd, EV_READ | EV_PERSIST, ubus_event_handler, mod_ubus);
    if (!mod_ubus->ubus_event)
    {
        log_error("Failed to create ubus event");
        goto exit_2;
    }

    event_add(mod_ubus->ubus_event, NULL);

    return mod_ubus;

exit_2:
    ubus_free(mod_ubus->ctx);
exit_1:
    free(mod_ubus);
exit_0:
    return NULL;
}

void mod_ubus_cleanup(mod_ubus_t **mod_ubus)
{
    if ((*mod_ubus)->ubus_event != NULL)
    {
        event_free((*mod_ubus)->ubus_event);
    }

    if ((*mod_ubus)->ctx != NULL)
    {
        ubus_free((*mod_ubus)->ctx);
    }

    free(*mod_ubus);
    mod_ubus = NULL;
}