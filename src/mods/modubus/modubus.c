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

typedef struct _mod_ubus_t
{
    struct ubus_context *ctx;
    struct event *ubus_event;
    relay_forwarders_t *relay_forwarders;
} mod_ubus_t;

static mod_ubus_t *mod_ubus;

enum
{
    ADD_RELAY_FORWARDER_ALIAS,
    ADD_RELAY_FORWARDER_DNSSERVERS,
    __ADD_RELAY_FORWARDER_MAX
};

static const struct blobmsg_policy add_relay_forwarder_policy[] = {
    [ADD_RELAY_FORWARDER_ALIAS] = {.name = "Alias", .type = BLOBMSG_TYPE_STRING},
    [ADD_RELAY_FORWARDER_DNSSERVERS] = {.name = "DNSServers", .type = BLOBMSG_TYPE_ARRAY},
};

static int get_config(struct ubus_context *ctx, UNUSED struct ubus_object *obj, UNUSED struct ubus_request_data *req, UNUSED const char *method, UNUSED struct blob_attr *msg)
{
    blob_buf_init(&b, 0);

    blobmsg_add_string(&b, "response", "Hello from JojoDNS!");

    ubus_send_reply(ctx, req, b.head);

    blob_buf_free(&b);
    return 0;
}

static int add_relay_forwarder(struct ubus_context *ctx, UNUSED struct ubus_object *obj, UNUSED struct ubus_request_data *req, UNUSED const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__ADD_RELAY_FORWARDER_MAX];
    struct blob_attr *cur = NULL;
    const char *alias = "";
    int rem = 0;
    JSON_Value *dnsservers_root_value = json_value_init_array();
    JSON_Array *nameservers = json_value_get_array(dnsservers_root_value);

    blobmsg_parse(add_relay_forwarder_policy, ARRAY_SIZE(add_relay_forwarder_policy), tb, blob_data(msg), blob_len(msg));

    if (tb[ADD_RELAY_FORWARDER_ALIAS])
    {
        alias = blobmsg_get_string(tb[ADD_RELAY_FORWARDER_ALIAS]);
    }

    if (tb[ADD_RELAY_FORWARDER_DNSSERVERS])
    {
        blobmsg_for_each_attr(cur, tb[ADD_RELAY_FORWARDER_DNSSERVERS], rem)
        {
            if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
            {
                const char *dns_server = blobmsg_get_string(cur);
                json_array_append_string(nameservers, dns_server);
            }
        }
    }

    blob_buf_init(&b, 0);

    if (relay_forwarders_add(mod_ubus->relay_forwarders, alias, nameservers))
    {
        blobmsg_add_string(&b, "Response", "ok");
    }
    else
    {
        blobmsg_add_string(&b, "Response", "failed");
    }

    json_value_free(dnsservers_root_value);

    ubus_send_reply(ctx, req, b.head);

    blob_buf_free(&b);
    return 0;
}

static struct ubus_method jojodns_methods[] = {
    UBUS_METHOD_NOARG("GetConfig", get_config),
    UBUS_METHOD("AddRelayForwarder", add_relay_forwarder, add_relay_forwarder_policy),
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

bool mod_ubus_init(struct event_base *base, relay_forwarders_t *relay_forwarders)
{
    if (base == NULL || relay_forwarders == NULL)
    {
        log_error("Invalid input arguments");
        goto exit_0;
    }

    mod_ubus = (mod_ubus_t *)calloc(1, sizeof(mod_ubus_t));
    if (mod_ubus == NULL)
    {
        log_error("Failed to allocate memory for mod_ubus_t");
        goto exit_0;
    }

    mod_ubus->relay_forwarders = relay_forwarders;

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

    return true;

exit_2:
    ubus_free(mod_ubus->ctx);
exit_1:
    free(mod_ubus);
exit_0:
    return false;
}

void mod_ubus_cleanup()
{
    if (mod_ubus->ubus_event != NULL)
    {
        event_free(mod_ubus->ubus_event);
    }

    if (mod_ubus->ctx != NULL)
    {
        ubus_free(mod_ubus->ctx);
    }

    free(mod_ubus);
    mod_ubus = NULL;
}