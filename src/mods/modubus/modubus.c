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

// static struct blob_buf b;

typedef struct _mod_ubus_t
{
    struct ubus_context *ctx;
    struct event *ubus_event;
    relay_forwarders_t *relay_forwarders;
    relay_servers_t *relay_servers;
    zones_t *zones;
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

enum
{
    ADD_RELAY_SERVER_ENABLE,
    ADD_RELAY_SERVER_ALIAS,
    ADD_RELAY_SERVER_FORWARDERS,
    ADD_RELAY_SERVER_INTERFACE,
    ADD_RELAY_SERVER_ADDRESS,
    ADD_RELAY_SERVER_PORT,
    ADD_RELAY_SERVER_CACHE_SIZE,
    ADD_RELAY_SERVER_CACHE_MIN_TTL,
    ADD_RELAY_SERVER_CACHE_MAX_TTL,
    __ADD_RELAY_SERVER_MAX
};

static const struct blobmsg_policy add_relay_server_policy[] = {
    [ADD_RELAY_SERVER_ENABLE] = {.name = "Enable", .type = BLOBMSG_TYPE_BOOL},
    [ADD_RELAY_SERVER_ALIAS] = {.name = "Alias", .type = BLOBMSG_TYPE_STRING},
    [ADD_RELAY_SERVER_FORWARDERS] = {.name = "Forwarders", .type = BLOBMSG_TYPE_ARRAY},
    [ADD_RELAY_SERVER_INTERFACE] = {.name = "Interface", .type = BLOBMSG_TYPE_STRING},
    [ADD_RELAY_SERVER_ADDRESS] = {.name = "Address", .type = BLOBMSG_TYPE_STRING},
    [ADD_RELAY_SERVER_PORT] = {.name = "Port", .type = BLOBMSG_TYPE_INT32},
    [ADD_RELAY_SERVER_CACHE_SIZE] = {.name = "CacheSize", .type = BLOBMSG_TYPE_INT32},
    [ADD_RELAY_SERVER_CACHE_MIN_TTL] = {.name = "CacheMinTTL", .type = BLOBMSG_TYPE_INT32},
    [ADD_RELAY_SERVER_CACHE_MAX_TTL] = {.name = "CacheMaxTTL", .type = BLOBMSG_TYPE_INT32},
};

static int get_config(struct ubus_context *ctx, UNUSED struct ubus_object *obj, UNUSED struct ubus_request_data *req, UNUSED const char *method, UNUSED struct blob_attr *msg)
{
    struct blob_buf b;
    size_t iter = 0;
    void *item = NULL;
    void *data_object = NULL;
    void *relay_object = NULL;
    void *config_array = NULL;
    void *zone_array = NULL;
    void *forwarding_array = NULL;

    memset(&b, 0, sizeof(b));
    blob_buf_init(&b, 0);

    data_object = blobmsg_open_table(&b, "Data");

    relay_object = blobmsg_open_table(&b, "Relay");

    config_array = blobmsg_open_array(&b, "Config");

    while (hashmap_iter(mod_ubus->relay_servers->servers, &iter, &item))
    {
        void *forwarders_array = NULL;
        relay_server_t *entry = item;

        void *server_entry = blobmsg_open_table(&b, NULL);

        blobmsg_add_u32(&b, "Enable", entry->data->enable);
        blobmsg_add_string(&b, "Alias", entry->data->alias);

        forwarders_array = blobmsg_open_array(&b, "Forwarders");
        blobmsg_add_string(&b, NULL, entry->data->forwarder_name);
        blobmsg_close_array(&b, forwarders_array);

        blobmsg_add_string(&b, "Interface", entry->data->interface);
        blobmsg_add_string(&b, "Address", entry->data->address);
        blobmsg_add_u32(&b, "Port", entry->data->port);

        blobmsg_add_u32(&b, "CacheSize", entry->data->cache_size);
        blobmsg_add_u32(&b, "CacheMinTTL", entry->data->cache_min_ttl);
        blobmsg_add_u32(&b, "CacheMaxTTL", entry->data->cache_max_ttl);

        blobmsg_close_table(&b, server_entry);
    }

    blobmsg_close_array(&b, config_array);

    zone_array = blobmsg_open_array(&b, "Zone");

    iter = 0;
    item = NULL;

    while (hashmap_iter(mod_ubus->zones->zones, &iter, &item))
    {
        zone_t *entry = item;
        void *hosts_array = NULL;
        JSON_Array *json_hosts = NULL;

        void *zone_entry = blobmsg_open_table(&b, NULL);

        blobmsg_add_u32(&b, "Enable", 1);
        blobmsg_add_string(&b, "Alias", entry->data->alias);
        hosts_array = blobmsg_open_array(&b, "Hosts");

        json_hosts = json_value_get_array(entry->data->hosts);

        for (size_t i = 0; i < json_array_get_count(json_hosts); i++)
        {
            void *host_entry = blobmsg_open_table(&b, NULL);
            JSON_Object *host_object = json_array_get_object(json_hosts, i);
            blobmsg_add_string(&b, "Alias", json_object_get_string(host_object, "Alias"));
            blobmsg_add_string(&b, "Name", json_object_get_string(host_object, "Name"));
            blobmsg_close_table(&b, host_entry);
        }

        blobmsg_close_array(&b, hosts_array);

        blobmsg_close_table(&b, zone_entry);
    }

    blobmsg_close_array(&b, zone_array);

    forwarding_array = blobmsg_open_array(&b, "Forwarding");

    iter = 0;
    item = NULL;

    while (hashmap_iter(mod_ubus->relay_forwarders->forwarders, &iter, &item))
    {
        void *dnsservers_array = NULL;
        relay_forwarder_t *entry = item;

        void *forwarding_entry = blobmsg_open_table(&b, NULL);

        blobmsg_add_u32(&b, "Enable", 1);
        blobmsg_add_string(&b, "Alias", entry->data->alias);

        dnsservers_array = blobmsg_open_array(&b, "DNSServers");

        for (size_t i = 0; i < entry->data->nameserver_count; i++)
        {
            blobmsg_add_string(&b, NULL, entry->data->nameservers[i]);
        }

        blobmsg_close_array(&b, dnsservers_array);

        blobmsg_close_table(&b, forwarding_entry);
    }

    blobmsg_close_array(&b, forwarding_array);

    blobmsg_close_table(&b, relay_object);

    blobmsg_close_table(&b, data_object);

    blobmsg_add_string(&b, "Status", "Ok");

    ubus_send_reply(ctx, req, b.head);

    blob_buf_free(&b);
    return 0;
}

static int add_relay_forwarder(struct ubus_context *ctx, UNUSED struct ubus_object *obj, struct ubus_request_data *req, UNUSED const char *method, struct blob_attr *msg)
{
    struct blob_buf b;
    struct blob_attr *tb[__ADD_RELAY_FORWARDER_MAX];
    struct blob_attr *cur = NULL;
    const char *alias = "";
    char **nameservers = NULL;
    size_t nameserver_count = 0;
    relay_forwarder_data_t *data = NULL;
    int rem = 0;

    blobmsg_parse(add_relay_forwarder_policy, ARRAY_SIZE(add_relay_forwarder_policy), tb, blob_data(msg), blob_len(msg));

    if (tb[ADD_RELAY_FORWARDER_ALIAS])
    {
        alias = blobmsg_get_string(tb[ADD_RELAY_FORWARDER_ALIAS]);
    }

    if (tb[ADD_RELAY_FORWARDER_DNSSERVERS])
    {
        size_t index = 0;

        blobmsg_for_each_attr(cur, tb[ADD_RELAY_FORWARDER_DNSSERVERS], rem)
        {
            if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
            {
                nameserver_count++;
            }
        }

        nameservers = (char **)calloc(nameserver_count, sizeof(char *));
        if (nameservers == NULL)
        {
            log_error("Failed to allocate memory for nameservers");
            goto cleanup;
        }

        blobmsg_for_each_attr(cur, tb[ADD_RELAY_FORWARDER_DNSSERVERS], rem)
        {
            if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
            {
                nameservers[index] = strdup(blobmsg_get_string(cur));
                if (nameservers[index] == NULL)
                {
                    log_error("Failed to allocate memory for nameserver[%zu]", index);
                    goto cleanup;
                }
                index++;
            }
        }
    }

    data = relay_forwarder_data_init(alias, nameservers, nameserver_count);
    if (data == NULL)
    {
        log_error("Failed to initialize relay forwarder data");
        goto cleanup;
    }

    memset(&b, 0, sizeof(b));
    blob_buf_init(&b, 0);

    if (relay_forwarders_add(mod_ubus->relay_forwarders, data))
    {
        blobmsg_add_string(&b, "Status", "Ok");
    }
    else
    {
        blobmsg_add_string(&b, "Status", "Failed");
    }

cleanup:
    if (nameservers)
    {
        for (size_t i = 0; i < nameserver_count; i++)
        {
            free(nameservers[i]);
        }
        free(nameservers);
    }

    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);

    return 0;
}

static int add_relay_server(UNUSED struct ubus_context *ctx, UNUSED struct ubus_object *obj, UNUSED struct ubus_request_data *req, UNUSED const char *method, UNUSED struct blob_attr *msg)
{
    struct blob_buf b;
    struct blob_attr *tb[__ADD_RELAY_SERVER_MAX];
    struct blob_attr *cur = NULL;
    bool enable = 0;
    const char *alias = "";
    int rem = 0;
    JSON_Value *forwarders_root_value = json_value_init_array();
    JSON_Array *forwarders = json_value_get_array(forwarders_root_value);
    const char *interface = "";
    const char *address = "";
    int port = 0;
    int cache_size = 0;
    int cache_min_ttl = 0;
    int cache_max_ttl = 0;
    relay_server_data_t *data = NULL;

    memset(&b, 0, sizeof(b));
    blob_buf_init(&b, 0);

    if (blobmsg_parse(add_relay_server_policy, ARRAY_SIZE(add_relay_server_policy), tb, blob_data(msg), blob_len(msg)) != 0)
    {
        blobmsg_add_string(&b, "Error", "Invalid arguments");
        goto exit_0;
    }

    if (tb[ADD_RELAY_SERVER_ENABLE])
    {
        enable = blobmsg_get_bool(tb[ADD_RELAY_SERVER_ENABLE]);
    }
    else
    {
        enable = 1;
    }

    if (tb[ADD_RELAY_SERVER_ALIAS])
    {
        alias = blobmsg_get_string(tb[ADD_RELAY_SERVER_ALIAS]);
    }
    else
    {
        blobmsg_add_string(&b, "Error", "Missing Alias argument");
        goto exit_0;
    }

    if (tb[ADD_RELAY_SERVER_FORWARDERS])
    {
        blobmsg_for_each_attr(cur, tb[ADD_RELAY_SERVER_FORWARDERS], rem)
        {
            if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
            {
                const char *forwarder = blobmsg_get_string(cur);
                json_array_append_string(forwarders, forwarder);
            }
        }
    }
    else
    {
        blobmsg_add_string(&b, "Error", "Missing Forwarders argument");
        goto exit_0;
    }

    if (tb[ADD_RELAY_SERVER_INTERFACE])
    {
        interface = blobmsg_get_string(tb[ADD_RELAY_SERVER_INTERFACE]);
    }
    else
    {
        blobmsg_add_string(&b, "Error", "Missing Interface argument");
        goto exit_0;
    }

    if (tb[ADD_RELAY_SERVER_ADDRESS])
    {
        address = blobmsg_get_string(tb[ADD_RELAY_SERVER_ADDRESS]);
    }
    else
    {
        blobmsg_add_string(&b, "Error", "Missing Address argument");
        goto exit_0;
    }

    if (tb[ADD_RELAY_SERVER_PORT])
    {
        port = blobmsg_get_u32(tb[ADD_RELAY_SERVER_PORT]);
    }
    else
    {
        blobmsg_add_string(&b, "Error", "Missing Port argument");
        goto exit_0;
    }

    if (tb[ADD_RELAY_SERVER_CACHE_SIZE])
    {
        cache_size = blobmsg_get_u32(tb[ADD_RELAY_SERVER_CACHE_SIZE]);
    }

    if (tb[ADD_RELAY_SERVER_CACHE_MIN_TTL])
    {
        cache_min_ttl = blobmsg_get_u32(tb[ADD_RELAY_SERVER_CACHE_MIN_TTL]);
    }

    if (tb[ADD_RELAY_SERVER_CACHE_MAX_TTL])
    {
        cache_max_ttl = blobmsg_get_u32(tb[ADD_RELAY_SERVER_CACHE_MAX_TTL]);
    }

    // Currently only 1 forwarder per server is supported
    data = relay_server_data_init(enable, alias, json_array_get_string(forwarders, 0), interface, address, port, cache_size, cache_min_ttl, cache_max_ttl);

    if (!relay_server_add(mod_ubus->relay_servers, data))
    {
        goto exit_1;
    }

    blobmsg_add_string(&b, "Status", "Ok");

    relay_server_data_cleanup(&data);

    json_value_free(forwarders_root_value);

    ubus_send_reply(ctx, req, b.head);

    blob_buf_free(&b);

    return 0;

exit_1:
    relay_server_data_cleanup(&data);

exit_0:

    blobmsg_add_string(&b, "Status", "Failed");

    json_value_free(forwarders_root_value);

    ubus_send_reply(ctx, req, b.head);

    blob_buf_free(&b);

    return -1;
}

static struct ubus_method jojodns_methods[] = {
    UBUS_METHOD_NOARG("GetConfig", get_config),
    UBUS_METHOD("AddRelayForwarder", add_relay_forwarder, add_relay_forwarder_policy),
    UBUS_METHOD("AddRelayServer", add_relay_server, add_relay_server_policy),
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

bool mod_ubus_init(struct event_base *base, relay_forwarders_t *relay_forwarders, relay_servers_t *relay_servers, zones_t *zones)
{
    if (base == NULL || relay_forwarders == NULL || relay_servers == NULL)
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
    mod_ubus->relay_servers = relay_servers;
    mod_ubus->zones = zones;

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