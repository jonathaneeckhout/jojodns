#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <event2/dns_struct.h>

#include "logging.h"
#include "server.h"

#define UNUSED __attribute__((unused))

typedef struct _server_request_t
{
    server_t *server;
    struct evdns_server_request *req;
    char *name;
    char type;
} server_request_t;

static server_request_t *server_request_init(server_t *server, struct evdns_server_request *req, const char *name, char type)
{
    server_request_t *server_request = (server_request_t *)malloc(sizeof(server_request_t));
    if (server_request == NULL)
    {
        log_error("Failed to allocate memory for server_request_t");
        goto exit_0;
    }

    server_request->server = server;
    server_request->req = req;

    server_request->name = strdup(name);
    if (!server_request->name)
    {
        log_error("Failed to allocate memory for name");
        goto exit_1;
    }

    server_request->type = type;

    return server_request;
exit_1:
    free(server_request);
exit_0:
    return NULL;
}

static void server_request_cleanup(server_request_t **server_request)
{
    if (server_request == NULL || *server_request == NULL)
    {
        return;
    }

    if ((*server_request)->name != NULL)
    {
        free((*server_request)->name);
    }

    free(*server_request);
    *server_request = NULL;
}

static void server_dns_response_ipv4_callback(int result, char UNUSED type, int count, int ttl, void *addresses, void *arg)
{
    server_request_t *server_request = (server_request_t *)arg;
    struct in_addr *addr_list = (struct in_addr *)addresses;

    if (result != DNS_ERR_NONE)
    {
        log_warning("Server failed to process dns query for name=[%s]", server_request->name);
        evdns_server_request_respond(server_request->req, DNS_ERR_SERVERFAILED);
        goto exit;
    }

    if (count == 0)
    {
        log_info("Server resolve dns query for name=[%s]", server_request->name);
        evdns_server_request_respond(server_request->req, DNS_ERR_NODATA);
        goto exit;
    }

    for (int i = 0; i < count; ++i)
    {
        evdns_server_request_add_a_reply(server_request->req, server_request->name, 1, &addr_list[i].s_addr, ttl);
    }

    evdns_server_request_respond(server_request->req, DNS_ERR_NONE);

    cache_add_entry(server_request->server->cache, server_request->name, server_request->type, count, ttl, addr_list, NULL);

exit:
    server_request_cleanup(&server_request);
}

static void server_dns_response_ipv6_callback(int result, UNUSED char type, int count, int ttl, void *addresses, void *arg)
{
    server_request_t *server_request = (server_request_t *)arg;
    struct in6_addr *addr_list = (struct in6_addr *)addresses;

    if (result != DNS_ERR_NONE)
    {
        log_warning("Server failed to process dns query for name=[%s]", server_request->name);
        evdns_server_request_respond(server_request->req, DNS_ERR_SERVERFAILED);
        goto exit;
    }

    if (count == 0)
    {
        log_info("Server resolve dns query for name=[%s]", server_request->name);
        evdns_server_request_respond(server_request->req, DNS_ERR_NODATA);
        goto exit;
    }

    for (int i = 0; i < count; ++i)
    {
        evdns_server_request_add_aaaa_reply(server_request->req, server_request->name, 1, &addr_list[i].__in6_u, ttl);
    }

    evdns_server_request_respond(server_request->req, DNS_ERR_NONE);

    cache_add_entry(server_request->server->cache, server_request->name, server_request->type, count, ttl, NULL, addr_list);

exit:
    server_request_cleanup(&server_request);
}

static void server_dns_send_cache_response(struct evdns_server_request *req, const cache_entry_t *entry)
{
    for (int i = 0; i < entry->count; ++i)
    {
        switch (entry->type)
        {
        case EVDNS_TYPE_A:
            evdns_server_request_add_a_reply(req, entry->name, 1, &entry->a_addr_list[i].s_addr, entry->ttl);
            break;
        case EVDNS_TYPE_AAAA:
            evdns_server_request_add_aaaa_reply(req, entry->name, 1, &entry->aaaa_addr_list[i].__in6_u, entry->ttl);
            break;
        default:
            break;
        }
    }

    evdns_server_request_respond(req, DNS_ERR_NONE);
}

static void server_dns_request_callback(struct evdns_server_request *req, void *data)
{
    server_t *server = (server_t *)data;
    struct evdns_server_question *q = NULL;
    const cache_entry_t *cache_entry = NULL;

    if (req->questions == NULL || req->nquestions <= 0)
    {
        log_error("Invalid DNS questions or no questions available");
        evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
        return;
    }

    // Only one question a time is currently supported
    q = req->questions[0];

    log_debug("Received dns query for name=[%s], class=[%d], type=[%d]", q->name, q->dns_question_class, q->type);

    cache_entry = cache_get_entry(server->cache, q->name);
    if (cache_entry != NULL && cache_entry->type == q->type)
    {
        server_dns_send_cache_response(req, cache_entry);
        return;
    }
    else
    {
        server_request_t *server_request = server_request_init(server, req, q->name, q->type);
        if (server_request == NULL)
        {
            evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
            return;
        }

        switch (q->type)
        {
        case EVDNS_TYPE_A:
            evdns_base_resolve_ipv4(server->client->dns_base, q->name, 0, server_dns_response_ipv4_callback, server_request);
            break;
        case EVDNS_TYPE_AAAA:
            evdns_base_resolve_ipv6(server->client->dns_base, q->name, 0, server_dns_response_ipv6_callback, server_request);
            break;
        default:
            evdns_server_request_respond(req, DNS_ERR_NOTIMPL);
            server_request_cleanup(&server_request);
        }

        return;
    }
}

static evutil_socket_t server_bind_address_socket(const char *address, int port)
{
    evutil_socket_t sock = 0;
    struct sockaddr_in addr;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        log_error("Failed to create server socket");
        goto exit_1;
    }

    evutil_make_socket_nonblocking(sock);

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(address);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        log_error("Failed to bind to server socket");
        goto exit_2;
    }

    log_info("DNS relay server socket bound to address=[%s] on port=[%d]", address, port);

    return sock;

exit_2:
    close(sock);
exit_1:
    return -1;
}

static evutil_socket_t server_bind_interface_socket(const char *interface, int port)
{
    evutil_socket_t sock = 0;
    struct sockaddr_in addr;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        log_error("Failed to create server socket");
        goto exit_1;
    }

    evutil_make_socket_nonblocking(sock);

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) != 0)
    {
        perror("setsockopt SO_BINDTODEVICE failed");
        close(sock);
        return 1;
    }

    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        log_error("Failed to bind to server socket");
        goto exit_2;
    }

    log_info("DNS relay server socket bound to interface=[%s] on port=[%d]", interface, port);

    return sock;

exit_2:
    close(sock);
exit_1:
    return -1;
}

server_t *server_init(struct event_base *base, client_t *client, UNUSED const char *interface, const char *address, int port)
{
    evutil_socket_t sock;
    server_t *server = (server_t *)calloc(1, sizeof(server_t));
    if (server == NULL)
    {
        log_error("Failed to allocate memory for server_t");
        goto exit_0;
    }

    server->client = client;

    if (interface != NULL && strlen(interface) > 0)
    {
        sock = server_bind_interface_socket(interface, port);
    }
    else
    {
        sock = server_bind_address_socket(address, port);
    }

    if (sock < 0)
    {
        log_error("Failed to bind to server socket");
        goto exit_1;
    }

    server->dns_server = evdns_add_server_port_with_base(base, sock, 0, server_dns_request_callback, server);
    if (server->dns_server == NULL)
    {
        log_error("Failed to create dns server");
        goto exit_2;
    }

    server->cache = cache_init();
    if (server->cache == NULL)
    {
        log_error("Failed to init the cache");
        goto exit_3;
    }

    return server;

exit_3:
    evdns_close_server_port(server->dns_server);
exit_2:
    close(sock);
exit_1:
    free(server);
exit_0:
    return NULL;
}

void server_cleanup(server_t **server)
{
    if (server == NULL || *server == NULL)
    {
        return;
    }

    if ((*server)->cache != NULL)
    {
        cache_cleanup(&(*server)->cache);
    }

    if ((*server)->dns_server != NULL)
    {
        evdns_close_server_port((*server)->dns_server);
    }

    free(*server);
    *server = NULL;
}
