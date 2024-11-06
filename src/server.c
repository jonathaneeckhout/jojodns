#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <event2/dns_struct.h>

#include "logging.h"
#include "server.h"

#define UNUSED __attribute__((unused))

typedef struct _server_request_t
{
    struct evdns_server_request *req;
    struct evdns_server_question *q;
} server_request_t;

static server_request_t *server_request_init(struct evdns_server_request *req, struct evdns_server_question *q)
{
    server_request_t *server_request = (server_request_t *)malloc(sizeof(server_request_t));
    if (server_request == NULL)
    {
        log_error("Failed to allocate memory for server_request_t");
        goto exit_0;
    }

    server_request->req = req;
    server_request->q = q;

    return server_request;

exit_0:
    return NULL;
}

static void server_request_cleanup(server_request_t **server_request)
{
    if (server_request == NULL || *server_request == NULL)
    {
        return;
    }

    free(*server_request);
    *server_request = NULL;
}

static void
server_dns_response_ipv4_callback(int result, UNUSED char type, int count, int ttl, void *addresses, void *arg)
{
    server_request_t *server_request = (server_request_t *)arg;
    struct in_addr *addr_list = (struct in_addr *)addresses;

    if (result != DNS_ERR_NONE)
    {
        log_warning("Server failed to process dns query for name=[%s]", server_request->q->name);
        evdns_server_request_respond(server_request->req, DNS_ERR_SERVERFAILED);
        goto exit;
    }

    if (count == 0)
    {
        log_info("Server resolve dns query for name=[%s]", server_request->q->name);
        evdns_server_request_respond(server_request->req, DNS_ERR_NODATA);
        goto exit;
    }

    for (int i = 0; i < count; ++i)
    {
        evdns_server_request_add_a_reply(server_request->req, server_request->q->name, 1, &addr_list[i].s_addr, ttl);
    }

    evdns_server_request_respond(server_request->req, 0);

exit:
    server_request_cleanup(&server_request);
}

static void server_dns_request_callback(struct evdns_server_request *req, void *data)
{
    server_t *server = (server_t *)data;

    for (int i = 0; i < req->nquestions; ++i)
    {
        struct evdns_server_question *q = req->questions[i];

        server_request_t *server_request = server_request_init(req, q);
        if (server_request == NULL)
        {
            evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
            return;
        }

        log_debug("Received dns query for name=[%s], class=[%d], type=[%d]", q->name, q->class, q->type);

        evdns_base_resolve_ipv4(server->client->dns_base, q->name, 0, server_dns_response_ipv4_callback, server_request);
    }
}

server_t *server_init(struct event_base *base, client_t *client, const char *address, int port)
{
    evutil_socket_t sock;
    struct sockaddr_in addr;
    server_t *server = (server_t *)calloc(1, sizeof(server_t));
    if (server == NULL)
    {
        log_error("Failed to allocate memory for server_t");
        goto exit_0;
    }

    server->client = client;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        log_error("Failed to create server socket");
        goto exit_1;
    }

    evutil_make_socket_nonblocking(sock);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(address);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        log_error("Failed to bind to server socket");
        goto exit_2;
    }

    server->dns_server = evdns_add_server_port_with_base(base, sock, 0, server_dns_request_callback, server);
    if (server->dns_server == NULL)
    {
        log_error("Failed to create dns server");
        goto exit_2;
    }

    return server;

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

    evdns_close_server_port((*server)->dns_server);

    free(*server);
    *server = NULL;
}
