#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "logging.h"
#include "server.h"

#define UNUSED __attribute__((unused))

static void evdns_server_callback(UNUSED struct evdns_server_request *req, UNUSED void *data) {}

server_t *server_init(struct event_base *base, client_t *client, const char *address, int port)
{
    server_t *server = (server_t *)calloc(1, sizeof(server_t));
    if (server == NULL)
    {
        log_error("Failed to allocate memory for server_t");
        goto exit_0;
    }

    server->client = client;

    evutil_socket_t sock;
    struct sockaddr_in addr;
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

    server->dns_server = evdns_add_server_port_with_base(base, sock, 0, evdns_server_callback, server);
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

    free(*server);
    *server = NULL;
}
