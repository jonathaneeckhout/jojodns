#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <arpa/inet.h>

#include "logging.h"
#include "client.h"
#include "server.h"

#define NAME "JojoDNS"
#define LOG_LEVEL LOG_INFO

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 9876

#define UNUSED __attribute__((unused))

typedef struct _jojodns_t
{
    struct event_base *base;
    client_t *client;
    server_t *server;
    struct sockaddr_in server_sin;
} jojodns_t;

static jojodns_t jojodns;

static bool init()
{
    memset(&jojodns, 0, sizeof(jojodns_t));

    jojodns.base = event_base_new();
    if (jojodns.base == NULL)
    {
        log_error("Failed to init event base");
        goto exit_0;
    }

    jojodns.client = client_init(jojodns.base);
    if (jojodns.client == NULL)
    {
        log_error("Failed to init client");
        goto exit_1;
    }

    jojodns.server = server_init(jojodns.base, jojodns.client, SERVER_ADDRESS, SERVER_PORT);
    if (jojodns.server == NULL)
    {
        log_error("Failed to init server");
        goto exit_2;
    }
    return true;

exit_2:
    client_cleanup(&(jojodns.client));
exit_1:
    event_base_free(jojodns.base);
exit_0:
    return false;
}

static void cleanup()
{
    server_cleanup(&(jojodns.server));
    client_cleanup(&(jojodns.client));

    event_base_free(jojodns.base);
}

static void run()
{
    event_base_dispatch(jojodns.base);
}

void handle_sigint(UNUSED int sig)
{
    log_info("Received SIGINT. Shutting down...");
    if (jojodns.base != NULL)
    {
        event_base_loopexit(jojodns.base, NULL);
    }
}

int main()
{
    logging_init(NAME, LOG_LEVEL);

    signal(SIGINT, handle_sigint);

    if (!init())
    {
        log_error("Failed to init %s", NAME);
        return 1;
    }

    log_info("Started %s on address %s port %d", NAME, SERVER_ADDRESS, SERVER_PORT);

    run();

    cleanup();

    logging_cleanup();

    return 0;
}