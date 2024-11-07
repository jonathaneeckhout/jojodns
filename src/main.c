#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <argp.h>
#include <signal.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <arpa/inet.h>

#include "logging.h"
#include "client.h"
#include "server.h"

#define NAME "JojoDNS"

#define DEFAULT_LOG_LEVEL LOG_INFO

#define DEFAULT_SERVER_INTERFACE ""
#define DEFAULT_SERVER_ADDRESS "127.0.0.1"
#define DEFAULT_SERVER_PORT 9876
#define DEFAULT_CLIENT_NAMESERVER ""
#define DEFAULT_CONFIG_FILE ""

#define UNUSED __attribute__((unused))

typedef struct _jojodns_t
{
    struct event_base *base;
    client_t *client;
    server_t *server;
    struct sockaddr_in server_sin;
} jojodns_t;

static jojodns_t jojodns;

struct arguments
{
    char *address;
    char *interface;
    int port;
    char *nameserver;
    char *config_file;
};

const char *argp_program_version = "jojodns v0.0.1";
const char *argp_program_bug_address = "<https://github.com/jonathaneeckhout/jojodns>";
static char doc[] = "A event driven dns relay server. With full runtime configuration options and real time statusses via events.";
static char args_doc[] = "";

static struct argp_option options[] = {
    {"address", 'a', "ADDRESS", 0, "IP address to bind to", 0},
    {"interface", 'i', "INTERFACE", 0, "Network interface to bind to. If set address argument is ingored", 0},
    {"port", 'p', "PORT", 0, "Port number to bind to", 0},
    {"nameserver", 'n', "NAMESERVER", 0, "Which forward nameserver to use. If not set, values from /etc/resolv.conf will be used", 0},
    {"config", 'c', "CONFIG_FILE", 0, "Path to the configuration file", 0},
    {"log-level", 'l', "LEVEL", 0, "Syslog log level (e.g., debug, info, warning, error)", 0},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 'a':
        arguments->address = arg;
        break;
    case 'i':
        arguments->interface = arg;
        break;
    case 'p':
        arguments->port = atoi(arg);
        break;
    case 'n':
        arguments->nameserver = arg;
        break;
    case 'c':
        arguments->config_file = arg;
        break;
    case 'l':
    {
        if (strcasecmp(arg, "debug") == 0)
        {
            logging_set_log_level(LOG_DEBUG);
        }
        else if (strcasecmp(arg, "info") == 0)
        {
            logging_set_log_level(LOG_INFO);
        }
        else if (strcasecmp(arg, "warning") == 0)
        {
            logging_set_log_level(LOG_WARNING);
        }
        else if (strcasecmp(arg, "error") == 0)
        {
            logging_set_log_level(LOG_ERR);
        }
        else
        {
            argp_error(state, "Invalid log level: %s", arg);
        }
        break;
    }
    case ARGP_KEY_END:
        if (arguments->port <= 0)
        {
            argp_error(state, "Port must be a positive integer.");
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// Argument parser structure
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

static bool init(struct arguments *arguments)
{
    memset(&jojodns, 0, sizeof(jojodns_t));

    jojodns.base = event_base_new();
    if (jojodns.base == NULL)
    {
        log_error("Failed to init event base");
        goto exit_0;
    }

    jojodns.client = client_init(jojodns.base, arguments->nameserver);
    if (jojodns.client == NULL)
    {
        log_error("Failed to init client");
        goto exit_1;
    }

    jojodns.server = server_init(jojodns.base, jojodns.client, arguments->interface, arguments->address, arguments->port);
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

int main(int argc, char *argv[])
{
    logging_init(NAME, DEFAULT_LOG_LEVEL);

    signal(SIGINT, handle_sigint);

    struct arguments arguments;

    arguments.interface = DEFAULT_SERVER_INTERFACE;
    arguments.address = DEFAULT_SERVER_ADDRESS;
    arguments.port = DEFAULT_SERVER_PORT;
    arguments.config_file = DEFAULT_CONFIG_FILE;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (!init(&arguments))
    {
        log_error("Failed to init %s", NAME);
        return 1;
    }

    log_info("Started %s ", NAME);

    run();

    cleanup();

    logging_cleanup();

    return 0;
}