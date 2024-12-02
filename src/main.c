#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <argp.h>
#include <signal.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <arpa/inet.h>
#include <parson.h>
#include <hashmap.h>

#include "logging.h"
#include "client.h"
#include "server.h"
#include "relay_forwarders.h"
#include "relay_servers.h"
#include "zones.h"

#ifdef MOD_UBUS
#include "mods/modubus/modubus.h"
#endif

#define NAME "JojoDNS"

#define DEFAULT_LOG_LEVEL LOG_INFO

#define DEFAULT_CONFIG_FILE ""

#define UNUSED __attribute__((unused))

typedef struct _jojodns_t
{
    struct event_base *base;
    relay_forwarders_t *relay_forwarders;
    relay_servers_t *relay_servers;
    zones_t *zones;
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
    {"config", 'c', "CONFIG_FILE", 0, "Path to the configuration file", 0},
    {"log-level", 'l', "LEVEL", 0, "Syslog log level (e.g., debug, info, warning, error)", 0},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
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
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

static bool init_modules()
{
#ifdef MOD_UBUS
    if (!mod_ubus_init(jojodns.base, jojodns.relay_forwarders, jojodns.relay_servers, jojodns.zones))
    {
        log_error("Failed init modubus");
        return false;
    }
#endif

    return true;
}

static bool init(struct arguments *arguments)
{
    JSON_Value *config_data = NULL;

    memset(&jojodns, 0, sizeof(jojodns_t));

    jojodns.base = event_base_new();
    if (jojodns.base == NULL)
    {
        log_error("Failed to init event base");
        goto exit_0;
    }

    config_data = json_parse_file(arguments->config_file);
    if (config_data == NULL)
    {
        log_warning("Failed to parse config file=[%s]", arguments->config_file);
        goto exit_1;
    }

    jojodns.relay_forwarders = relay_forwarders_init(jojodns.base, config_data);
    if (jojodns.relay_forwarders == NULL)
    {
        log_error("Failed to init relay forwarders");
        goto exit_2;
    }

    jojodns.zones = zones_init(config_data);
    if (jojodns.zones == NULL)
    {
        log_error("Failed to init zones");
        goto exit_3;
    }

    jojodns.relay_servers = relay_servers_init(jojodns.base, jojodns.relay_forwarders, jojodns.zones, config_data);
    if (jojodns.relay_servers == NULL)
    {
        log_error("Failed to init relay servers");
        goto exit_4;
    }

    if (!init_modules())
    {
        log_error("Failed to init modules");
        goto exit_5;
    }

    json_value_free(config_data);

    return true;

exit_5:
    relay_servers_cleanup(&jojodns.relay_servers);
exit_4:
    zones_cleanup(&jojodns.zones);
exit_3:
    relay_forwarders_cleanup(&jojodns.relay_forwarders);
exit_2:
    json_value_free(config_data);
exit_1:
    event_base_free(jojodns.base);
exit_0:
    return false;
}

static void cleanup_modules()
{
    mod_ubus_cleanup();
}

static void cleanup()
{
    cleanup_modules();

    relay_servers_cleanup(&jojodns.relay_servers);
    relay_forwarders_cleanup(&jojodns.relay_forwarders);
    zones_cleanup(&jojodns.zones);

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

    arguments.config_file = DEFAULT_CONFIG_FILE;

    if (argp_parse(&argp, argc, argv, ARGP_NO_EXIT, 0, &arguments) != 0)
    {
        goto exit_0;
    }

    if (!init(&arguments))
    {
        log_error("Failed to init %s", NAME);
        goto exit_0;
    }

    log_info("Started %s ", NAME);

    run();

    cleanup();

    logging_cleanup();

    return 0;

exit_0:
    logging_cleanup();
    return 1;
}