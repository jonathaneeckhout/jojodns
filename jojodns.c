#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <arpa/inet.h>

#define SOCKET_PORT 9876

typedef struct _jojodns_t
{
    struct event_base *base;
    struct evdns_base *dns_base;
    struct evconnlistener *listener;
} jojodns_t;

jojodns_t jojodns;

void dns_callback(int result, char type, int count, int ttl, void *addresses, void *arg)
{
    if (result != DNS_ERR_NONE)
    {
        fprintf(stderr, "DNS lookup failed: %s\n", evdns_err_to_string(result));
        return;
    }

    printf("DNS lookup succeeded, type %d, count %d, ttl %d\n", type, count, ttl);
    for (int i = 0; i < count; i++)
    {
        if (type == DNS_IPv4_A)
        {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct in_addr *)addresses)[i], ip, sizeof(ip));
            printf("IPv4 Address: %s\n", ip);
        }
        else if (type == DNS_IPv6_AAAA)
        {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &((struct in6_addr *)addresses)[i], ip, sizeof(ip));
            printf("IPv6 Address: %s\n", ip);
        }
    }
}

// Callback for when a connection receives data
void read_callback(struct bufferevent *bev, void *ctx) {
    char buffer[256];
    int n;
    while ((n = bufferevent_read(bev, buffer, sizeof(buffer))) > 0) {
        buffer[n] = '\0';
        syslog(LOG_INFO, "Received: %s", buffer);

        // Echo the data back to the client
        bufferevent_write(bev, buffer, n);
    }
}

// Callback for when an event occurs on a connection
void event_callback(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_ERROR) {
        syslog(LOG_ERR, "Error on connection");
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        syslog(LOG_INFO, "Connection closed");
        bufferevent_free(bev);
    }
}

static void accept_callback(struct evconnlistener *listener, evutil_socket_t fd,
                            struct sockaddr *address, int socklen, void *ctx)
{
    struct event_base *base = (struct event_base *)ctx;
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in *client_addr = (struct sockaddr_in *)address;
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));
    syslog(LOG_INFO, "Accepted connection from %s:%d", client_ip, ntohs(client_addr->sin_port));

    bufferevent_setcb(bev, read_callback, NULL, event_callback, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

static bool init_socket_server(uint16_t port)
{
    struct sockaddr_in sin;

    // Configure the socket address
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);

    jojodns.listener = evconnlistener_new_bind(jojodns.base, accept_callback, (void *)jojodns.base,
                                               LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
                                               (struct sockaddr *)&sin, sizeof(sin));
    if (!jojodns.listener)
    {
        syslog(LOG_ERR, "Could not create a listener");
        return 1;
    }

    return true;
}

int main(int argc, char **argv)
{

    openlog("jojodns", LOG_PID | LOG_CONS, LOG_USER);

    memset(&jojodns, 0, sizeof(jojodns_t));

    if (argc != 2)
    {
        syslog(LOG_ERR, "Usage: %s <hostname>\n", argv[0]);
        return 1;
    }

    jojodns.base = event_base_new();
    if (!jojodns.base)
    {
        syslog(LOG_ERR, "Could not initialize libevent!\n");
        return 1;
    }

    if (!init_socket_server(SOCKET_PORT))
    {
        syslog(LOG_ERR, "Could not init socket server");
        return 1;
    }

    jojodns.dns_base = evdns_base_new(jojodns.base, 1);
    if (!jojodns.dns_base)
    {
        syslog(LOG_ERR, "Could not initialize DNS base!\n");
        event_base_free(jojodns.base);
        return 1;
    }

    evdns_base_resolve_ipv4(jojodns.dns_base, argv[1], 0, dns_callback, NULL);

    syslog(LOG_INFO, "JojoDNS started");

    event_base_dispatch(jojodns.base);

    evdns_base_free(jojodns.dns_base, 0);
    event_base_free(jojodns.base);

    closelog();

    return 0;
}
