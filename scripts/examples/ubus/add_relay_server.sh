#!/bin/bash

ubus call jojodns AddRelayServer '{"Alias":"testserver", "Forwarders": ["google"], "Interface": "", "Address":"127.0.0.1", "Port": 9877}'
