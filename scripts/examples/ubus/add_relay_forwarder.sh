#!/bin/bash

ubus call jojodns AddRelayForwarder '{"Alias":"testrelay", "DNSServers": ["8.8.8.8", "8.8.6.6"]}'
