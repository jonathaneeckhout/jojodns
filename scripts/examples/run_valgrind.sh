#!/bin/bash

valgrind --leak-check=full --show-leak-kinds=all ../../build/src/jojodns -c ../../config/config.example.json -l debug
