# jojodns

## Introduction
JojoDNS is a simple lightweight asynchronous event driven DNS relay server. 
The key concepts of JojoDNS are:
* As fast as possible
* As dynamically configurable as possible
* As much information retrieved from the internal state as possible

## Dependencies
Please install the following packages
``` bash
sudo apt install libevent2-dev
```

## How to build

``` bash
mkdir build
cd build
cmake ../
make
```

## How to run
You can check the help option for al options
``` bash
./jojodns --help
```
and example configuration
``` bash
./jojodns -a 127.0.0.1 -p 53 -l debug
```
