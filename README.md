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
If you want to run/extend the tests please also install the following dependencies
``` bash
sudo apt install libcmocka-dev lcov
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
./jojodns -c config/config.example.json -l debug
```


## How to run tests
``` bash
cd build
make
make test
```

## How to run coverage report
Generate the coverage report.
``` bash
cd build
make
make test
make coverage
```

Show coverage report in a html page. Make sure you did the previous step and you're in the build directory.
``` bash
genhtml coverage.info --output-directory coverage_report
firefox coverage_report/index.html
```