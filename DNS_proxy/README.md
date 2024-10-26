# DNS_proxy

The DNS_proxy proxy project is a simple multithreaded DNS proxy server implemented in C with blacklist functionality. It processes requests using basic blocking sockets and 8 threads. This project includes the main DNS proxy server and a suite of tests to ensure functionality, along with memory leak checks.

## Usages

* INI parser (inih) https://github.com/benhoyt/inih for parse config
* Hash map (uthash) https://troydhanson.github.io/uthash/ for udp requests hash map
* Thread pool (thpool) from this repo https://github.com/Pithikos/C-Thread-Pool

## Dependencies

* [CMake 3.5.0](https://cmake.org/download/) _(or higher)_
* [Check 0.15.2](https://github.com/libcheck/check/releases) _(for unit testing)_
* [Valgrind 3.15.0](https://valgrind.org/docs/manual/dist.readme.html) _(for memory leak detection)_

## Installing

1. Check you have all of the dependencies
2. Configure and build project
  ```bash
  cmake -B ./build . # configure
  cmake --build -B ./build . # build
  ```

## Configure DNS proxy

For configuring DNS proxy you need to create a file `config.ini` in the directory where you run DNS proxy.

```ini
# Example config.ini
[server]
port = 8000 # not required | 53 default

[upstream_dns]
ipaddress = 8.8.8.8 # required
port = 53 # required

[blacklisted]
response = REFUSED # required | if no error we return ip addresses from config 
response_ip = 142.251.46.174 # required if response = NOERROR
response_ipv6 = 2607:f8b0:4005:811::200e # required if response = NOERROR

file_with_domains = blacklisted.txt #required | default blacklisted.txt
```

After this create ASCII file with blacklisted domains, by default filename is `blacklisted.txt` (file ecoding should be ASCII!)

`
google.com
microsoft.org
`

## Run

In the `./bin` folder we have all the binaries to execute

1. `DNS_proxy` file, it's our dns proxy
2. `tests` file, it's all tests

## Tests

```bash
cd ./build 
ctest -V
```

## Memory leak checks 

```bash
cmake --build ./build --target tests_memory_leak_check # Memory leaks check for all tests
cmake --build ./build --target DNS_proxy_memory_leak_check # Memory leaks check for all tests
```

## What I used for testing 

* Packet Sender for stress testing and sending udp packages. 
* Wireshark for exploring udp packages
* Unit testing for testing DNS proxy

## Advantages and restrictions

* Advantages 
  * It multithreaded
  * Thread pool for maximizing productivity
  * Nice project structure
  * Test coverage (Check lib and CTest)

* Restrictions 
  * not fully optimized, think I can find ways to make it faster 
  * max received traffic is ~3 Mb/s, but I send ~10 Mb/s (used Packet Sender for intensive tests, I think some packets are lost)
  * EDS0 support


 




